// Package attribution answers "who had a session open when this file
// changed" by parsing sshd's own auth log — never by trusting `last`,
// `who`, or `w`, which shell out to system accounting files that could
// equally be altered, consistent with the rest of Warden's threat model
// (see docs/DESIGN.md).
//
// This is deliberately conservative: a line it can't parse, or a log file
// it can't find, is treated as "no evidence" rather than guessed at. The
// caller (cmd/warden) is expected to treat "no evidence" as "don't act" —
// see docs/DESIGN.md's note on why a wrong auto-response is worse than no
// response at all.
package attribution

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"time"
)

// Session is one SSH session sshd's own log recorded: who connected, from
// where, and for how long. End is the zero Time if the log never recorded
// this session closing (still open, or the log rotated out from under it)
// — Overlapping treats that as "open through now."
type Session struct {
	User  string
	IP    string
	PID   string
	Start time.Time
	End   time.Time
}

// open reports whether the session was live at t.
func (s Session) open(t time.Time) bool {
	if t.Before(s.Start) {
		return false
	}
	if s.End.IsZero() {
		return true
	}
	return !t.After(s.End)
}

var (
	timestampRe    = regexp.MustCompile(`^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[(\d+)\]:\s*(.*)$`)
	acceptedRe     = regexp.MustCompile(`^Accepted \S+ for (\S+) from ([0-9a-fA-F.:]+) port \d+`)
	disconnectRe   = regexp.MustCompile(`^Disconnected from(?: user \S+)? ([0-9a-fA-F.:]+) port \d+`)
	receivedDiscRe = regexp.MustCompile(`^Received disconnect from ([0-9a-fA-F.:]+) port \d+`)
)

// SessionsFromAuthLog reads every accepted-login/disconnect pair it can
// parse out of an OpenSSH auth log (Debian/Ubuntu's /var/log/auth.log or
// RHEL-family's /var/log/secure — both use the same sshd log line format).
// now anchors the year, since classic syslog timestamps don't carry one.
func SessionsFromAuthLog(path string, now time.Time) ([]Session, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("attribution: open %s: %w", path, err)
	}
	defer f.Close()

	open := map[string]*Session{} // pid -> session, until closed
	var sessions []Session

	scanner := bufio.NewScanner(f)
	// Auth logs can have long lines (rare, but don't let one truncate the
	// scan); 1MB is generous for a single syslog line.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		m := timestampRe.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		ts, ok := parseSyslogTime(m[1], now)
		if !ok {
			continue
		}
		pid, rest := m[2], m[3]

		switch {
		case acceptedRe.MatchString(rest):
			am := acceptedRe.FindStringSubmatch(rest)
			open[pid] = &Session{User: am[1], IP: am[2], PID: pid, Start: ts}

		case disconnectRe.MatchString(rest):
			dm := disconnectRe.FindStringSubmatch(rest)
			closeSession(open, &sessions, pid, dm[1], ts)

		case receivedDiscRe.MatchString(rest):
			dm := receivedDiscRe.FindStringSubmatch(rest)
			closeSession(open, &sessions, pid, dm[1], ts)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("attribution: read %s: %w", path, err)
	}

	// Anything still open when the log ends is still-open, not missing.
	for _, s := range open {
		sessions = append(sessions, *s)
	}

	return sessions, nil
}

func closeSession(open map[string]*Session, sessions *[]Session, pid, ip string, end time.Time) {
	s, ok := open[pid]
	if !ok {
		return // a disconnect with no matching accepted line — nothing to close
	}
	if s.IP != "" && s.IP != ip {
		return // pid reused by an unrelated line; be conservative and drop it
	}
	s.End = end
	*sessions = append(*sessions, *s)
	delete(open, pid)
}

// parseSyslogTime parses a classic BSD-syslog timestamp ("Sep 20
// 14:32:10"), which carries no year, against now's year — correcting back
// a year if that would otherwise land in the future (a log line from just
// before a new year, read just after it).
func parseSyslogTime(s string, now time.Time) (time.Time, bool) {
	t, err := time.Parse("Jan _2 15:04:05 2006", s+" "+fmt.Sprint(now.Year()))
	if err != nil {
		return time.Time{}, false
	}
	t = t.In(now.Location())
	if t.After(now.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t, true
}

// Overlapping returns the distinct IPs of every session that was live at
// t, deduplicated.
func Overlapping(sessions []Session, t time.Time) []string {
	seen := map[string]bool{}
	var ips []string
	for _, s := range sessions {
		if !s.open(t) {
			continue
		}
		if seen[s.IP] {
			continue
		}
		seen[s.IP] = true
		ips = append(ips, s.IP)
	}
	return ips
}

// UserFor returns the username attribution found for ip's session
// overlapping t, or "" if none is on record. Used only to make an alert
// message more specific ("someone used the root account..."), never for
// an access decision.
func UserFor(sessions []Session, ip string, t time.Time) string {
	for _, s := range sessions {
		if s.IP == ip && s.open(t) {
			return s.User
		}
	}
	return ""
}
