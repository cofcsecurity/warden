package attribution

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeLog(t *testing.T, lines ...string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSessionsFromAuthLogPairsAcceptedAndDisconnected(t *testing.T) {
	path := writeLog(t,
		"Sep 20 14:32:10 box sshd[1234]: Accepted publickey for root from 203.0.113.10 port 51522 ssh2",
		"Sep 20 14:40:02 box sshd[1234]: Disconnected from 203.0.113.10 port 51522",
	)

	now := time.Date(2026, time.September, 20, 15, 0, 0, 0, time.UTC)
	sessions, err := SessionsFromAuthLog(path, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d: %+v", len(sessions), sessions)
	}
	s := sessions[0]
	if s.IP != "203.0.113.10" || s.User != "root" {
		t.Fatalf("unexpected session: %+v", s)
	}
	if s.Start.IsZero() || s.End.IsZero() {
		t.Fatalf("expected both Start and End set, got %+v", s)
	}

	// A time inside the session's window should overlap; before/after should not.
	inside := time.Date(2026, time.September, 20, 14, 35, 0, 0, time.UTC)
	before := time.Date(2026, time.September, 20, 14, 0, 0, 0, time.UTC)
	after := time.Date(2026, time.September, 20, 15, 0, 0, 0, time.UTC)

	if ips := Overlapping(sessions, inside); len(ips) != 1 || ips[0] != "203.0.113.10" {
		t.Fatalf("expected an overlap at %v, got %v", inside, ips)
	}
	if ips := Overlapping(sessions, before); len(ips) != 0 {
		t.Fatalf("expected no overlap at %v, got %v", before, ips)
	}
	if ips := Overlapping(sessions, after); len(ips) != 0 {
		t.Fatalf("expected no overlap at %v, got %v", after, ips)
	}
}

func TestSessionsFromAuthLogStillOpenSessionCountsAsOngoing(t *testing.T) {
	path := writeLog(t,
		"Sep 20 14:32:10 box sshd[1234]: Accepted publickey for root from 203.0.113.10 port 51522 ssh2",
	)

	now := time.Date(2026, time.September, 20, 15, 0, 0, 0, time.UTC)
	sessions, err := SessionsFromAuthLog(path, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 still-open session, got %d", len(sessions))
	}

	// Anything after Start, with no End recorded, should still overlap.
	later := time.Date(2026, time.September, 20, 14, 59, 0, 0, time.UTC)
	if ips := Overlapping(sessions, later); len(ips) != 1 {
		t.Fatalf("expected a still-open session to overlap %v, got %v", later, ips)
	}
}

func TestSessionsFromAuthLogUsesReceivedDisconnect(t *testing.T) {
	path := writeLog(t,
		"Sep 20 14:32:10 box sshd[1234]: Accepted publickey for admin from 198.51.100.5 port 40000 ssh2",
		"Sep 20 14:33:00 box sshd[1234]: Received disconnect from 198.51.100.5 port 40000:11: disconnected by user",
	)

	now := time.Date(2026, time.September, 20, 15, 0, 0, 0, time.UTC)
	sessions, err := SessionsFromAuthLog(path, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].End.IsZero() {
		t.Fatalf("expected one closed session, got %+v", sessions)
	}
}

func TestSessionsFromAuthLogIgnoresUnrelatedLines(t *testing.T) {
	path := writeLog(t,
		"Sep 20 14:00:00 box CRON[999]: (root) CMD (some cron job)",
		"Sep 20 14:32:10 box sshd[1234]: Failed password for root from 198.51.100.6 port 33221 ssh2",
		"garbage line with no timestamp at all",
	)

	now := time.Date(2026, time.September, 20, 15, 0, 0, 0, time.UTC)
	sessions, err := SessionsFromAuthLog(path, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Fatalf("expected no sessions from non-session lines, got %+v", sessions)
	}
}

func TestSessionsFromAuthLogMissingFileIsAnError(t *testing.T) {
	_, err := SessionsFromAuthLog("/nonexistent/auth.log", time.Now())
	if err == nil {
		t.Fatal("expected an error for a missing log file, not silent empty evidence")
	}
}

func TestUserForReturnsAttributedUsername(t *testing.T) {
	path := writeLog(t,
		"Sep 20 14:32:10 box sshd[1234]: Accepted publickey for backdoor from 203.0.113.10 port 51522 ssh2",
	)
	now := time.Date(2026, time.September, 20, 15, 0, 0, 0, time.UTC)
	sessions, err := SessionsFromAuthLog(path, now)
	if err != nil {
		t.Fatal(err)
	}

	at := time.Date(2026, time.September, 20, 14, 40, 0, 0, time.UTC)
	if u := UserFor(sessions, "203.0.113.10", at); u != "backdoor" {
		t.Fatalf("expected user 'backdoor', got %q", u)
	}
	if u := UserFor(sessions, "9.9.9.9", at); u != "" {
		t.Fatalf("expected no user for an unrelated ip, got %q", u)
	}
}

func TestJournalISOAndKeyFingerprint(t *testing.T) {
	now := time.Date(2026, 9, 21, 18, 0, 0, 0, time.UTC)
	input := "2026-09-21T12:00:00-0400 box sshd-session[10]: Accepted publickey for root from 192.0.2.1 port 123 ssh2: ED25519 SHA256:abc123\n2026-09-21T12:05:00-0400 box sshd-session[10]: Disconnected from user root 192.0.2.1 port 123\n"
	sessions, err := SessionsFromReader(strings.NewReader(input), now)
	if err != nil || len(sessions) != 1 {
		t.Fatalf("sessions=%v err=%v", sessions, err)
	}
	s := sessions[0]
	if s.KeyFingerprint != "SHA256:abc123" || s.Start.Hour() != 12 || s.End.IsZero() || len(Overlapping(sessions, now)) != 0 {
		t.Fatalf("bad session: %+v", s)
	}
}
