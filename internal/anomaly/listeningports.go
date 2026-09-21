package anomaly

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// listeningSocket is one TCP socket in the LISTEN state, as reported by
// /proc/net/tcp or /proc/net/tcp6.
type listeningSocket struct {
	proto string
	port  int
	uid   string
}

// CheckListeningPorts flags any TCP port newly found in the LISTEN state
// since the last run. procRoot is overridable so tests can point this at
// a fake /proc tree, the same pattern cmd/warden/detect.go's procRoot
// already uses.
//
// /proc/net/tcp{,6} already reports each socket's owning UID as one of
// its own columns — no inode-to-PID walk over every /proc/<pid>/fd/*
// symlink is needed just to answer "who owns this listening socket."
func CheckListeningPorts(baselineDir, procRoot string) ([]Finding, error) {
	baselinePath := filepath.Join(baselineDir, "listening-ports.json")
	bootstrap := firstRun(baselinePath)
	old, err := loadBaseline(baselinePath)
	if err != nil {
		return nil, err
	}

	var sockets []listeningSocket
	for _, spec := range []struct{ file, proto string }{
		{"tcp", "tcp"},
		{"tcp6", "tcp6"},
	} {
		path := filepath.Join(procRoot, "net", spec.file)
		socks, err := parseProcNetTCP(path, spec.proto)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		sockets = append(sockets, socks...)
	}

	next := baseline{}
	var findings []Finding
	for _, s := range sockets {
		key := fmt.Sprintf("%s:%d", s.proto, s.port)
		owner := uidToUsername(s.uid)
		next[key] = owner
		if bootstrap {
			continue
		}
		if _, existed := old[key]; existed {
			continue
		}
		findings = append(findings, Finding{
			Check:       "listening-ports",
			Description: fmt.Sprintf("new listening port: %s/%d (owned by uid %s)", s.proto, s.port, s.uid),
			Detail:      fmt.Sprintf("resolved owner: %s", owner),
			Culprit:     owner,
		})
	}

	if err := saveBaseline(baselinePath, next); err != nil {
		return nil, err
	}
	return findings, nil
}

// parseProcNetTCP reads one /proc/net/tcp-format file. Columns (after the
// header line): sl local_address rem_address st tx_queue:rx_queue
// tr:tm->when retrnsmt uid timeout inode ... — st == "0A" is TCP_LISTEN,
// local_address is hex-encoded "IP:PORT", uid is a plain decimal string.
func parseProcNetTCP(path, proto string) ([]listeningSocket, error) {
	// Not wrapped with fmt.Errorf here: the caller checks os.IsNotExist
	// on this specific error (tcp6 legitimately doesn't exist on an
	// IPv4-only box), and os.IsNotExist doesn't see through %w-wrapping.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var out []listeningSocket
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if i == 0 {
			continue // header
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		if fields[3] != "0A" { // not LISTEN
			continue
		}
		addrParts := strings.Split(fields[1], ":")
		if len(addrParts) != 2 {
			continue
		}
		port, err := strconv.ParseInt(addrParts[1], 16, 32)
		if err != nil {
			continue
		}
		out = append(out, listeningSocket{proto: proto, port: int(port), uid: fields[7]})
	}
	return out, nil
}

// uidToUsername resolves a decimal UID string to a username, or returns
// the UID itself if that isn't possible — still useful as a Culprit
// (accountlock's caller-side gates work off names, but a bare UID isn't
// a valid one, so this only matters for the human-readable Detail; the
// gate re-checking against /etc/passwd by name is what actually decides
// whether it's safe to act on).
func uidToUsername(uid string) string {
	u, err := user.LookupId(uid)
	if err != nil {
		return uid
	}
	return u.Username
}
