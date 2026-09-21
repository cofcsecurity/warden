package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/ssh"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"warden/internal/attribution"
)

func writeAuthLog(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.log")
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// withAuthLogAndTeamIP points package-level lookup at a fake log and a
// fake team IP for the duration of one test, restoring both afterward —
// these are ordinary package vars, not build-time consts, specifically so
// tests can do this instead of touching real /var/log files.
func withAuthLogAndTeamIP(t *testing.T, logPath, teamIP string) {
	t.Helper()
	origPaths, origIP := authLogPaths, buildTeamFromIP
	authLogPaths = []string{logPath}
	buildTeamFromIP = teamIP
	t.Cleanup(func() {
		authLogPaths = origPaths
		buildTeamFromIP = origIP
	})
}

func TestIPMatchesTeamExact(t *testing.T) {
	origIP := buildTeamFromIP
	defer func() { buildTeamFromIP = origIP }()

	buildTeamFromIP = "203.0.113.10"
	if !ipMatchesTeam("203.0.113.10") {
		t.Fatal("expected an exact match")
	}
	if ipMatchesTeam("203.0.113.11") {
		t.Fatal("expected no match for a different IP")
	}
}

func TestIPMatchesTeamCIDR(t *testing.T) {
	origIP := buildTeamFromIP
	defer func() { buildTeamFromIP = origIP }()

	buildTeamFromIP = "203.0.113.0/24"
	if !ipMatchesTeam("203.0.113.42") {
		t.Fatal("expected an address inside the CIDR to match")
	}
	if ipMatchesTeam("198.51.100.1") {
		t.Fatal("expected an address outside the CIDR not to match")
	}
}

func TestAttributeChangeNoAuthLogMeansNoSuspect(t *testing.T) {
	oldJournal := journalSessions
	journalSessions = func(time.Time, time.Time) ([]attribution.Session, error) {
		return nil, fmt.Errorf("journal unavailable")
	}
	t.Cleanup(func() { journalSessions = oldJournal })
	origPaths := authLogPaths
	authLogPaths = []string{"/nonexistent/auth.log"}
	defer func() { authLogPaths = origPaths }()

	suspect, _, evidence, _ := attributeChange(time.Now(), time.Now())
	if suspect != "" {
		t.Fatalf("expected no suspect with no auth log, got %q", suspect)
	}
	if evidence == "" {
		t.Fatal("expected a human-readable reason even when there's no evidence")
	}
}

func TestAttributeChangeSkipsTheTeamsOwnSession(t *testing.T) {
	logPath := writeAuthLog(t,
		"Sep 20 14:32:10 box sshd[1234]: Accepted publickey for root from 203.0.113.10 port 51522 ssh2",
	)
	withAuthLogAndTeamIP(t, logPath, "203.0.113.10")

	now := time.Date(2026, time.September, 20, 15, 0, 0, 0, time.UTC)
	eventTime := time.Date(2026, time.September, 20, 14, 40, 0, 0, time.UTC)

	suspect, _, evidence, _ := attributeChange(eventTime, now)
	if suspect != "" {
		t.Fatalf("expected no ban target when only the team's own IP had a session, got %q (%s)", suspect, evidence)
	}
}

func TestAttributeChangeFindsAForeignRootSession(t *testing.T) {
	logPath := writeAuthLog(t,
		"Sep 20 14:32:10 box sshd[1234]: Accepted publickey for root from 198.51.100.6 port 40000 ssh2",
	)
	withAuthLogAndTeamIP(t, logPath, "203.0.113.10")

	now := time.Date(2026, time.September, 20, 15, 0, 0, 0, time.UTC)
	eventTime := time.Date(2026, time.September, 20, 14, 40, 0, 0, time.UTC)

	suspect, account, evidence, _ := attributeChange(eventTime, now)
	if suspect != "198.51.100.6" {
		t.Fatalf("expected the foreign IP to be identified as the suspect, got %q (%s)", suspect, evidence)
	}
	if account != "root" {
		t.Fatalf("expected the account to be recorded, got %q", account)
	}
}

func TestAttributeChangeIgnoresNonRootSessions(t *testing.T) {
	// A replication peer's inbound session authenticates as warden-backup,
	// never root — this must never become a ban suspect regardless of
	// timing, since that account can't touch a config-tier path anyway
	// (command="/usr/bin/false" restricted, per docs/DEPLOYMENT.md).
	logPath := writeAuthLog(t,
		"Sep 20 14:32:10 box sshd[1234]: Accepted publickey for warden-backup from 198.51.100.6 port 40000 ssh2",
	)
	withAuthLogAndTeamIP(t, logPath, "203.0.113.10")

	now := time.Date(2026, time.September, 20, 15, 0, 0, 0, time.UTC)
	eventTime := time.Date(2026, time.September, 20, 14, 40, 0, 0, time.UTC)

	suspect, _, evidence, _ := attributeChange(eventTime, now)
	if suspect != "" {
		t.Fatalf("expected a non-root session to never be a ban suspect, got %q (%s)", suspect, evidence)
	}
}

func TestAttributeChangeAmbiguousWithMultipleForeignSessions(t *testing.T) {
	logPath := writeAuthLog(t,
		"Sep 20 14:32:10 box sshd[1234]: Accepted publickey for root from 198.51.100.6 port 40000 ssh2",
		"Sep 20 14:33:00 box sshd[5678]: Accepted publickey for root from 198.51.100.7 port 40001 ssh2",
	)
	withAuthLogAndTeamIP(t, logPath, "203.0.113.10")

	now := time.Date(2026, time.September, 20, 15, 0, 0, 0, time.UTC)
	eventTime := time.Date(2026, time.September, 20, 14, 40, 0, 0, time.UTC)

	suspect, _, evidence, _ := attributeChange(eventTime, now)
	if suspect != "" {
		t.Fatalf("expected no single suspect when more than one foreign IP overlaps, got %q (%s)", suspect, evidence)
	}
}

func TestJournalFallbackAndTeamKeyExclusion(t *testing.T) {
	oldJournal, oldKey := journalSessions, buildTeamPubKey
	t.Cleanup(func() { journalSessions, buildTeamPubKey = oldJournal, oldKey })
	withAuthLogAndTeamIP(t, "/nonexistent/auth.log", "203.0.113.10")
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	buildTeamPubKey = string(ssh.MarshalAuthorizedKey(key))
	now := time.Now()
	journalSessions = func(event, now time.Time) ([]attribution.Session, error) {
		return []attribution.Session{
			{User: "operator", IP: "192.0.2.1", KeyFingerprint: ssh.FingerprintSHA256(key), Start: now.Add(-time.Hour)},
			{User: "root", IP: "192.0.2.1", Start: now.Add(-time.Minute)},
		}, nil
	}
	suspect, _, _, _ := attributeChange(now, now)
	if suspect != "" {
		t.Fatalf("team key's IP targeted: %s", suspect)
	}
	journalSessions = func(event, now time.Time) ([]attribution.Session, error) {
		return []attribution.Session{{User: "root", IP: "192.0.2.2", Start: now.Add(-time.Minute)}}, nil
	}
	suspect, _, _, _ = attributeChange(now, now)
	if suspect != "192.0.2.2" {
		t.Fatalf("journal session missing: %s", suspect)
	}
	journalSessions = func(event, now time.Time) ([]attribution.Session, error) { return nil, fmt.Errorf("unavailable") }
	suspect, _, evidence, _ := attributeChange(now, now)
	if suspect != "" || !strings.Contains(evidence, "unavailable") {
		t.Fatalf("failed journal read: %s %s", suspect, evidence)
	}
}
