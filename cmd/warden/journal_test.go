package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadJournalSessionsCommand(t *testing.T) {
	dir := t.TempDir()
	argsPath := filepath.Join(dir, "args")
	t.Setenv("PATH", dir)
	t.Setenv("JOURNAL_TEST_ARGS", argsPath)
	script := `#!/bin/sh
printf '%s\n' "$@" > "$JOURNAL_TEST_ARGS"
printf '%s\n' '2026-09-21T12:00:00+0000 box sshd[123]: Accepted password for root from 192.0.2.1 port 123 ssh2'
`
	cmdPath := filepath.Join(dir, "journalctl")
	if err := os.WriteFile(cmdPath, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 21, 13, 0, 0, 0, time.UTC)
	sessions, err := readJournalSessions(now, now)
	if err != nil || len(sessions) != 1 || sessions[0].IP != "192.0.2.1" {
		t.Fatalf("sessions=%v err=%v", sessions, err)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--output=short-iso", "--identifier=sshd-session", "2026-09-20T13:00:00Z", "2026-09-21T13:00:00Z"} {
		if !strings.Contains(string(args), want) {
			t.Fatalf("missing %s in %s", want, args)
		}
	}
	if err := os.WriteFile(cmdPath, []byte(script+"exit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if got, err := readJournalSessions(now, now); err == nil || got != nil {
		t.Fatalf("partial failed command accepted: %v %v", got, err)
	}
}
