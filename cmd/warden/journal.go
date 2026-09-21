package main

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"warden/internal/attribution"
)

// A bounded lookback can miss older sessions; it never invents evidence.
var journalSessions = readJournalSessions

func authSessions(eventTime, now time.Time) ([]attribution.Session, error) {
	if path, ok := findAuthLog(); ok {
		return attribution.SessionsFromAuthLog(path, now)
	}
	return journalSessions(eventTime, now)
}

func readJournalSessions(eventTime, now time.Time) ([]attribution.Session, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "journalctl", "--no-pager", "--output=short-iso", "--identifier=sshd", "--identifier=sshd-session", "--since", eventTime.Add(-24*time.Hour).Format(time.RFC3339), "--until", now.Format(time.RFC3339))
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("journal unavailable: %w", err)
	}
	sessions, parseErr := attribution.SessionsFromReader(out, now)
	if parseErr != nil {
		cancel()
	}
	waitErr := cmd.Wait()
	if parseErr != nil {
		return nil, parseErr
	}
	if waitErr != nil {
		return nil, fmt.Errorf("journal read failed: %w", waitErr)
	}
	return sessions, nil
}
