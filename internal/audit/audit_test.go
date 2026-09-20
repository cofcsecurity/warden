package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLogAppendsJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")

	l, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	if err := l.Log("watch", "auto-restored", map[string]any{"path": "/etc/nginx/nginx.conf"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Log("opmenu", "rejected", map[string]any{"command": "shell", "reason": "bad totp"}); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var entries []Entry
	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			t.Fatalf("invalid json line: %v", err)
		}
		entries = append(entries, e)
	}

	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Component != "watch" || entries[0].Action != "auto-restored" {
		t.Errorf("unexpected first entry: %+v", entries[0])
	}
	if entries[1].Fields["reason"] != "bad totp" {
		t.Errorf("unexpected second entry fields: %+v", entries[1].Fields)
	}
}

func TestReadMissingLogReturnsNoEntries(t *testing.T) {
	entries, err := Read(filepath.Join(t.TempDir(), "does-not-exist.log"))
	if err != nil {
		t.Fatal(err)
	}
	if entries != nil {
		t.Fatalf("expected no entries, got %+v", entries)
	}
}

func TestReadRoundTripsWhatLogWrote(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Log("watch", "pass", map[string]any{"auto_restored": 1}); err != nil {
		t.Fatal(err)
	}
	if err := l.Log("sentinel", "pass", map[string]any{"recreated": 0}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	entries, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Component != "watch" || entries[1].Component != "sentinel" {
		t.Errorf("expected oldest-first order, got %+v", entries)
	}
}

func TestReadSkipsMalformedLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Log("watch", "pass", nil); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate a crash mid-write: append a truncated, non-JSON line.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"time":"2026-01-0`); err != nil {
		t.Fatal(err)
	}
	f.Close()

	entries, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected the malformed trailing line to be skipped, got %d entries", len(entries))
	}
}

func TestLastByComponentKeepsMostRecent(t *testing.T) {
	entries := []Entry{
		{Component: "watch", Action: "pass"},
		{Component: "sentinel", Action: "pass"},
		{Component: "watch", Action: "auto-restored"},
	}

	last := LastByComponent(entries)
	if len(last) != 2 {
		t.Fatalf("got %d components, want 2", len(last))
	}
	if last["watch"].Action != "auto-restored" {
		t.Errorf("expected the later watch entry to win, got %+v", last["watch"])
	}
}
