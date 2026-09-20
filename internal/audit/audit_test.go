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
