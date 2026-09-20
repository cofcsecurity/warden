// Package audit writes an append-only, JSON-lines log of every action
// Warden takes.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Entry is a single audit log record. Component-specific detail goes in
// Fields rather than as ad-hoc struct fields, so this package doesn't need
// to know about every caller.
type Entry struct {
	Time      time.Time      `json:"time"`
	Component string         `json:"component"`
	Action    string         `json:"action"`
	Fields    map[string]any `json:"fields,omitempty"`
}

// Logger appends JSON-lines entries to a log file. It is safe for
// concurrent use.
type Logger struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

// New opens (creating if necessary) the audit log at path for appending.
func New(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	return &Logger{f: f, path: path}, nil
}

// Log appends one entry, stamped with the current time.
func (l *Logger) Log(component, action string, fields map[string]any) error {
	entry := Entry{
		Time:      time.Now().UTC(),
		Component: component,
		Action:    action,
		Fields:    fields,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("audit: encode entry: %w", err)
	}
	data = append(data, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

	if _, err := l.f.Write(data); err != nil {
		return fmt.Errorf("audit: write %s: %w", l.path, err)
	}
	return l.f.Sync()
}

// Close closes the underlying log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}
