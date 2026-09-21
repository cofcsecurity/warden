// Package audit writes an append-only, JSON-lines log of every action
// Warden takes.
package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// maxLineBytes bounds one audit line while reading; anything longer is
// skipped rather than read into memory.
const maxLineBytes = 1 << 20

// Entry is a single audit log record. Component-specific detail goes in
// Fields rather than as ad-hoc struct fields, so this package doesn't need
// to know about every caller.
type Entry struct {
	Time      time.Time      `json:"time"`
	Component string         `json:"component"`
	Action    string         `json:"action"`
	Fields    map[string]any `json:"fields,omitempty"`
	// Host is this box's hostname, stamped on every entry. It costs
	// almost nothing locally (the log is already per-box) and is what
	// makes the log usable once it leaves the box: replicated audit logs
	// from six or eight boxes land in one place (see replicate), and
	// anything ingesting these JSON lines — a SIEM, or just grep — needs
	// each line to say which box it came from without inferring it from
	// a file path. Deliberately the hostname rather than the binary's
	// own (disguised, identical across the fleet) install name.
	Host string `json:"host,omitempty"`
}

// MaxLogBytes is the size at which New rotates the log to <path>.1
// before opening it. Without a cap the log grows unbounded across a
// multi-day competition — store.Prune bounds the object store, but
// nothing bounded this. One previous file is kept, and Read spans both,
// so rotation doesn't hide history from `warden alerts`/`status`.
const MaxLogBytes = 8 << 20 // 8 MiB

// RotatedPath is where New moves the log once it passes MaxLogBytes.
func RotatedPath(path string) string {
	return path + ".1"
}

// Logger appends JSON-lines entries to a log file. It is safe for
// concurrent use.
type Logger struct {
	mu   sync.Mutex
	f    *os.File
	path string
	host string
}

// New opens (creating if necessary) the audit log at path for appending,
// rotating it first if it has grown past MaxLogBytes.
func New(path string) (*Logger, error) {
	if err := rotateIfLarge(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	host, _ := os.Hostname() // an unknowable hostname just means an empty field
	return &Logger{f: f, path: path, host: host}, nil
}

// rotateIfLarge moves an oversized log aside to RotatedPath, replacing
// whatever was there. Content older than the last two files is dropped on
// the floor by design — the durable copy of an audit trail is the one
// replicate has already pushed off-box (see cmd/warden/replicate.go),
// not this file, which red team with root can delete outright anyway.
func rotateIfLarge(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("audit: stat %s: %w", path, err)
	}
	if info.Size() < MaxLogBytes {
		return nil
	}
	if err := os.Rename(path, RotatedPath(path)); err != nil {
		return fmt.Errorf("audit: rotate %s: %w", path, err)
	}
	return nil
}

// Log appends one entry, stamped with the current time.
func (l *Logger) Log(component, action string, fields map[string]any) error {
	entry := Entry{
		Time:      time.Now().UTC(),
		Component: component,
		Action:    action,
		Fields:    fields,
		Host:      l.host,
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

// Read returns every entry in the log at path, oldest first — including
// the rotated-aside previous file, if there is one, so rotation never
// makes recent history disappear from `warden alerts` or `status`. A
// missing log returns no entries rather than an error, matching
// manifest.New's treatment of a not-yet-created file. A malformed line is
// skipped rather than failing the whole read, since a corrupted last
// entry (e.g. from a crash mid-write) shouldn't hide everything before
// it.
func Read(path string) ([]Entry, error) {
	rotated, err := readFile(RotatedPath(path))
	if err != nil {
		return nil, err
	}
	current, err := readFile(path)
	if err != nil {
		return nil, err
	}
	return append(rotated, current...), nil
}

func readFile(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	defer f.Close()

	// Read line by line with a fixed buffer, skipping any line longer
	// than it — one oversized or binary-garbage line (a truncated write,
	// a file someone padded) must not make the whole log unreadable, for
	// the same reason a malformed JSON line is skipped rather than
	// fatal: everything before it is still evidence.
	var entries []Entry
	r := bufio.NewReaderSize(f, maxLineBytes)
	for {
		line, err := r.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			for err == bufio.ErrBufferFull {
				_, err = r.ReadSlice('\n')
			}
			if err == nil {
				continue // skipped an over-long line
			}
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("audit: read %s: %w", path, err)
		}

		if len(bytes.TrimSpace(line)) > 0 {
			var e Entry
			if json.Unmarshal(bytes.TrimSpace(line), &e) == nil {
				entries = append(entries, e)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("audit: read %s: %w", path, err)
		}
	}
	return entries, nil
}

// LastByComponent returns the most recent entry for each component seen in
// entries (which should be oldest-first, as Read returns them).
func LastByComponent(entries []Entry) map[string]Entry {
	last := map[string]Entry{}
	for _, e := range entries {
		last[e.Component] = e
	}
	return last
}
