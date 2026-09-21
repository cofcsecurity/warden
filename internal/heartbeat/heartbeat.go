// Package heartbeat is the dead-man's switch: every replication push
// leaves a small "this box was alive and here's how it was doing" record
// on each peer, so a box that goes completely dark — powered off, network
// cut, or every one of its timers killed at once — produces a signal
// somewhere other than itself.
//
// This is the one alerting path that can't be silenced from the box it's
// about, which is exactly the point. Everything else Warden reports
// (audit entries, `warden alerts`, `warden status`) is written and read
// on the box being attacked; if that box stops running Warden entirely,
// all of it goes quiet, and quiet is indistinguishable from calm. Here,
// *absence* is the alert: peers know roughly when the next beat is due
// (Interval), so one that never arrives is a finding on their side.
//
// Trust boundary: a beat is evidence, not authentication. It is written
// by the replication account into a directory that account can write, so
// anyone who can write there can forge one — including, on a compromised
// peer, forging a healthy beat for a box that is actually down. Nothing
// automatic is ever done in response to a beat; they're surfaced to a
// human (`warden fleet`) and logged as an alert, which is the same bar
// the rest of Warden's reporting holds itself to.
package heartbeat

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Beat is one box's self-report at one moment. Deliberately small and
// flat: it's JSON, it's read by other boxes, and every field is
// something an operator would actually look at when deciding whether a
// box needs attention.
type Beat struct {
	Host      string    `json:"host"`
	WrittenAt time.Time `json:"written_at"`
	// IntervalSeconds is how often this box intends to write one of
	// these, so a reader can decide what "late" means without hardcoding
	// the sender's schedule. Seconds rather than a Go duration string so
	// anything else reading these files (jq, a SIEM) gets a plain number.
	IntervalSeconds int `json:"interval_seconds"`

	Armed      bool `json:"armed"`
	Generation int  `json:"generation"`
	// LastPass is the last recorded run of each periodic component
	// ("watch", "sentinel", "scan", "replicate"). A component missing
	// from the map has never run on this box, which is itself worth
	// seeing.
	LastPass    map[string]time.Time `json:"last_pass,omitempty"`
	ActiveBans  int                  `json:"active_bans"`
	ActiveLocks int                  `json:"active_locks"`
}

// Encode renders a beat as the JSON written to a peer.
func Encode(b Beat) ([]byte, error) {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("heartbeat: encode: %w", err)
	}
	return append(data, '\n'), nil
}

// Parse decodes one beat file.
func Parse(data []byte) (Beat, error) {
	var b Beat
	if err := json.Unmarshal(data, &b); err != nil {
		return Beat{}, fmt.Errorf("heartbeat: parse: %w", err)
	}
	return b, nil
}

// Age is how long ago this beat was written, as of now.
func (b Beat) Age(now time.Time) time.Duration {
	return now.Sub(b.WrittenAt)
}

// Stale reports whether this box has missed enough beats to be worth
// alerting on. The window is the sender's own declared interval plus
// grace, so a box that pushes every 15 minutes and one that pushes every
// hour are each judged against their own schedule rather than a constant
// that happens to suit one of them. A beat with no declared interval
// (an older sender) falls back to grace alone.
func (b Beat) Stale(now time.Time, grace time.Duration) bool {
	return b.Age(now) > b.expectedWithin()+grace
}

func (b Beat) expectedWithin() time.Duration {
	if b.IntervalSeconds <= 0 {
		return 0
	}
	return time.Duration(b.IntervalSeconds) * time.Second
}

// Collect reads every beat file matching any of globs and returns the
// newest one per host, sorted by host.
//
// Unreadable and unparsable files are skipped rather than failing the
// whole read: these files come from other boxes, one of which may be
// mid-compromise, and one bad file must not be able to hide every other
// box's status. A beat with no host is dropped for the same reason —
// there's nothing useful to say about it and nothing to key it by.
func Collect(globs []string) ([]Beat, error) {
	newest := map[string]Beat{}

	for _, pattern := range globs {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("heartbeat: bad pattern %q: %w", pattern, err)
		}
		for _, path := range matches {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			b, err := Parse(data)
			if err != nil || b.Host == "" {
				continue
			}
			if existing, ok := newest[b.Host]; ok && !b.WrittenAt.After(existing.WrittenAt) {
				continue
			}
			newest[b.Host] = b
		}
	}

	beats := make([]Beat, 0, len(newest))
	for _, b := range newest {
		beats = append(beats, b)
	}
	sort.Slice(beats, func(i, j int) bool { return beats[i].Host < beats[j].Host })
	return beats, nil
}
