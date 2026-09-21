package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"warden/internal/accountlock"
	"warden/internal/audit"
	"warden/internal/autoban"
	"warden/internal/heartbeat"
	"warden/internal/manifest"
)

// heartbeatComponents are the periodic components a beat reports the last
// run of — every one that has its own timer, since a timer silently
// ceasing to fire is precisely what a reader is looking for.
var heartbeatComponents = []string{"watch", "sentinel", "scan", "replicate"}

// collectHeartbeat builds this box's current self-report. Every field is
// read from state that already exists (the manifest, the audit log, the
// ban/lock stores) — a beat never causes work of its own, it just
// summarizes what the box already knows about itself.
func collectHeartbeat(p paths, now time.Time) (heartbeat.Beat, error) {
	host, _ := os.Hostname()

	armed, err := isArmed(p)
	if err != nil {
		return heartbeat.Beat{}, err
	}

	m, err := manifest.New(p.configManifestPath)
	if err != nil {
		return heartbeat.Beat{}, err
	}

	entries, err := audit.Read(p.auditLogPath)
	if err != nil {
		return heartbeat.Beat{}, err
	}
	last := audit.LastByComponent(entries)
	lastPass := map[string]time.Time{}
	for _, component := range heartbeatComponents {
		if e, ok := last[component]; ok && !e.Time.IsZero() {
			lastPass[component] = e.Time
		}
	}

	beat := heartbeat.Beat{
		Host:            host,
		WrittenAt:       now.UTC(),
		IntervalSeconds: int(heartbeatInterval.Seconds()),
		Armed:           armed,
		Generation:      m.Generation,
		LastPass:        lastPass,
	}

	if bans, err := autoban.NewStore(p.bannedIPsPath).Load(); err == nil {
		for _, b := range bans {
			if !b.Expired(now) {
				beat.ActiveBans++
			}
		}
	}
	if locks, err := accountlock.NewStore(p.accountLocksPath).Load(); err == nil {
		for _, l := range locks {
			if !l.Expired(now) {
				beat.ActiveLocks++
			}
		}
	}

	return beat, nil
}

// heartbeatGlobsUnder builds the patterns to search when an operator
// names a directory explicitly: both "this is the account home holding
// one root per peer" and "this is a single replication root" are
// reasonable readings of --from, and checking both costs nothing.
func heartbeatGlobsUnder(dir string) []string {
	return []string{
		filepath.Join(dir, "*", "heartbeat", "*.json"),
		filepath.Join(dir, "heartbeat", "*.json"),
	}
}

// inboundHeartbeats reads the beats other boxes have pushed into this
// box's own receiving directory. Reading locally rather than fetching
// from a peer is the whole design: the boxes that report here are the
// ones that replicate *to* this box, and their beats are already sitting
// on this disk with no network round trip and nothing to authenticate.
func inboundHeartbeats(globs []string) ([]heartbeat.Beat, error) {
	return heartbeat.Collect(globs)
}

// heartbeatAlertState remembers which silent peers have already been
// alerted on, so a box that stays dark for six hours produces one alert
// and one recovery notice rather than an alert every ten minutes for the
// rest of the competition.
type heartbeatAlertState map[string]heartbeatAlert

type heartbeatAlert struct {
	// AlertedAt is when the silence was reported; SeenAt is the
	// timestamp of the beat that was current at that point, which is
	// what tells a later pass whether anything new has arrived since.
	AlertedAt time.Time `json:"alerted_at"`
	SeenAt    time.Time `json:"seen_at"`
}

func loadHeartbeatAlertState(path string) (heartbeatAlertState, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return heartbeatAlertState{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("heartbeat: read %s: %w", path, err)
	}
	state := heartbeatAlertState{}
	if err := json.Unmarshal(data, &state); err != nil {
		// Same reasoning as replicate's push state: a corrupt file
		// starts over (at worst one duplicate alert) rather than
		// stopping the check that notices a box is gone.
		return heartbeatAlertState{}, nil
	}
	return state, nil
}

func saveHeartbeatAlertState(path string, state heartbeatAlertState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("heartbeat: encode alert state: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("heartbeat: write %s: %w", path, err)
	}
	return nil
}

// checkPeerHeartbeats is the dead-man's switch itself, run on
// sentinel-check's schedule: any box that reports here and has since gone
// quiet past its own declared interval plus grace gets one loud audit
// entry, and one more when it comes back.
//
// It deliberately never reacts beyond logging. A missing heartbeat has
// plenty of innocent explanations (a reboot, a network blip, a box
// legitimately taken down), and a beat is forgeable by anyone who can
// write to the receiving directory — so this is an alert for a human,
// never an input to an automatic response.
func checkPeerHeartbeats(p paths, log *audit.Logger, now time.Time) error {
	beats, err := inboundHeartbeats(inboundHeartbeatGlobs)
	if err != nil {
		return err
	}
	if len(beats) == 0 {
		return nil // nothing reports to this box; nothing to miss
	}

	state, err := loadHeartbeatAlertState(p.heartbeatAlertsPath)
	if err != nil {
		return err
	}

	changed := false
	seen := map[string]bool{}
	for _, b := range beats {
		seen[b.Host] = true
		alert, alreadyAlerted := state[b.Host]

		switch {
		case b.Stale(now, heartbeatStaleGrace):
			if alreadyAlerted && !b.WrittenAt.After(alert.SeenAt) {
				continue // already reported this same silence
			}
			if err := log.Log("react", "alert", map[string]any{
				"source":         "heartbeat",
				"peer":           b.Host,
				"description":    fmt.Sprintf("no heartbeat from %s in %s — that box may be down, cut off, or have had its timers killed", b.Host, now.Sub(b.WrittenAt).Round(time.Minute)),
				"last_seen":      b.WrittenAt.UTC().Format(time.RFC3339),
				"peer_armed":     b.Armed,
				"silent_seconds": int(now.Sub(b.WrittenAt).Seconds()),
			}); err != nil {
				return err
			}
			state[b.Host] = heartbeatAlert{AlertedAt: now.UTC(), SeenAt: b.WrittenAt}
			changed = true

		case alreadyAlerted:
			if err := log.Log("react", "peer-returned", map[string]any{
				"source":      "heartbeat",
				"peer":        b.Host,
				"description": fmt.Sprintf("%s is reporting again (silent since %s)", b.Host, alert.SeenAt.UTC().Format(time.RFC3339)),
			}); err != nil {
				return err
			}
			delete(state, b.Host)
			changed = true
		}
	}

	// Forget any host that no longer reports here at all — its entry is
	// about a silence nobody can resolve any more (the peer was
	// decommissioned, or rebuilt under a new name), and keeping it would
	// leave a permanent stale record nothing ever clears.
	for host := range state {
		if !seen[host] {
			delete(state, host)
			changed = true
		}
	}

	if !changed {
		return nil
	}
	return saveHeartbeatAlertState(p.heartbeatAlertsPath, state)
}
