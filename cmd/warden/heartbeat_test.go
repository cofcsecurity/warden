package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"warden/internal/audit"
	"warden/internal/heartbeat"
)

// heartbeatTestSetup builds a paths value plus a receiving directory of
// the shape a peer's replication root has, and a logger to read entries
// back out of.
func heartbeatTestSetup(t *testing.T) (p paths, receiveDir string) {
	t.Helper()
	dir := t.TempDir()

	p = paths{
		auditLogPath:        filepath.Join(dir, "audit.log"),
		heartbeatAlertsPath: filepath.Join(dir, "heartbeat-alerts.json"),
	}
	return p, filepath.Join(dir, "receive")
}

func writePeerBeat(t *testing.T, receiveDir, host string, at time.Time) {
	t.Helper()
	dir := filepath.Join(receiveDir, "from-"+host, "heartbeat")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := heartbeat.Encode(heartbeat.Beat{
		Host:            host,
		WrittenAt:       at,
		IntervalSeconds: int(heartbeatInterval.Seconds()),
		Armed:           true,
	})
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(dir, host+"-"+at.UTC().Format("20060102150405.000000000")+".json")
	if err := os.WriteFile(name, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// checkPeers runs the dead-man's switch against a specific receiving
// directory, standing in for the box-wide default globs.
func checkPeers(t *testing.T, p paths, receiveDir string, now time.Time) []audit.Entry {
	t.Helper()

	oldGlobs := inboundHeartbeatGlobs
	inboundHeartbeatGlobs = heartbeatGlobsUnder(receiveDir)
	defer func() { inboundHeartbeatGlobs = oldGlobs }()

	log, err := audit.New(p.auditLogPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkPeerHeartbeats(p, log, now); err != nil {
		log.Close()
		t.Fatal(err)
	}
	log.Close()

	entries, err := audit.Read(p.auditLogPath)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func heartbeatEntries(entries []audit.Entry) []audit.Entry {
	var out []audit.Entry
	for _, e := range entries {
		if source, _ := e.Fields["source"].(string); source == "heartbeat" {
			out = append(out, e)
		}
	}
	return out
}

// TestPeerGoingSilentAlertsOnceAndRecovers is the dead-man's switch end
// to end: a box that stops reporting produces exactly one alert however
// long it stays dark, and one notice when it comes back.
func TestPeerGoingSilentAlertsOnceAndRecovers(t *testing.T) {
	p, receiveDir := heartbeatTestSetup(t)
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

	// A beat from well inside its own schedule: nothing to report.
	writePeerBeat(t, receiveDir, "box2", now.Add(-5*time.Minute))
	if got := heartbeatEntries(checkPeers(t, p, receiveDir, now)); len(got) != 0 {
		t.Fatalf("a healthy peer must not alert, got %+v", got)
	}

	// Two hours later that same beat is the newest one there is.
	silent := now.Add(2 * time.Hour)
	entries := heartbeatEntries(checkPeers(t, p, receiveDir, silent))
	if len(entries) != 1 || entries[0].Action != "alert" {
		t.Fatalf("expected exactly one silence alert, got %+v", entries)
	}
	if peer, _ := entries[0].Fields["peer"].(string); peer != "box2" {
		t.Errorf("expected the alert to name box2, got %+v", entries[0].Fields)
	}

	// Still silent an hour after that: no second alert for the same
	// silence, or a dark box would fill the log every ten minutes for
	// the rest of the competition.
	entries = heartbeatEntries(checkPeers(t, p, receiveDir, silent.Add(time.Hour)))
	if len(entries) != 1 {
		t.Fatalf("expected no repeat alert for an ongoing silence, got %+v", entries)
	}

	// It comes back.
	back := silent.Add(2 * time.Hour)
	writePeerBeat(t, receiveDir, "box2", back.Add(-time.Minute))
	entries = heartbeatEntries(checkPeers(t, p, receiveDir, back))
	if len(entries) != 2 || entries[1].Action != "peer-returned" {
		t.Fatalf("expected a recovery notice, got %+v", entries)
	}

	// And a later silence is a fresh alert, not suppressed by the old
	// state.
	entries = heartbeatEntries(checkPeers(t, p, receiveDir, back.Add(3*time.Hour)))
	if len(entries) != 3 || entries[2].Action != "alert" {
		t.Fatalf("expected a new silence to alert again, got %+v", entries)
	}
}

func TestNoPeersReportingIsNotAnAlert(t *testing.T) {
	p, receiveDir := heartbeatTestSetup(t)
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

	if got := heartbeatEntries(checkPeers(t, p, receiveDir, now)); len(got) != 0 {
		t.Fatalf("a box nobody replicates to has nothing to miss, got %+v", got)
	}
}

// TestSlowPeerIsJudgedOnItsOwnInterval: the grace period is added to what
// the sender itself declared, so a box configured to replicate hourly
// isn't permanently reported as dead by a box that replicates every 15
// minutes.
func TestSlowPeerIsJudgedOnItsOwnInterval(t *testing.T) {
	p, receiveDir := heartbeatTestSetup(t)
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

	dir := filepath.Join(receiveDir, "from-box3", "heartbeat")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := heartbeat.Encode(heartbeat.Beat{
		Host:            "box3",
		WrittenAt:       now.Add(-50 * time.Minute),
		IntervalSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "box3.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	if got := heartbeatEntries(checkPeers(t, p, receiveDir, now)); len(got) != 0 {
		t.Fatalf("an hourly peer 50 minutes quiet is on schedule, got %+v", got)
	}
}

func TestAlertStateForgetsPeersThatStopReportingEntirely(t *testing.T) {
	p, receiveDir := heartbeatTestSetup(t)
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

	writePeerBeat(t, receiveDir, "box2", now.Add(-3*time.Hour))
	checkPeers(t, p, receiveDir, now) // alerts, recording state

	state, err := loadHeartbeatAlertState(p.heartbeatAlertsPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := state["box2"]; !ok {
		t.Fatalf("expected box2's silence recorded, got %+v", state)
	}

	// The peer's directory goes away entirely — decommissioned, or
	// rebuilt under another name. Its entry shouldn't linger forever.
	if err := os.RemoveAll(filepath.Join(receiveDir, "from-box2")); err != nil {
		t.Fatal(err)
	}
	writePeerBeat(t, receiveDir, "box4", now.Add(-time.Minute))
	checkPeers(t, p, receiveDir, now)

	state, err = loadHeartbeatAlertState(p.heartbeatAlertsPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := state["box2"]; ok {
		t.Errorf("expected a peer that no longer reports to be forgotten, got %+v", state)
	}
}

func TestHeartbeatAlertStateRoundTripAndCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heartbeat-alerts.json")
	at := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

	if err := saveHeartbeatAlertState(path, heartbeatAlertState{
		"box2": {AlertedAt: at, SeenAt: at.Add(-time.Hour)},
	}); err != nil {
		t.Fatal(err)
	}
	state, err := loadHeartbeatAlertState(path)
	if err != nil {
		t.Fatal(err)
	}
	if !state["box2"].SeenAt.Equal(at.Add(-time.Hour)) {
		t.Errorf("round trip mismatch: %+v", state)
	}

	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	state, err = loadHeartbeatAlertState(path)
	if err != nil {
		t.Fatalf("corrupt state must not stop the check that notices a box is gone: %v", err)
	}
	if len(state) != 0 {
		t.Errorf("expected an empty state, got %+v", state)
	}
}
