package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warden/internal/audit"
	"warden/internal/heartbeat"
	"warden/internal/replicate"
)

func TestDialReplicateTargetFile(t *testing.T) {
	dir := t.TempDir()
	target, closeTarget, err := dialReplicateTarget("file://"+dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer closeTarget()

	if has, err := target.Has("deadbeef"); err != nil || has {
		t.Fatalf("expected a fresh file:// target to report Has=false, got has=%v err=%v", has, err)
	}
}

func TestDialReplicateTargetUnsupportedScheme(t *testing.T) {
	if _, _, err := dialReplicateTarget("ftp://example.com/x", ""); err == nil {
		t.Fatal("expected an error for an unsupported scheme")
	}
}

func TestDialReplicateTargetSSHWithoutBuildTimeKeyErrors(t *testing.T) {
	oldKey := buildReplicateKey
	buildReplicateKey = ""
	defer func() { buildReplicateKey = oldKey }()

	if _, _, err := dialReplicateTarget("ssh://warden@backup-box/warden", "ssh-ed25519 AAAA"); err == nil {
		t.Fatal("expected an error when no replication key is baked in")
	}
}

func TestDialReplicateTargetSSHWithoutHostKeyErrors(t *testing.T) {
	oldKey := buildReplicateKey
	buildReplicateKey = "dGVzdA=="
	defer func() { buildReplicateKey = oldKey }()

	if _, _, err := dialReplicateTarget("ssh://warden@backup-box/warden", ""); err == nil {
		t.Fatal("expected an error when the target has no pinned host key")
	}
}

func TestParseReplicateTargets(t *testing.T) {
	targets := parseReplicateTargets("ssh://a/root||ssh-ed25519 AAAA host-a;;file:///mnt/backup||")
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2: %+v", len(targets), targets)
	}
	if targets[0].url != "ssh://a/root" || targets[0].hostKey != "ssh-ed25519 AAAA host-a" {
		t.Errorf("unexpected first target: %+v", targets[0])
	}
	if targets[1].url != "file:///mnt/backup" || targets[1].hostKey != "" {
		t.Errorf("unexpected second target: %+v", targets[1])
	}
}

func TestParseReplicateTargetsEmpty(t *testing.T) {
	if targets := parseReplicateTargets(""); len(targets) != 0 {
		t.Fatalf("expected no targets for an empty string, got %+v", targets)
	}
}

func TestHostKeyForConfiguredTarget(t *testing.T) {
	old := buildReplicateTargets
	buildReplicateTargets = "ssh://a/root||ssh-ed25519 AAAA host-a;;file:///mnt/backup||"
	defer func() { buildReplicateTargets = old }()

	hostKey, err := hostKeyForConfiguredTarget("ssh://a/root")
	if err != nil {
		t.Fatal(err)
	}
	if hostKey != "ssh-ed25519 AAAA host-a" {
		t.Errorf("got %q", hostKey)
	}

	if _, err := hostKeyForConfiguredTarget("ssh://not-configured/root"); err == nil {
		t.Fatal("expected an error for a peer URL that isn't configured")
	}
}

// auditTestPaths builds a paths value pointing at a temp dir, for the
// audit-replication helpers (which only ever touch auditLogPath and
// auditPushStatePath).
func auditTestPaths(t *testing.T) paths {
	t.Helper()
	dir := t.TempDir()
	return paths{
		auditLogPath:       filepath.Join(dir, "audit.log"),
		auditPushStatePath: filepath.Join(dir, "audit-replicated.json"),
	}
}

func fsReplicator(t *testing.T) (*replicate.Replicator, *replicate.FSTarget, string) {
	t.Helper()
	root := t.TempDir()
	target, err := replicate.NewFSTarget(root)
	if err != nil {
		t.Fatal(err)
	}
	return replicate.New(target), target, root
}

func replicatedAudit(t *testing.T, target *replicate.FSTarget) string {
	t.Helper()
	data, err := replicate.NewRetriever(target).PullAudit()
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestPushAuditLogSendsOnlyWhatIsNew is the whole point of tracking an
// offset per peer: a 15-minute timer must not re-send the entire log
// every pass.
func TestPushAuditLogSendsOnlyWhatIsNew(t *testing.T) {
	p := auditTestPaths(t)
	r, target, _ := fsReplicator(t)
	state := auditPushState{}

	if err := os.WriteFile(p.auditLogPath, []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := pushAuditLog(p, r, "file:///peer", state); err != nil {
		t.Fatal(err)
	}

	// Nothing appended since: nothing to send.
	sent, err := pushAuditLog(p, r, "file:///peer", state)
	if err != nil {
		t.Fatal(err)
	}
	if sent != 0 {
		t.Errorf("expected an unchanged log to send nothing, sent %d bytes", sent)
	}

	f, err := os.OpenFile(p.auditLogPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("two\n")
	f.Close()

	sent, err = pushAuditLog(p, r, "file:///peer", state)
	if err != nil {
		t.Fatal(err)
	}
	if sent != len("two\n") {
		t.Errorf("expected only the appended bytes to be sent, sent %d", sent)
	}
	if got := replicatedAudit(t, target); got != "one\ntwo\n" {
		t.Errorf("peer should hold the whole log exactly once, got %q", got)
	}
}

// TestPushAuditLogSurvivesRotation covers the case that would otherwise
// lose evidence outright: the log rotated between passes, so the bytes
// written to the old file after the last push only exist there.
func TestPushAuditLogSurvivesRotation(t *testing.T) {
	p := auditTestPaths(t)
	r, target, _ := fsReplicator(t)
	state := auditPushState{}

	if err := os.WriteFile(p.auditLogPath, []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := pushAuditLog(p, r, "file:///peer", state); err != nil {
		t.Fatal(err)
	}

	// More gets logged, then the file rotates before the next push.
	if err := os.WriteFile(p.auditLogPath, []byte("one\nmissed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(p.auditLogPath, audit.RotatedPath(p.auditLogPath)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.auditLogPath, []byte("after\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := pushAuditLog(p, r, "file:///peer", state); err != nil {
		t.Fatal(err)
	}

	got := replicatedAudit(t, target)
	for _, want := range []string{"one\n", "missed\n", "after\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("peer is missing %q after rotation; has %q", want, got)
		}
	}
}

func TestPushAuditLogWithNoLogYetIsNotAnError(t *testing.T) {
	p := auditTestPaths(t)
	r, _, _ := fsReplicator(t)

	sent, err := pushAuditLog(p, r, "file:///peer", auditPushState{})
	if err != nil {
		t.Fatalf("a box that has never logged anything must not fail replication: %v", err)
	}
	if sent != 0 {
		t.Errorf("expected nothing sent, got %d bytes", sent)
	}
}

func TestAuditPushStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit-replicated.json")
	if err := saveAuditPushState(path, auditPushState{
		"ssh://peer/root": {Offset: 42, Digest: strings.Repeat("a", 64)},
	}); err != nil {
		t.Fatal(err)
	}
	state, err := loadAuditPushState(path)
	if err != nil {
		t.Fatal(err)
	}
	if state["ssh://peer/root"].Offset != 42 || state["ssh://peer/root"].Digest != strings.Repeat("a", 64) {
		t.Errorf("expected the offset to survive a round trip, got %+v", state)
	}

	// Corrupt state starts over rather than stopping replication.
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	state, err = loadAuditPushState(path)
	if err != nil {
		t.Fatalf("corrupt state must not fail replication: %v", err)
	}
	if len(state) != 0 {
		t.Errorf("expected an empty state, got %+v", state)
	}
}

func TestPushHeartbeatLandsOnThePeer(t *testing.T) {
	r, _, root := fsReplicator(t)
	at := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

	beat := heartbeat.Beat{Host: "box1", WrittenAt: at, IntervalSeconds: 900, Armed: true, Generation: 4}
	data, err := heartbeat.Encode(beat)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.PushHeartbeat(replicate.HeartbeatName(beat.Host, at), data); err != nil {
		t.Fatal(err)
	}

	beats, err := heartbeat.Collect(heartbeatGlobsUnder(root))
	if err != nil {
		t.Fatal(err)
	}
	if len(beats) != 1 || beats[0].Host != "box1" || beats[0].Generation != 4 {
		t.Fatalf("expected the pushed beat to be readable from the peer root, got %+v", beats)
	}
}

// TestPushHeartbeatNamesNeverCollide: each push leaves its own file, so
// two pushes in the same second must not silently become one (the
// write-once targets skip a name that already exists).
func TestPushHeartbeatNamesNeverCollide(t *testing.T) {
	r, _, root := fsReplicator(t)
	at := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

	for i, when := range []time.Time{at, at.Add(time.Millisecond)} {
		beat := heartbeat.Beat{Host: "box1", WrittenAt: when, IntervalSeconds: 900, Generation: i + 1}
		data, err := heartbeat.Encode(beat)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.PushHeartbeat(replicate.HeartbeatName(beat.Host, when), data); err != nil {
			t.Fatal(err)
		}
	}

	files, err := filepath.Glob(filepath.Join(root, "heartbeat", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("expected both pushes to leave a file, got %v", files)
	}

	// The reader takes the newest, which is the later generation.
	beats, err := heartbeat.Collect(heartbeatGlobsUnder(root))
	if err != nil {
		t.Fatal(err)
	}
	if len(beats) != 1 || beats[0].Generation != 2 {
		t.Fatalf("expected the newest beat to win, got %+v", beats)
	}
}

func TestCollectHeartbeatReportsThisBoxesState(t *testing.T) {
	dir := t.TempDir()
	p := paths{
		configManifestPath: filepath.Join(dir, "manifest-config.json"),
		auditLogPath:       filepath.Join(dir, "audit.log"),
		armedMarkerPath:    filepath.Join(dir, "armed"),
		bannedIPsPath:      filepath.Join(dir, "banned_ips.json"),
		accountLocksPath:   filepath.Join(dir, "account_locks.json"),
	}
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

	log, err := audit.New(p.auditLogPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Log("watch", "pass", nil); err != nil {
		t.Fatal(err)
	}
	log.Close()

	if err := os.WriteFile(p.armedMarkerPath, []byte("armed\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	beat, err := collectHeartbeat(p, now)
	if err != nil {
		t.Fatal(err)
	}

	if !beat.Armed {
		t.Error("expected the beat to report this box as armed")
	}
	if beat.IntervalSeconds != int(heartbeatInterval.Seconds()) {
		t.Errorf("expected the beat to declare its own interval, got %d", beat.IntervalSeconds)
	}
	if _, ok := beat.LastPass["watch"]; !ok {
		t.Errorf("expected the recorded watch pass to be reported, got %+v", beat.LastPass)
	}
	if _, ok := beat.LastPass["scan"]; ok {
		t.Error("a component that has never run must be absent, not zero-valued")
	}
	if !beat.WrittenAt.Equal(now.UTC()) {
		t.Errorf("expected the beat stamped with the given time, got %v", beat.WrittenAt)
	}
}
