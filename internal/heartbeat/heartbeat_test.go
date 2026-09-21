package heartbeat

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeBeat(t *testing.T, dir string, b Beat) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, b.Host+"-"+b.WrittenAt.UTC().Format("20060102150405.000000000")+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEncodeParseRoundTrip(t *testing.T) {
	at := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	want := Beat{
		Host:            "box1",
		WrittenAt:       at,
		IntervalSeconds: 900,
		Armed:           true,
		Generation:      7,
		LastPass:        map[string]time.Time{"watch": at.Add(-2 * time.Minute)},
		ActiveBans:      1,
		ActiveLocks:     2,
	}

	data, err := Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}

	if got.Host != want.Host || got.Generation != want.Generation || !got.Armed {
		t.Errorf("round trip mismatch: %+v", got)
	}
	if !got.WrittenAt.Equal(want.WrittenAt) {
		t.Errorf("timestamp mismatch: %v vs %v", got.WrittenAt, want.WrittenAt)
	}
	if !got.LastPass["watch"].Equal(want.LastPass["watch"]) {
		t.Errorf("last pass mismatch: %+v", got.LastPass)
	}
	if got.ActiveBans != 1 || got.ActiveLocks != 2 {
		t.Errorf("counts mismatch: %+v", got)
	}
}

// TestStaleJudgesAgainstTheSendersOwnInterval is what lets boxes built
// with different replication intervals live in one fleet without the
// slower ones permanently looking dead.
func TestStaleJudgesAgainstTheSendersOwnInterval(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	grace := 35 * time.Minute

	fast := Beat{IntervalSeconds: 900, WrittenAt: now.Add(-40 * time.Minute)}  // 15m + 35m = 50m allowed
	slow := Beat{IntervalSeconds: 3600, WrittenAt: now.Add(-40 * time.Minute)} // 60m + 35m = 95m allowed

	if fast.Stale(now, grace) {
		t.Error("a 15-minute box 40 minutes quiet is late, not overdue")
	}
	if slow.Stale(now, grace) {
		t.Error("an hourly box 40 minutes quiet is well within its own schedule")
	}

	if !(Beat{IntervalSeconds: 900, WrittenAt: now.Add(-51 * time.Minute)}).Stale(now, grace) {
		t.Error("expected a 15-minute box quiet for 51 minutes to be overdue")
	}

	// A beat from a sender that declared no interval is judged on grace
	// alone rather than being treated as never overdue.
	if !(Beat{WrittenAt: now.Add(-36 * time.Minute)}).Stale(now, grace) {
		t.Error("expected a beat with no declared interval to fall back to grace")
	}
}

// TestCollectKeepsOnlyTheNewestPerHost matters because every push leaves
// another file behind: a peer's directory holds its whole history, and
// only the last one describes the box now.
func TestCollectKeepsOnlyTheNewestPerHost(t *testing.T) {
	root := t.TempDir()
	at := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

	box1 := filepath.Join(root, "from-box1", "heartbeat")
	writeBeat(t, box1, Beat{Host: "box1", WrittenAt: at.Add(-time.Hour), Generation: 3})
	writeBeat(t, box1, Beat{Host: "box1", WrittenAt: at, Generation: 9})

	box2 := filepath.Join(root, "from-box2", "heartbeat")
	writeBeat(t, box2, Beat{Host: "box2", WrittenAt: at.Add(-30 * time.Minute), Generation: 4})

	beats, err := Collect([]string{filepath.Join(root, "*", "heartbeat", "*.json")})
	if err != nil {
		t.Fatal(err)
	}
	if len(beats) != 2 {
		t.Fatalf("expected one beat per host, got %+v", beats)
	}
	if beats[0].Host != "box1" || beats[0].Generation != 9 {
		t.Errorf("expected box1's newest beat (generation 9), got %+v", beats[0])
	}
	if beats[1].Host != "box2" {
		t.Errorf("expected box2 second, sorted by host, got %+v", beats[1])
	}
}

// TestCollectSkipsUnusableFiles: these files arrive from other boxes, one
// of which may be mid-compromise. One bad file must not be able to hide
// every other box's status.
func TestCollectSkipsUnusableFiles(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "from-box1", "heartbeat")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "garbage.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hostless.json"), []byte(`{"written_at":"2026-09-21T12:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	writeBeat(t, dir, Beat{Host: "box1", WrittenAt: time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)})

	beats, err := Collect([]string{filepath.Join(root, "*", "heartbeat", "*.json")})
	if err != nil {
		t.Fatal(err)
	}
	if len(beats) != 1 || beats[0].Host != "box1" {
		t.Fatalf("expected only the one usable beat, got %+v", beats)
	}
}

func TestCollectWithNothingToReadIsNotAnError(t *testing.T) {
	beats, err := Collect([]string{filepath.Join(t.TempDir(), "*", "heartbeat", "*.json")})
	if err != nil {
		t.Fatal(err)
	}
	if len(beats) != 0 {
		t.Fatalf("expected no beats, got %+v", beats)
	}
}
