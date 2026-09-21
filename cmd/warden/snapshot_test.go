package main

import (
	"testing"

	"warden/internal/manifest"
)

func rec(path, hash string) manifest.Record {
	return manifest.Record{Path: path, Hash: hash, Class: manifest.SafeAutoRestore}
}

// TestKeepBaselineRefusesToAbsorbDrift is the guard against the race that
// used to decide, per edit, whether an attacker's change was reverted or
// blessed: snapshot and watch run on the same cadence, and whichever
// fired first won. Snapshot no longer gets a vote.
func TestKeepBaselineRefusesToAbsorbDrift(t *testing.T) {
	last := &manifest.Manifest{Records: []manifest.Record{
		rec("/etc/nginx/nginx.conf", "known-good"),
		rec("/etc/ssh/sshd_config", "known-good-sshd"),
		rec("/etc/vsftpd.conf", "known-good-ftp"),
	}}
	// nginx.conf edited, vsftpd.conf deleted, an unexpected file appeared.
	current := &manifest.Manifest{Records: []manifest.Record{
		rec("/etc/nginx/nginx.conf", "attacker"),
		rec("/etc/ssh/sshd_config", "known-good-sshd"),
		rec("/etc/cron.d/backdoor", "new"),
	}}

	records, declined := keepBaseline(last, current)

	byPath := map[string]manifest.Record{}
	for _, r := range records {
		byPath[r.Path] = r
	}
	if got := byPath["/etc/nginx/nginx.conf"].Hash; got != "known-good" {
		t.Errorf("drifted path must keep its baseline hash, got %q", got)
	}
	if _, ok := byPath["/etc/vsftpd.conf"]; !ok {
		t.Error("a deleted path must keep its record, or watch has nothing to restore from")
	}
	if _, ok := byPath["/etc/cron.d/backdoor"]; ok {
		t.Error("a path that appeared since the baseline must not be absorbed into it")
	}
	if len(records) != 3 {
		t.Errorf("expected exactly the baseline's records, got %+v", records)
	}

	want := []string{"/etc/cron.d/backdoor", "/etc/nginx/nginx.conf", "/etc/vsftpd.conf"}
	if len(declined) != len(want) {
		t.Fatalf("expected %v declined, got %v", want, declined)
	}
	for i, p := range want {
		if declined[i] != p {
			t.Errorf("declined[%d] = %q, want %q", i, declined[i], p)
		}
	}
}

func TestKeepBaselineLeavesAQuietBoxAlone(t *testing.T) {
	last := &manifest.Manifest{Records: []manifest.Record{rec("/etc/nginx/nginx.conf", "known-good")}}
	current := &manifest.Manifest{Records: []manifest.Record{rec("/etc/nginx/nginx.conf", "known-good")}}

	records, declined := keepBaseline(last, current)
	if len(declined) != 0 {
		t.Errorf("nothing changed, so nothing should be declined, got %v", declined)
	}
	if !sameRecords(records, last.Records) {
		t.Errorf("expected the baseline unchanged, got %+v", records)
	}
}

func TestSameRecordsComparesStateNotOrder(t *testing.T) {
	a := []manifest.Record{rec("/a", "1"), rec("/b", "2")}
	if !sameRecords(a, []manifest.Record{rec("/b", "2"), rec("/a", "1")}) {
		t.Error("order must not matter")
	}
	if sameRecords(a, []manifest.Record{rec("/a", "1")}) {
		t.Error("a missing record is a difference")
	}
	if sameRecords(a, []manifest.Record{rec("/a", "changed"), rec("/b", "2")}) {
		t.Error("a changed hash is a difference")
	}

	symlinked := rec("/a", "1")
	symlinked.Symlink = true
	if sameRecords(a, []manifest.Record{symlinked, rec("/b", "2")}) {
		t.Error("a path that became a symlink is a difference, even at the same hash")
	}
}
