package main

import "testing"

func TestDialReplicateTargetFile(t *testing.T) {
	dir := t.TempDir()
	target, closeTarget, err := dialReplicateTarget("file://" + dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTarget()

	if has, err := target.Has("deadbeef"); err != nil || has {
		t.Fatalf("expected a fresh file:// target to report Has=false, got has=%v err=%v", has, err)
	}
}

func TestDialReplicateTargetUnsupportedScheme(t *testing.T) {
	if _, _, err := dialReplicateTarget("ftp://example.com/x"); err == nil {
		t.Fatal("expected an error for an unsupported scheme")
	}
}

func TestDialReplicateTargetSSHWithoutBuildTimeKeysErrors(t *testing.T) {
	oldKey, oldHostKey := buildReplicateKey, buildReplicateHostKey
	buildReplicateKey, buildReplicateHostKey = "", ""
	defer func() { buildReplicateKey, buildReplicateHostKey = oldKey, oldHostKey }()

	if _, _, err := dialReplicateTarget("ssh://warden@backup-box/warden"); err == nil {
		t.Fatal("expected an error when no replication key is baked in")
	}
}
