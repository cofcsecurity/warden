package main

import (
	"testing"
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

func TestDialReplicateTargetSSHWithoutPeerKeyErrors(t *testing.T) {
	if _, _, err := dialReplicateTarget("ssh+receiver://warden@backup-box/box1", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"); err == nil {
		t.Fatal("expected an error when this box has no backup key yet")
	}
}

func TestDialReplicateTargetSSHWithoutHostKeyErrors(t *testing.T) {
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
	setPeers(t, "ssh://a/root||ssh-ed25519 AAAA host-a;;file:///mnt/backup||")

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
