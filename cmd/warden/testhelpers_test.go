package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// withConfig restores the runtime config after the test.
func withConfig(t *testing.T) {
	t.Helper()
	saved := cfg
	t.Cleanup(func() { cfg = saved })
}

// setPeers sets the configured peers from "<url>||<hostkey>;;..." records.
func setPeers(t *testing.T, spec string) {
	t.Helper()
	withConfig(t)
	cfg.Peers = nil
	for _, target := range parseReplicateTargets(spec) {
		cfg.Peers = append(cfg.Peers, peerConfig{URL: target.url, HostKey: target.hostKey})
	}
}

// testKey returns a fresh SSH public key line.
func testKey(t *testing.T, comment string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) + " " + comment
}

// withUnitDir points systemd unit paths at a temp dir for the test.
func withUnitDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	oldUnit, oldTimers, oldPaths := systemdUnitDir, systemdTimersWantsDir, systemdPathsWantsDir
	systemdUnitDir = dir
	systemdTimersWantsDir = filepath.Join(dir, "timers.target.wants")
	systemdPathsWantsDir = filepath.Join(dir, "paths.target.wants")
	t.Cleanup(func() { systemdUnitDir, systemdTimersWantsDir, systemdPathsWantsDir = oldUnit, oldTimers, oldPaths })
	return dir
}

// fakeCommands replaces runCommand and unitActive for the test, recording
// every command line.
func fakeCommands(t *testing.T) *[]string {
	t.Helper()
	var calls []string
	oldRun, oldActive := runCommand, unitActive
	runCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(append([]string{name}, args...), " "))
		return nil, nil
	}
	unitActive = func(string) bool { return true }
	t.Cleanup(func() { runCommand, unitActive = oldRun, oldActive })
	return &calls
}
