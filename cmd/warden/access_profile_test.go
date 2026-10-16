package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A broken profile must never block the access shell or disarm, while
// commands that depend on the profile refuse to run.
func TestBrokenProfileEmergencyAccess(t *testing.T) {
	if root := os.Getenv("WARDEN_TEST_ACCESS_ROOT"); root != "" {
		profilePathFor = func(paths) string { return filepath.Join(root, "profile.json") }
		if err := runOpmenu(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	dir := t.TempDir()
	profile := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(profile, []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		request, want string
		success       bool
	}{
		{"shell", "SHELL_REACHED", true},
		{"", "SHELL_REACHED", true},
		{"restore /example --apply", "host profile:", false},
		{"rm -rf /", "not a warden command", false},
	} {
		t.Run(tc.request, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestBrokenProfileEmergencyAccess$")
			cmd.Env = append(os.Environ(), "WARDEN_TEST_ACCESS_ROOT="+dir, "SSH_ORIGINAL_COMMAND="+tc.request, "SSH_CLIENT=203.0.113.10 1234 22")
			cmd.Stdin = strings.NewReader("printf SHELL_REACHED")
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.success || !strings.Contains(string(out), tc.want) {
				t.Fatalf("%v: %s", err, out)
			}
		})
	}
	for _, command := range []string{"watch", "restore", "arm", "snapshot"} {
		if err := prepareCommandProfile(command, profile); err == nil {
			t.Fatalf("%s accepted invalid profile", command)
		}
	}
	for _, command := range []string{"disarm", "status", "sentinel-check", "opmenu"} {
		if err := prepareCommandProfile(command, profile); err != nil {
			t.Fatalf("%s blocked: %v", command, err)
		}
	}
}
