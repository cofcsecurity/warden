package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrokenProfileEmergencyAccess(t *testing.T) {
	if root := os.Getenv("WARDEN_TEST_ACCESS_ROOT"); root != "" {
		p := paths{auditLogPath: filepath.Join(root, "audit.log"), staticSecretPath: filepath.Join(root, "second-factor"), spentTOTPPath: filepath.Join(root, "spent")}
		profile := filepath.Join(root, "profile.json")
		err := prepareCommandProfile("opmenu", profile)
		if err == nil {
			err = runOpmenuWithPaths(p, profile)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "profile.json"), []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "second-factor"), []byte("test-factor"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		request, want string
		success       bool
	}{
		{"shell test-factor", "SHELL_REACHED", true},
		{"shell wrong-factor", "second factor required", false},
		{"restore test-factor /example apply", "host profile:", false},
		{"restore wrong-factor /example apply", "second factor required", false},
	} {
		t.Run(tc.request, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestBrokenProfileEmergencyAccess$")
			cmd.Env = append(os.Environ(), "WARDEN_TEST_ACCESS_ROOT="+dir, "SSH_ORIGINAL_COMMAND="+tc.request, "SSH_CLIENT=203.0.113.10 1234 22")
			cmd.Stdin = strings.NewReader("printf SHELL_REACHED")
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.success || !strings.Contains(string(out), tc.want) {
				t.Fatalf("%v: %s", err, out)
			}
			if !tc.success && strings.Contains(string(out), "SHELL_REACHED") {
				t.Fatal("unauthorized shell")
			}
		})
	}
	for _, command := range []string{"watch", "restore", "arm", "snapshot"} {
		if err := prepareCommandProfile(command, filepath.Join(dir, "profile.json")); err == nil {
			t.Fatalf("%s accepted invalid profile", command)
		}
	}
	for _, command := range []string{"disarm", "status"} {
		if err := prepareCommandProfile(command, filepath.Join(dir, "profile.json")); err != nil {
			t.Fatalf("%s blocked: %v", command, err)
		}
	}
}
