package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateBuildWorkspace(t *testing.T) {
	source, err := os.ReadFile("../../scripts/build-and-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	functions := strings.TrimSuffix(string(source), "main \"$@\"\n")
	if strings.Contains(functions, "\nmain \"$@\"") {
		t.Fatal("installer entry point remains")
	}
	for _, failAt := range []string{"none", "build", "install"} {
		t.Run(failAt, func(t *testing.T) {
			root := t.TempDir()
			script := filepath.Join(root, "scripts/build-and-install.sh")
			if err := os.MkdirAll(filepath.Dir(script), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(root, "deploy"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(script, []byte(functions), 0600); err != nil {
				t.Fatal(err)
			}
			body := `source "$0"
prepare_build_workspace
printf '%s' "$BUILD_WORKSPACE" > "$REPO_ROOT/workspace-path"
TEAM_PUBKEY='ssh-ed25519 AAAA test'
TEAM_FROM_IP=203.0.113.10
TOTP_SECRET=test-secret
REPLICATE_TARGETS= REPLICATE_KEY= AUTOBAN_ENABLED= AUTOLOCK_ENABLED= SAFE_ACCOUNTS=
go() {
 local output=''
 while [[ $# -gt 0 ]]; do
  if [[ "$1" == '-o' ]]; then shift; output="$1"; fi
  shift
 done
 [[ "$output" == "$BUILD_WORKSPACE/warden" ]]
 [[ "$GOCACHE" == "$BUILD_WORKSPACE/cache" ]]
 [[ "$GOTMPDIR" == "$BUILD_WORKSPACE/tmp" ]]
 [[ "$(umask)" == '0077' ]]
 printf '#!/bin/sh\nexit 0\n' > "$output"
 chmod +x "$output"
 if [[ "$FAIL_AT" == build ]]; then return 42; fi
}
build
# Copy mode metadata to a listing that survives the exit trap.
ls -ld "$BUILD_WORKSPACE" "$BUILD_WORKSPACE/warden" "$BUILD_WORKSPACE/cache" "$BUILD_WORKSPACE/tmp" > "$REPO_ROOT/modes"
[[ ! -e "$REPO_ROOT/deploy/warden" ]]
if [[ "$FAIL_AT" == install ]]; then exit 43; fi
`
			cmd := exec.Command("bash", "-c", body, script)
			cmd.Env = append(os.Environ(), "FAIL_AT="+failAt)
			out, err := cmd.CombinedOutput()
			if (err == nil) != (failAt == "none") {
				t.Fatalf("%v: %s", err, out)
			}
			if failAt != "none" {
				if e, ok := err.(*exec.ExitError); !ok || (failAt == "build" && e.ExitCode() != 42) || (failAt == "install" && e.ExitCode() != 43) {
					t.Fatalf("wrong failure: %v: %s", err, out)
				}
			}
			path, err := os.ReadFile(filepath.Join(root, "workspace-path"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(string(path)); !os.IsNotExist(err) {
				t.Fatalf("workspace survived %s: %v", failAt, err)
			}
			if failAt != "build" {
				modes, err := os.ReadFile(filepath.Join(root, "modes"))
				if err != nil {
					t.Fatal(err)
				}
				for _, line := range strings.Split(strings.TrimSpace(string(modes)), "\n") {
					fields := strings.Fields(line)
					if len(fields) == 0 || len(fields[0]) < 10 || fields[0][4:10] != "------" {
						t.Fatalf("non-private artifact: %s", line)
					}
				}
			}
		})
	}
}

func TestInstallerVerificationUsesTeamClient(t *testing.T) {
	source, err := os.ReadFile("../../deploy/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	functions := strings.TrimSuffix(string(source), "main \"$@\"\n")
	script := filepath.Join(t.TempDir(), "functions.sh")
	if err := os.WriteFile(script, []byte(functions), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `source "$1"; OPMENU_USER=svchelper; TEAM_FROM_IP=203.0.113.10; ask() { ans=y; }; step_verify_access`, "test", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	for _, want := range []string{"team's SSH client", "TEAM_FROM_IP=203.0.113.10", "svchelper@<this-host-address> status"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("missing %q: %s", want, out)
		}
	}
	if strings.Contains(string(out), "127.0.0.1") {
		t.Fatal("loopback verification remains")
	}
}
