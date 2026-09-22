package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise generated access files without creating accounts or changing ownership.
func TestInstallerAccessConfiguration(t *testing.T) {
	if _, err := exec.LookPath("visudo"); err != nil {
		t.Skip("visudo unavailable")
	}
	script, err := os.ReadFile("../../deploy/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "install-functions.sh")
	if err := os.WriteFile(scriptPath, []byte(strings.TrimSuffix(string(script), "main \"$@\"\n")), 0600); err != nil {
		t.Fatal(err)
	}
	// Fail if the entry point was not removed; sourcing must never deploy.
	content, _ := os.ReadFile(scriptPath)
	if strings.Contains(string(content), "\nmain \"$@\"") {
		t.Fatal("installer entry point remains")
	}
	body := `source "$1"
OPMENU_USER=svchelper
OPMENU_USER_HOME="$2/home"
AUTHORIZED_KEYS="$OPMENU_USER_HOME/.ssh/authorized_keys"
SUDOERS_PATH="$2/sudoers"
id() { return 1; }
chown() { :; }
useradd() { printf '%s\n' "$@" > "$TEST_USERADD_LOG"; }
step_create_opmenu_user
mkdir -p "$(dirname "$AUTHORIZED_KEYS")"
printf '%s\n' 'ssh-ed25519 OTHER unauthorized' > "$AUTHORIZED_KEYS"
step_authorize_key
step_configure_sudoers
`
	cmd := exec.Command("bash", "-c", body, "test", scriptPath, dir)
	cmd.Env = append(os.Environ(), "INSTALL_PATH=/usr/local/sbin/svchelper", "TEAM_PUBKEY=ssh-ed25519 AAAA team", "TEAM_FROM_IP=203.0.113.10", "TEST_USERADD_LOG="+filepath.Join(dir, "useradd"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("installer functions: %v: %s", err, out)
	}
	sudo, err := os.ReadFile(filepath.Join(dir, "sudoers"))
	if err != nil || string(sudo) != sudoersDropInContent("svchelper", "/usr/local/sbin/svchelper") {
		t.Fatalf("sudo rules differ: %q, %v", sudo, err)
	}
	keyPath := filepath.Join(dir, "home/.ssh/authorized_keys")
	key, err := os.ReadFile(keyPath)
	want := "command=\"sudo /usr/local/sbin/svchelper opmenu\",from=\"203.0.113.10\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-user-rc,no-pty ssh-ed25519 AAAA team\n"
	if err != nil || string(key) != want {
		t.Fatalf("unexpected key policy: %q, %v", key, err)
	}
	for path, mode := range map[string]os.FileMode{keyPath: 0644, filepath.Dir(keyPath): 0755, filepath.Join(dir, "home"): 0755, filepath.Join(dir, "sudoers"): 0440} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Fatalf("%s: got %o, want %o", path, info.Mode().Perm(), mode)
		}
	}
	args, err := os.ReadFile(filepath.Join(dir, "useradd"))
	if err != nil || !strings.Contains(string(args), "-s\n/bin/sh\n") {
		t.Fatalf("wrong login shell: %q, %v", args, err)
	}
}
