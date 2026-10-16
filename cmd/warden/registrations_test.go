package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthorizedKeysFileCheckAndRecreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_keys")
	line := `command="/usr/local/sbin/svchelper opmenu",from="203.0.113.10" ssh-ed25519 AAAA team@ccdc`

	present, err := checkAuthorizedKeysFile(path, line)
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatalf("expected the entry to be absent before recreate")
	}

	if err := recreateAuthorizedKeysFile(path, line); err != nil {
		t.Fatal(err)
	}

	present, err = checkAuthorizedKeysFile(path, line)
	if err != nil {
		t.Fatal(err)
	}
	if !present {
		t.Fatalf("expected the entry to be present after recreate")
	}
}

func TestAuthorizedKeysFileRemovesOtherKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_keys")
	otherKey := "ssh-ed25519 AAAAOTHER someone-else@laptop\n"
	if err := os.WriteFile(path, []byte(otherKey), 0o600); err != nil {
		t.Fatal(err)
	}

	line := `command="/usr/local/sbin/svchelper opmenu" ssh-ed25519 AAAA team@ccdc`
	if err := recreateAuthorizedKeysFile(path, line); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "someone-else@laptop") {
		t.Errorf("dedicated account must not retain other keys, got:\n%s", got)
	}
	if !strings.Contains(string(got), line) {
		t.Errorf("expected our line to be appended, got:\n%s", got)
	}
}

func TestSudoersFileCheckAndRecreate(t *testing.T) {
	if _, err := exec.LookPath("visudo"); err != nil {
		t.Skip("visudo not available on this machine")
	}

	path := filepath.Join(t.TempDir(), "svchelper")
	content := sudoersDropInContent("svchelper", "/usr/local/sbin/svchelper", true)

	present, err := checkSudoersFile(path, content)
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatalf("expected absent before recreate")
	}

	if err := recreateSudoersFile(path, content); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Errorf("expected exact content, got:\n%s", got)
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o440 {
		t.Errorf("expected mode 0440 (sudoers.d requirement), got %o", info.Mode().Perm())
	}

	present, err = checkSudoersFile(path, content)
	if err != nil {
		t.Fatal(err)
	}
	if !present {
		t.Fatalf("expected present after recreate")
	}

	// recreateSudoersFile must never leave a temp file behind.
	if _, err := os.Stat(path + ".warden-tmp"); !os.IsNotExist(err) {
		t.Errorf("expected no leftover temp file, stat returned err=%v", err)
	}
}

func TestSudoersFileRejectsInvalidContent(t *testing.T) {
	if _, err := exec.LookPath("visudo"); err != nil {
		t.Skip("visudo not available on this machine")
	}

	path := filepath.Join(t.TempDir(), "svchelper")
	if err := recreateSudoersFile(path, "this is not valid sudoers syntax {{{\n"); err == nil {
		t.Fatal("expected invalid sudoers content to be rejected by visudo, not written")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected no file written when validation fails, stat returned err=%v", err)
	}
}

func TestSpareBinaryCheckAndRecreate(t *testing.T) {
	dir := t.TempDir()
	installed := filepath.Join(dir, "svchelper")
	spare := filepath.Join(dir, ".spare")

	if err := os.WriteFile(installed, []byte("binary-content-v1"), 0o700); err != nil {
		t.Fatal(err)
	}

	present, err := checkSpareBinary(installed, spare)
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatalf("expected absent before recreate")
	}

	if err := recreateSpareBinary(installed, spare); err != nil {
		t.Fatal(err)
	}

	present, err = checkSpareBinary(installed, spare)
	if err != nil {
		t.Fatal(err)
	}
	if !present {
		t.Fatalf("expected present and matching after recreate")
	}

	// If the installed binary changes (a legitimate update), the spare is
	// now stale until sentinel-check refreshes it again.
	if err := os.WriteFile(installed, []byte("binary-content-v2"), 0o700); err != nil {
		t.Fatal(err)
	}
	present, err = checkSpareBinary(installed, spare)
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatalf("expected stale spare to be reported absent/mismatched")
	}
}

func TestSpareBinaryRestoresAfterInstalledIsDeleted(t *testing.T) {
	dir := t.TempDir()
	installed := filepath.Join(dir, "svchelper")
	spare := filepath.Join(dir, ".spare")

	if err := os.WriteFile(installed, []byte("binary-content"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := recreateSpareBinary(installed, spare); err != nil {
		t.Fatal(err)
	}

	// Simulate red team deleting the installed binary, then the shell-only
	// cron fallback restoring it from the spare (test/cp/chmod, not Go).
	if err := os.Remove(installed); err != nil {
		t.Fatal(err)
	}
	spareContent, err := os.ReadFile(spare)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installed, spareContent, 0o700); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(installed)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "binary-content" {
		t.Fatalf("expected restored binary to match the spare, got %q", got)
	}
}

func TestCronEntryFileCheckAndRecreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crontab")
	marker := "# svchelper-sentinel"
	newLine := "*/10 * * * * /usr/local/sbin/svchelper sentinel-check " + marker

	present, err := checkCronEntryFile(path, newLine)
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatalf("expected absent before recreate")
	}

	if err := recreateCronEntryFile(path, marker, newLine); err != nil {
		t.Fatal(err)
	}

	present, err = checkCronEntryFile(path, newLine)
	if err != nil {
		t.Fatal(err)
	}
	if !present {
		t.Fatalf("expected present after recreate")
	}
}

func TestCronEntryFilePreservesOtherJobsAndDedupsOwnLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crontab")
	marker := "# svchelper-sentinel"
	staleLine := "*/5 * * * * /old/path sentinel-check " + marker
	otherJob := "0 2 * * * /usr/local/bin/backup.sh"

	initial := strings.Join([]string{otherJob, staleLine}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}

	freshLine := "*/10 * * * * /usr/local/sbin/svchelper sentinel-check " + marker
	if err := recreateCronEntryFile(path, marker, freshLine); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(got)

	if !strings.Contains(content, otherJob) {
		t.Errorf("recreate must preserve unrelated jobs, got:\n%s", content)
	}
	if strings.Contains(content, "/old/path") {
		t.Errorf("expected stale copy of our own line to be dropped, got:\n%s", content)
	}
	if !strings.Contains(content, freshLine) {
		t.Errorf("expected the fresh line to be present, got:\n%s", content)
	}
	if strings.Count(content, marker) != 1 {
		t.Errorf("expected exactly one line carrying our marker, got:\n%s", content)
	}
}

// TestBuildRegistrationsCoversEveryLinkAndTrigger guards the whole set:
// a link or trigger nobody checks can be removed once and never comes back.
func TestBuildRegistrationsCoversEveryLinkAndTrigger(t *testing.T) {
	withConfig(t)
	cfg.TeamKey, cfg.AllowFrom, cfg.BreakGlassUser = testKey(t, "team"), "203.0.113.0/24", "pcimonitor"
	setPeers(t, "")

	regs, err := buildRegistrations(pathsForName("svchelper"))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, r := range regs {
		names[r.Name] = true
	}
	for _, want := range []string{
		"binary-spare", "binary-mirror", "config-copies",
		"main-account", "main-keys", "main-sudoers", "main-sshd-dropin", "main-sshd-access",
		"break-glass-account", "break-glass-keys", "break-glass-sudoers", "break-glass-sshd-dropin", "break-glass-sshd-access",
		"sshd-service", "firewall-allow", "sudo", "ld-preload",
		"sentinel-timer", "sentinel-path", "cron-entry", "break-glass-timer", "break-glass-cron",
		"watch-timer", "snapshot-config-timer", "snapshot-data-timer", "scan-timer",
	} {
		if !names[want] {
			t.Errorf("no %q registration; sentinel-check would never notice it broken", want)
		}
	}
	if names["replicate-timer"] {
		t.Error("replicate-timer registered with no peers configured")
	}

	setPeers(t, "file:///tmp/peer")
	cfg.TeamKey = testKey(t, "team")
	regs, err = buildRegistrations(pathsForName("svchelper"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range regs {
		found = found || r.Name == "replicate-timer"
	}
	if !found {
		t.Error("expected a replicate-timer registration once a peer is configured")
	}
}

// TestUnitRegistrationCatchesMaskingAndMissingLink: a masked unit is a
// symlink to /dev/null with every file "present", and a timer without its
// wants link never fires. Both must count as broken.
func TestUnitRegistrationCatchesMaskingAndMissingLink(t *testing.T) {
	dir := withUnitDir(t)
	calls := fakeCommands(t)
	reg := unitRegistration("x", "x", map[string]string{"x.service": "svc\n", "x.timer": "tmr\n"}, "x.timer", systemdTimersWantsDir)

	if ok, _ := reg.Check(); ok {
		t.Fatal("absent unit reported present")
	}
	if err := reg.Recreate(); err != nil {
		t.Fatal(err)
	}
	if ok, _ := reg.Check(); !ok {
		t.Fatal("recreated unit not reported present")
	}
	if len(*calls) == 0 || !strings.Contains(strings.Join(*calls, "\n"), "systemctl restart x.timer") {
		t.Fatalf("recreate must (re)start the unit: %v", *calls)
	}

	timer := filepath.Join(dir, "x.timer")
	os.Remove(timer)
	if err := os.Symlink("/dev/null", timer); err != nil {
		t.Fatal(err)
	}
	if ok, _ := reg.Check(); ok {
		t.Fatal("a masked timer must not count as present")
	}
	if err := reg.Recreate(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(timer); err != nil || info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("recreate must replace the mask with the real unit file")
	}

	os.Remove(filepath.Join(systemdTimersWantsDir, "x.timer"))
	if ok, _ := reg.Check(); ok {
		t.Fatal("a timer with no wants link must not count as present")
	}

	unitActive = func(string) bool { return false }
	if err := reg.Recreate(); err != nil {
		t.Fatal(err)
	}
	if ok, _ := reg.Check(); ok {
		t.Fatal("a stopped timer must not count as present")
	}
}

func TestAuthorizedKeysRejectsCommentedOrAdditionalEntries(t *testing.T) {
	line := `command="sudo /usr/local/sbin/warden opmenu" ssh-ed25519 AAAA team`
	for _, content := range []string{"# " + line, line + "\nssh-ed25519 OTHER attacker", line + " extra"} {
		path := filepath.Join(t.TempDir(), "authorized_keys")
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		ok, err := checkAuthorizedKeysFile(path, line)
		if err != nil || ok {
			t.Fatalf("accepted %q: %v, %v", content, ok, err)
		}
	}
}
