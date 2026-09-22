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
	content := sudoersDropInContent("svchelper", "/usr/local/sbin/svchelper")

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

func TestSystemdTimerFilesRequireAllThreeArtifacts(t *testing.T) {
	dir := t.TempDir()
	servicePath := filepath.Join(dir, "svchelper-sentinel.service")
	timerPath := filepath.Join(dir, "svchelper-sentinel.timer")
	enabledLinkPath := filepath.Join(dir, "wants", "svchelper-sentinel.timer")

	present, err := checkSystemdTimerFiles(servicePath, timerPath, enabledLinkPath)
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatalf("expected absent before any files exist")
	}

	if err := writeSystemdTimerFiles(servicePath, timerPath, "service content", "timer content"); err != nil {
		t.Fatal(err)
	}

	// Service and timer exist now, but not the enabled symlink yet.
	present, err = checkSystemdTimerFiles(servicePath, timerPath, enabledLinkPath)
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatalf("expected absent without the enabled symlink")
	}

	if err := os.MkdirAll(filepath.Dir(enabledLinkPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(timerPath, enabledLinkPath); err != nil {
		t.Fatal(err)
	}

	present, err = checkSystemdTimerFiles(servicePath, timerPath, enabledLinkPath)
	if err != nil {
		t.Fatal(err)
	}
	if !present {
		t.Fatalf("expected present once service, timer, and symlink all exist")
	}
}

func TestCronEntryFileCheckAndRecreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crontab")
	marker := "# svchelper-sentinel"
	newLine := "*/10 * * * * /usr/local/sbin/svchelper sentinel-check " + marker

	present, err := checkCronEntryFile(path, marker)
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatalf("expected absent before recreate")
	}

	if err := recreateCronEntryFile(path, marker, newLine); err != nil {
		t.Fatal(err)
	}

	present, err = checkCronEntryFile(path, marker)
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

// TestBuildRegistrationsCoversEveryTimer is the regression guard for the
// gap this file used to have: only sentinel's own timer (and replicate's)
// were registered, so watch, both snapshot tiers, and scan could each be
// disabled and deleted once with nothing ever noticing or rebuilding them.
func TestBuildRegistrationsCoversEveryTimer(t *testing.T) {
	oldPubKey, oldFromIP, oldTargets := buildTeamPubKey, buildTeamFromIP, buildReplicateTargets
	defer func() {
		buildTeamPubKey, buildTeamFromIP, buildReplicateTargets = oldPubKey, oldFromIP, oldTargets
	}()
	buildTeamPubKey, buildTeamFromIP = "ssh-ed25519 AAAA team@ccdc", "203.0.113.10"
	buildReplicateTargets = ""

	regs, err := buildRegistrations()
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, r := range regs {
		names[r.Name] = true
	}

	for _, want := range []string{
		"authorized_keys", "sudoers", "systemd-timer", "cron-entry", "binary-backup",
		"watch-timer", "snapshot-config-timer", "snapshot-data-timer", "scan-timer",
	} {
		if !names[want] {
			t.Errorf("no %q registration; sentinel-check would never notice it being disabled", want)
		}
	}
	if names["replicate-timer"] {
		t.Error("replicate-timer registered on a build with no replication targets configured")
	}

	buildReplicateTargets = "file:///tmp/peer"
	regs, err = buildRegistrations()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range regs {
		if r.Name == "replicate-timer" {
			found = true
		}
	}
	if !found {
		t.Error("expected a replicate-timer registration once targets are configured")
	}
}

// TestTimerRegistrationChecksAllThreeFiles pins the contract every timer
// registration relies on: a .timer file with no symlink in
// timers.target.wants never actually fires, so "present" has to mean all
// three files, not just the unit ones.
func TestTimerRegistrationChecksAllThreeFiles(t *testing.T) {
	dir := t.TempDir()
	service := filepath.Join(dir, "x.service")
	timer := filepath.Join(dir, "x.timer")
	link := filepath.Join(dir, "wants", "x.timer")

	ok, err := checkSystemdTimerFiles(service, timer, link)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected absent before anything is written")
	}

	if err := writeSystemdTimerFiles(service, timer, "svc", "tmr"); err != nil {
		t.Fatal(err)
	}
	ok, err = checkSystemdTimerFiles(service, timer, link)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("a timer with no timers.target.wants symlink must not count as present")
	}

	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(timer, link); err != nil {
		t.Fatal(err)
	}
	ok, err = checkSystemdTimerFiles(service, timer, link)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected present once all three exist")
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
