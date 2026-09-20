package main

import (
	"os"
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

func TestAuthorizedKeysFilePreservesOtherKeys(t *testing.T) {
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
	if !strings.Contains(string(got), "someone-else@laptop") {
		t.Errorf("recreate must not disturb existing keys, got:\n%s", got)
	}
	if !strings.Contains(string(got), line) {
		t.Errorf("expected our line to be appended, got:\n%s", got)
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
