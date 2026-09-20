package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoveCronEntryFilePreservesOtherJobs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crontab")
	marker := "# svchelper-sentinel"
	ownLine := "*/10 * * * * /usr/local/sbin/svchelper sentinel-check " + marker
	otherJob := "0 2 * * * /usr/local/bin/backup.sh"

	initial := strings.Join([]string{otherJob, ownLine}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := removeCronEntryFile(path, marker); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(got)

	if !strings.Contains(content, otherJob) {
		t.Errorf("must preserve unrelated jobs, got:\n%s", content)
	}
	if strings.Contains(content, marker) {
		t.Errorf("must remove the marked line, got:\n%s", content)
	}
}

func TestRemoveCronEntryFileDeletesFileWhenEmptied(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crontab")
	marker := "# svchelper-sentinel"
	ownLine := "*/10 * * * * /usr/local/sbin/svchelper sentinel-check " + marker

	if err := os.WriteFile(path, []byte(ownLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := removeCronEntryFile(path, marker); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected %s removed once it held nothing else, got err=%v", path, err)
	}
}

func TestRemoveCronEntryFileMissingFileIsNoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crontab")
	if err := removeCronEntryFile(path, "# marker"); err != nil {
		t.Fatalf("missing file should be a no-op, got: %v", err)
	}
}
