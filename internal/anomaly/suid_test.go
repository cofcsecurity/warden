package anomaly

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckSUIDFirstRunBootstrapsSilently(t *testing.T) {
	baseDir := t.TempDir()
	binDir := t.TempDir()
	writeSetuidFile(t, filepath.Join(binDir, "sudo"))

	findings, err := CheckSUID(baseDir, []string{binDir})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings on first run, got %+v", findings)
	}
}

func TestCheckSUIDFlagsNewSetuidBinary(t *testing.T) {
	baseDir := t.TempDir()
	binDir := t.TempDir()
	writeSetuidFile(t, filepath.Join(binDir, "sudo"))

	if _, err := CheckSUID(baseDir, []string{binDir}); err != nil {
		t.Fatal(err)
	}

	newBinary := filepath.Join(binDir, "backdoor")
	writeSetuidFile(t, newBinary)

	findings, err := CheckSUID(baseDir, []string{binDir})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly one finding, got %+v", findings)
	}
	if findings[0].Detail != newBinary {
		t.Fatalf("expected the finding to point at %s, got %+v", newBinary, findings[0])
	}
}

func TestCheckSUIDIgnoresNonSetuidFiles(t *testing.T) {
	baseDir := t.TempDir()
	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, "ls"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := CheckSUID(baseDir, []string{binDir}); err != nil {
		t.Fatal(err)
	}

	findings, err := CheckSUID(baseDir, []string{binDir})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for a plain 0755 file, got %+v", findings)
	}
}

// writeSetuidFile writes an executable file with the setuid bit set. On
// Linux (the real CI runner and deployment target) a non-root user can
// set this on a file they own; some sandboxed/non-Linux dev environments
// silently drop it on chmod, so this skips rather than fails when that
// happens here, instead of asserting behavior the actual host doesn't
// support at all.
func writeSetuidFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o4755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetuid == 0 {
		t.Skip("this environment doesn't let chmod set the setuid bit (common outside Linux) — skipping")
	}
}
