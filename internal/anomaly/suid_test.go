package anomaly

import (
	"os"
	"path/filepath"
	"strings"
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

// TestCheckSUIDFlagsAnInPlaceReplacement covers trojaning a setuid
// binary that's been on the box since the first scan: same path, same
// mode, new contents — invisible to a baseline keyed on path alone.
func TestCheckSUIDFlagsAnInPlaceReplacement(t *testing.T) {
	baseDir := t.TempDir()
	binDir := t.TempDir()
	sudo := filepath.Join(binDir, "sudo")
	writeSetuidFile(t, sudo)

	if _, err := CheckSUID(baseDir, []string{binDir}); err != nil {
		t.Fatal(err) // bootstrap
	}

	if err := os.WriteFile(sudo, []byte("#!/bin/sh\nexec /bin/sh\n"), 0o4755); err != nil {
		t.Fatal(err)
	}

	findings, err := CheckSUID(baseDir, []string{binDir})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the replaced binary to be flagged, got %+v", findings)
	}
	if !strings.Contains(findings[0].Description, "replaced in place") {
		t.Errorf("unexpected description: %s", findings[0].Description)
	}

	// Unchanged on the next pass.
	findings, err = CheckSUID(baseDir, []string{binDir})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings once the new contents are the baseline, got %+v", findings)
	}
}

func TestCheckSUIDIgnoresLegacyBaselineValues(t *testing.T) {
	baseDir := t.TempDir()
	binDir := t.TempDir()
	sudo := filepath.Join(binDir, "sudo")
	writeSetuidFile(t, sudo)

	if err := os.WriteFile(filepath.Join(baseDir, "suid.json"),
		[]byte(`{"`+sudo+`":"1"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err := CheckSUID(baseDir, []string{binDir})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("a legacy path-only baseline must reseed quietly, got %+v", findings)
	}
}
