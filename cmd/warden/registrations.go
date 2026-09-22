package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"warden/internal/fsutil"
	"warden/internal/sentinel"
)

// buildRegistrations wires sentinel-check's real checks together: the
// authorized_keys entry (and the sudoers rule it depends on), its own
// cron entry, its hidden spare binary, and *every* timer install.sh lays
// down — watch, both snapshot tiers, scan, sentinel's own, and (when a
// replication target is configured) replicate's.
//
// Every timer has to be in here, not just sentinel's own: a timer nobody
// watches can be disabled and deleted once, and nothing ever notices or
// rebuilds it. That would silently end auto-restore and drift-flagging
// (watch), backups (snapshot), anomaly detection (scan), or off-box
// evidence survival (replicate) for the rest of the competition, with a
// box that still looks armed from the outside.
//
// Every Check reads the relevant file directly rather than shelling to
// systemctl/crontab, per docs/DESIGN.md's threat model.
func buildRegistrations() ([]sentinel.Registration, error) {
	path, err := installPath()
	if err != nil {
		return nil, err
	}
	unitName, err := sentinelUnitName()
	if err != nil {
		return nil, err
	}
	line, err := authorizedKeysLine(path)
	if err != nil {
		return nil, err
	}
	akPath, err := authorizedKeysPath()
	if err != nil {
		return nil, err
	}
	opUser, err := opmenuUser()
	if err != nil {
		return nil, err
	}
	sudoersPath := sudoersDropInPath(opUser)
	sudoersContent := sudoersDropInContent(opUser, path)
	sparePath := spareBinaryPath(path)

	regs := []sentinel.Registration{
		{
			Name:     "authorized_keys",
			Check:    func() (bool, error) { return checkAuthorizedKeysFile(akPath, line) },
			Recreate: func() error { return recreateAuthorizedKeysFile(akPath, line) },
		},
		{
			// Without this, the authorized_keys entry above is inert —
			// the forced command runs `sudo <path> opmenu`, and if the
			// sudoers rule granting that is gone, every opmenu invocation
			// just fails at the sudo step.
			Name:     "sudoers",
			Check:    func() (bool, error) { return checkSudoersFile(sudoersPath, sudoersContent) },
			Recreate: func() error { return recreateSudoersFile(sudoersPath, sudoersContent) },
		},
		timerRegistration("systemd-timer", unitName, sentinelServiceContent(unitName, path), sentinelTimerContent(unitName)),
		{
			Name:  "cron-entry",
			Check: func() (bool, error) { return checkCronEntryFile(cronSpoolPath(), cronMarker(unitName)) },
			Recreate: func() error {
				return recreateCronEntryFile(cronSpoolPath(), cronMarker(unitName), cronLine(unitName, path))
			},
		},
		{
			// watch/sentinel-check/retrieve are all *inside* this binary —
			// none of them can run to restore it if the binary file itself
			// is deleted. Keeping a hidden spare in sync means the cron
			// trigger's test/cp/chmod fallback (see cronLine) has
			// something to restore from, without depending on the Go
			// binary at all.
			Name:     "binary-backup",
			Check:    func() (bool, error) { return checkSpareBinary(path, sparePath) },
			Recreate: func() error { return recreateSpareBinary(path, sparePath) },
		},
	}

	// The remaining timers install.sh installs unconditionally. Each one
	// is what a whole capability rides on, so each one is watched the
	// same way sentinel's own timer is.
	for _, t := range []struct {
		name    string
		unit    func() (string, error)
		service func(unitName, path string) string
		timer   func(unitName string) string
	}{
		{"watch-timer", watchUnitName, watchServiceContent, watchTimerContent},
		{"snapshot-config-timer", snapshotConfigUnitName, snapshotConfigServiceContent, snapshotConfigTimerContent},
		{"snapshot-data-timer", snapshotDataUnitName, snapshotDataServiceContent, snapshotDataTimerContent},
		{"scan-timer", scanUnitName, scanServiceContent, scanTimerContent},
	} {
		name, err := t.unit()
		if err != nil {
			return nil, err
		}
		regs = append(regs, timerRegistration(t.name, name, t.service(name, path), t.timer(name)))
	}

	// replicate's timer only exists on a box built with peers configured,
	// so unlike the rest it's registered conditionally — otherwise
	// sentinel-check would "repair" a replication timer onto every box
	// that has nothing to replicate to.
	if buildReplicateTargets != "" {
		repUnitName, err := replicateUnitName()
		if err != nil {
			return nil, err
		}
		regs = append(regs, timerRegistration(
			"replicate-timer",
			repUnitName,
			replicateServiceContent(repUnitName, path),
			replicateTimerContent(repUnitName),
		))
	}

	return regs, nil
}

// timerRegistration builds the "this timer must exist and be enabled"
// registration shared by every timer on the box: the .service file, the
// .timer file, and the symlink in timers.target.wants that actually makes
// it fire. Recreate writes all three back and tells the running daemon
// about them.
func timerRegistration(name, unitName, serviceContent, timerContent string) sentinel.Registration {
	servicePath := filepath.Join(systemdUnitDir, unitName+".service")
	timerPath := filepath.Join(systemdUnitDir, unitName+".timer")
	enabledLinkPath := filepath.Join(systemdTimersWantsDir, unitName+".timer")

	return sentinel.Registration{
		Name:  name,
		Check: func() (bool, error) { return checkSystemdTimerFiles(servicePath, timerPath, enabledLinkPath) },
		Recreate: func() error {
			if err := writeSystemdTimerFiles(servicePath, timerPath, serviceContent, timerContent); err != nil {
				return err
			}
			if err := runSystemctl("daemon-reload"); err != nil {
				return err
			}
			return runSystemctl("enable", "--now", unitName+".timer")
		},
	}
}

func checkAuthorizedKeysFile(path, expectedLine string) (bool, error) {
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("sentinel: read %s: %w", path, err)
	}
	return strings.TrimSpace(string(content)) == expectedLine, nil
}

// The dedicated operator account permits only the configured restricted key.
func recreateAuthorizedKeysFile(path, line string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("sentinel: mkdir for %s: %w", path, err)
	}
	return fsutil.WriteFile(path, []byte(line+"\n"), 0o644)
}

// checkSystemdTimerFiles requires the service file, the timer file, and the
// enabled symlink to all be present — a timer file without the symlink in
// timers.target.wants would never actually fire.
func checkSystemdTimerFiles(servicePath, timerPath, enabledLinkPath string) (bool, error) {
	for _, p := range []string{servicePath, timerPath, enabledLinkPath} {
		if _, err := os.Lstat(p); err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, fmt.Errorf("sentinel: stat %s: %w", p, err)
		}
	}
	return true, nil
}

func writeSystemdTimerFiles(servicePath, timerPath, serviceContent, timerContent string) error {
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0o644); err != nil {
		return fmt.Errorf("sentinel: write %s: %w", servicePath, err)
	}
	if err := os.WriteFile(timerPath, []byte(timerContent), 0o644); err != nil {
		return fmt.Errorf("sentinel: write %s: %w", timerPath, err)
	}
	return nil
}

// runSystemctl is one of two places sentinel-check shells out (the other
// is visudo, below): activating a timer (the symlink in
// timers.target.wants plus telling the running daemon about it) isn't
// something writing files alone can do. This is distinct from using
// systemctl to check status, which the design deliberately avoids
// trusting.
func runSystemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sentinel: systemctl %s: %w: %s", strings.Join(args, " "), err, out)
	}
	return nil
}

func checkSudoersFile(path, expectedContent string) (bool, error) {
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("sentinel: read %s: %w", path, err)
	}
	return string(content) == expectedContent, nil
}

// recreateSudoersFile validates with visudo -cf before installing — a
// malformed sudoers file breaks sudo box-wide, for every account, not
// just this one. Written to a temp file and renamed into place only once
// validated, so a failed check never leaves a bad file where sudo would
// read it. 0440 matches sudoers.d's own permission requirement.
func recreateSudoersFile(path, content string) error {
	tmp := path + ".warden-tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o440); err != nil {
		return fmt.Errorf("sentinel: write %s: %w", tmp, err)
	}
	if out, err := exec.Command("visudo", "-cf", tmp).CombinedOutput(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("sentinel: generated sudoers content failed validation: %w: %s", err, out)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("sentinel: install %s: %w", path, err)
	}
	return nil
}

func checkCronEntryFile(path, marker string) (bool, error) {
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("sentinel: read %s: %w", path, err)
	}
	return strings.Contains(string(content), marker), nil
}

// recreateCronEntryFile rewrites the crontab spool file, but only to drop
// any stale copy of our own marked line and append the current one — every
// other job already in the file is preserved untouched.
func recreateCronEntryFile(path, marker, newLine string) error {
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("sentinel: read %s: %w", path, err)
	}

	var kept []string
	if len(existing) > 0 {
		for _, line := range strings.Split(strings.TrimRight(string(existing), "\n"), "\n") {
			if strings.Contains(line, marker) {
				continue
			}
			kept = append(kept, line)
		}
	}
	kept = append(kept, newLine)

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("sentinel: mkdir for %s: %w", path, err)
	}
	if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
		return fmt.Errorf("sentinel: write %s: %w", path, err)
	}
	return nil
}

// spareBinaryPath matches deploy/install.sh's SPARE_BINARY_PATH exactly —
// hidden alongside the rest of this binary's own state under
// /var/lib/<name>, not a second name to keep track of.
func spareBinaryPath(installedPath string) string {
	return "/var/lib/" + filepath.Base(installedPath) + "/.spare"
}

// checkSpareBinary compares against the currently running binary, not a
// stored hash — this only defends against the binary file being deleted,
// not a subtler tamper-and-still-runs substitution, which would need
// content-addressed verification against something outside the binary
// itself to catch.
func checkSpareBinary(installedPath, sparePath string) (bool, error) {
	want, err := os.ReadFile(installedPath)
	if err != nil {
		return false, fmt.Errorf("sentinel: read %s: %w", installedPath, err)
	}
	got, err := os.ReadFile(sparePath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("sentinel: read %s: %w", sparePath, err)
	}
	return bytes.Equal(want, got), nil
}

func recreateSpareBinary(installedPath, sparePath string) error {
	content, err := os.ReadFile(installedPath)
	if err != nil {
		return fmt.Errorf("sentinel: read %s: %w", installedPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(sparePath), 0o700); err != nil {
		return fmt.Errorf("sentinel: mkdir for %s: %w", sparePath, err)
	}
	if err := os.WriteFile(sparePath, content, 0o700); err != nil {
		return fmt.Errorf("sentinel: write %s: %w", sparePath, err)
	}
	return nil
}
