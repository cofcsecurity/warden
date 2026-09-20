package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"warden/internal/sentinel"
)

// buildRegistrations wires sentinel-check's real checks together: the
// authorized_keys entry, its own systemd timer, and its own cron entry.
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

	servicePath := filepath.Join(systemdUnitDir, unitName+".service")
	timerPath := filepath.Join(systemdUnitDir, unitName+".timer")
	enabledLinkPath := filepath.Join(systemdTimersWantsDir, unitName+".timer")

	return []sentinel.Registration{
		{
			Name:     "authorized_keys",
			Check:    func() (bool, error) { return checkAuthorizedKeysFile(authorizedKeysPath, line) },
			Recreate: func() error { return recreateAuthorizedKeysFile(authorizedKeysPath, line) },
		},
		{
			Name:  "systemd-timer",
			Check: func() (bool, error) { return checkSystemdTimerFiles(servicePath, timerPath, enabledLinkPath) },
			Recreate: func() error {
				if err := writeSystemdTimerFiles(servicePath, timerPath, sentinelServiceContent(unitName, path), sentinelTimerContent(unitName)); err != nil {
					return err
				}
				if err := runSystemctl("daemon-reload"); err != nil {
					return err
				}
				return runSystemctl("enable", "--now", unitName+".timer")
			},
		},
		{
			Name:  "cron-entry",
			Check: func() (bool, error) { return checkCronEntryFile(cronSpoolPath, cronMarker(unitName)) },
			Recreate: func() error {
				return recreateCronEntryFile(cronSpoolPath, cronMarker(unitName), cronLine(unitName, path))
			},
		},
	}, nil
}

func checkAuthorizedKeysFile(path, expectedLine string) (bool, error) {
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("sentinel: read %s: %w", path, err)
	}
	return strings.Contains(string(content), expectedLine), nil
}

// recreateAuthorizedKeysFile appends, never rewrites: any other key already
// in the file is left exactly as it was.
func recreateAuthorizedKeysFile(path, line string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("sentinel: mkdir for %s: %w", path, err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("sentinel: open %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		return fmt.Errorf("sentinel: append to %s: %w", path, err)
	}
	return nil
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

// runSystemctl is the one place sentinel-check shells out: activating a
// timer (the symlink in timers.target.wants plus telling the running
// daemon about it) isn't something writing files alone can do. This is
// distinct from using systemctl to check status, which the design
// deliberately avoids trusting.
func runSystemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sentinel: systemctl %s: %w: %s", strings.Join(args, " "), err, out)
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
