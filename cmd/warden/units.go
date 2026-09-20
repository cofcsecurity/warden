package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// installPath returns the path this binary was actually invoked from,
// whatever name it was installed under (see deploy/install.sh's
// INSTALL_PATH). Deriving everything else from this, instead of a second
// baked-in name, keeps one source of truth for what this box's units and
// authorized_keys entry are called.
func installPath() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("determine own install path: %w", err)
	}
	return p, nil
}

func binaryName() (string, error) {
	p, err := installPath()
	if err != nil {
		return "", err
	}
	return filepath.Base(p), nil
}

// sentinelUnitName returns the systemd/cron name sentinel-check protects
// for itself, e.g. "svchelper-sentinel" if the binary is installed as
// /usr/local/sbin/svchelper.
func sentinelUnitName() (string, error) {
	name, err := binaryName()
	if err != nil {
		return "", err
	}
	return name + "-sentinel", nil
}

func sentinelServiceContent(unitName, path string) string {
	return fmt.Sprintf(`[Unit]
Description=%s

[Service]
Type=oneshot
ExecStart=%s sentinel-check
`, unitName, path)
}

func sentinelTimerContent(unitName string) string {
	return fmt.Sprintf(`[Unit]
Description=%s timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=%s
RandomizedDelaySec=%s
Unit=%s.service

[Install]
WantedBy=timers.target
`, unitName, sentinelInterval, sentinelJitter, unitName)
}

// cronMarker tags this registration's line in the crontab so it can be
// found and de-duplicated without disturbing anything else in the file —
// sentinel must never touch other jobs already on the box.
func cronMarker(unitName string) string {
	return "# " + unitName
}

func cronLine(unitName, path string) string {
	return fmt.Sprintf("*/10 * * * * %s sentinel-check %s", path, cronMarker(unitName))
}

// authorizedKeysLine reproduces exactly what deploy/install.sh's
// step_authorize_key appends, so sentinel can detect and restore it
// without a second definition of the format drifting from the first.
func authorizedKeysLine(path string) (string, error) {
	if buildTeamPubKey == "" || buildTeamFromIP == "" {
		return "", fmt.Errorf("sentinel: buildTeamPubKey/buildTeamFromIP not baked in at build time")
	}
	return fmt.Sprintf(
		`command="%s opmenu",from="%s",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty %s`,
		path, buildTeamFromIP, buildTeamPubKey,
	), nil
}
