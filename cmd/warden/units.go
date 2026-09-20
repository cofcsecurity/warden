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

// replicateUnitName is the systemd name for the replication timer, when
// one is configured — see registrations.go's replicate-timer registration.
func replicateUnitName() (string, error) {
	name, err := binaryName()
	if err != nil {
		return "", err
	}
	return name + "-replicate", nil
}

// oneshotServiceContent and oneshotTimerContent generate the same shape of
// unit deploy/install.sh's templates do, for the two units sentinel-check
// knows how to recreate from scratch (sentinel's own timer, and
// replicate's, when configured).
func oneshotServiceContent(unitName, path, subcommand string) string {
	return fmt.Sprintf(`[Unit]
Description=%s

[Service]
Type=oneshot
ExecStart=%s %s
`, unitName, path, subcommand)
}

func oneshotTimerContent(unitName, bootDelay, interval, jitter string) string {
	return fmt.Sprintf(`[Unit]
Description=%s timer

[Timer]
OnBootSec=%s
OnUnitActiveSec=%s
RandomizedDelaySec=%s
Unit=%s.service

[Install]
WantedBy=timers.target
`, unitName, bootDelay, interval, jitter, unitName)
}

func sentinelServiceContent(unitName, path string) string {
	return oneshotServiceContent(unitName, path, "sentinel-check")
}

func sentinelTimerContent(unitName string) string {
	return oneshotTimerContent(unitName, "2min", sentinelInterval, sentinelJitter)
}

func replicateServiceContent(unitName, path string) string {
	return oneshotServiceContent(unitName, path, "replicate")
}

func replicateTimerContent(unitName string) string {
	return oneshotTimerContent(unitName, "7min", replicateInterval, replicateJitter)
}

// cronMarker tags this registration's line in the crontab so it can be
// found and de-duplicated without disturbing anything else in the file —
// sentinel must never touch other jobs already on the box.
func cronMarker(unitName string) string {
	return "# " + unitName
}

// cronLine reproduces exactly what deploy/install.sh's step_install_cron_entry
// writes. The "test -x ... || { cp; chmod; }" prefix restores the binary
// itself from its hidden spare copy (spareBinaryPath) using only
// test/cp/chmod — never the Go binary — since sentinel-check can't run to
// fix its own absence if the binary file itself is what's missing.
func cronLine(unitName, path string) string {
	spare := spareBinaryPath(path)
	return fmt.Sprintf(
		"*/10 * * * * test -x %s || { cp %s %s; chmod 0700 %s; }; %s sentinel-check %s",
		path, spare, path, path, path, cronMarker(unitName),
	)
}

// authorizedKeysLine reproduces exactly what deploy/install.sh's
// step_authorize_key appends, so sentinel can detect and restore it
// without a second definition of the format drifting from the first. The
// forced command runs through sudo — see opmenuUser.
func authorizedKeysLine(path string) (string, error) {
	if buildTeamPubKey == "" || buildTeamFromIP == "" {
		return "", fmt.Errorf("sentinel: buildTeamPubKey/buildTeamFromIP not baked in at build time")
	}
	return fmt.Sprintf(
		`command="sudo %s opmenu",from="%s",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty %s`,
		path, buildTeamFromIP, buildTeamPubKey,
	), nil
}

// opmenuUser is the dedicated account holding the team's forced-command
// SSH entry — never root, since PermitRootLogin no (independent of
// Warden, some teams' standard practice) disables root SSH authentication
// entirely, forced-command key included. Reuses the disguised binary
// name: a same-named system account is ordinary (nginx/nginx,
// postgres/postgres, ...).
func opmenuUser() (string, error) {
	return binaryName()
}

// opmenuUserHome is where install.sh creates the account (useradd -m -d
// <this>), matching warden-backup's own convention.
func opmenuUserHome(user string) string {
	return "/home/" + user
}

func sudoersDropInPath(user string) string {
	return "/etc/sudoers.d/" + user
}

// sudoersDropInContent grants running this one binary as root, without a
// password — required since a forced-command session has no terminal.
// Nothing broader. !requiretty guards against a box-wide `Defaults
// requiretty` blocking this rule.
func sudoersDropInContent(user, path string) string {
	return fmt.Sprintf("Defaults:%s !requiretty\n%s ALL=(root) NOPASSWD: %s\n", user, user, path)
}
