package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// installPath returns the path this binary was invoked from, whatever name
// `warden install` gave it. Every other name on the box derives from it.
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

// Unit name suffixes. None of them says what the tool is; each reads like
// an ordinary maintenance job for a service called <name>.
const (
	sentinelSuffix       = "-refresh"
	watchSuffix          = "-verify"
	snapshotConfigSuffix = "-cache"
	snapshotDataSuffix   = "-archive"
	scanSuffix           = "-audit"
	replicateSuffix      = "-sync"
)

func sentinelUnitName() (string, error)       { return unitNameSuffixed(sentinelSuffix) }
func replicateUnitName() (string, error)      { return unitNameSuffixed(replicateSuffix) }
func scanUnitName() (string, error)           { return unitNameSuffixed(scanSuffix) }
func watchUnitName() (string, error)          { return unitNameSuffixed(watchSuffix) }
func snapshotConfigUnitName() (string, error) { return unitNameSuffixed(snapshotConfigSuffix) }
func snapshotDataUnitName() (string, error)   { return unitNameSuffixed(snapshotDataSuffix) }

func unitNameSuffixed(suffix string) (string, error) {
	name, err := binaryName()
	if err != nil {
		return "", err
	}
	return name + suffix, nil
}

// oneshotServiceContent is every job's service unit. StartLimitIntervalSec=0
// matters for the path-triggered sentinel: a burst of file changes must
// never rate-limit the unit into a failed state that stops it starting.
func oneshotServiceContent(unitName, path, subcommand string) string {
	return fmt.Sprintf(`[Unit]
Description=%s
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=%s %s --quiet
TimeoutStartSec=5min
`, unitName, path, subcommand)
}

// oneshotTimerContent fires bootDelay after boot and after the timer is
// (re)started (OnActiveSec matters when a timer is recreated long after
// boot, when OnBootSec has already passed), then every interval.
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

// pathUnitContent starts unitName's service the moment any watched access
// file or directory changes, so a deleted key is back within seconds
// rather than at the next timer tick.
func pathUnitContent(unitName string, watched []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Unit]\nDescription=%s path\n\n[Path]\n", unitName)
	for _, w := range watched {
		fmt.Fprintf(&b, "PathChanged=%s\n", w)
	}
	fmt.Fprintf(&b, "Unit=%s.service\nTriggerLimitIntervalSec=0\n\n[Install]\nWantedBy=paths.target\n", unitName)
	return b.String()
}

// sshdDropInContent hooks sshd's own start: whenever sshd (re)starts,
// including a restart red runs to apply a lockout, systemd first asks for
// a sentinel pass. The leading "-" makes it fail-open and --no-block
// returns at once, so sshd's start is never delayed or blocked by it.
func sshdDropInContent(systemctl, sentinelUnit string) string {
	return fmt.Sprintf("[Service]\nExecStartPre=-%s start --no-block %s.service\n", systemctl, sentinelUnit)
}

func systemctlPath() string {
	if p, err := exec.LookPath("systemctl"); err == nil {
		return p
	}
	return "/bin/systemctl"
}

// cronMarker tags our lines so they can be found without disturbing any
// other job in the file.
func cronMarker(unitName string) string {
	return "# " + unitName
}

// cronLine runs sentinel every two minutes from root's crontab. The prefix
// restores the binary from a spare using only test/cp/chmod, since the Go
// binary cannot run to fix its own absence.
func cronLine(unitName, path string) string {
	spare := spareBinaryPath(path)
	return fmt.Sprintf(
		"*/2 * * * * test -x %s || { cp %s %s; chmod 0700 %s; }; %s sentinel-check --quiet %s",
		path, spare, path, path, path, cronMarker(unitName),
	)
}

// cronDContent is the break-glass trigger, a different cron mechanism
// (/etc/cron.d rather than root's spool) restoring from a different spare.
func cronDContent(unitName, path, mirror string) string {
	return fmt.Sprintf(
		"%s\n*/2 * * * * root test -x %s || { cp %s %s; chmod 0700 %s; }; %s sentinel-check --quiet >/dev/null 2>&1\n",
		cronMarker(unitName), path, mirror, path, path, path,
	)
}

// opmenuUser is the dedicated account holding the team key, never root, so
// PermitRootLogin no does not disable it. It reuses the binary's name, the
// way services usually have a same-named account.
func opmenuUser() (string, error) {
	return binaryName()
}

func opmenuUserHome(user string) string {
	return "/home/" + user
}

// authorizedKeysPath is the opmenu account's own authorized_keys file.
func authorizedKeysPath() (string, error) {
	user, err := opmenuUser()
	if err != nil {
		return "", err
	}
	return opmenuUserHome(user) + "/.ssh/authorized_keys", nil
}

func sudoersDropInPath(user string) string {
	return "/etc/sudoers.d/" + user
}

// sudoersDropInContent lets the access account run only opmenu (and, for
// paired sources, receive) as root. The SSH request and terminal type must
// survive sudo's environment reset.
func sudoersDropInContent(user, path string, receive bool) string {
	cmds := path + " opmenu"
	if receive {
		cmds += ", " + path + " receive --source *"
	}
	return fmt.Sprintf("Defaults:%s !requiretty\nDefaults:%s env_keep += \"SSH_ORIGINAL_COMMAND SSH_CLIENT SSH_CONNECTION TERM\"\n%s ALL=(root) NOPASSWD: %s\n", user, user, user, cmds)
}

// keyOptions are the restrictions on every team key line. A pty is
// allowed so `ssh -t` gives a usable root shell.
const keyOptions = "no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-user-rc"

// teamKeyLine is the team key's forced-command entry for an access account.
func teamKeyLine(path string) (string, error) {
	if cfg.TeamKey == "" {
		return "", fmt.Errorf("access: no team key configured (run 'warden install --key ...')")
	}
	from := ""
	if cfg.AllowFrom != "" && cfg.AllowFrom != allowAny {
		from = fmt.Sprintf(`from="%s",`, strings.ReplaceAll(cfg.AllowFrom, " ", ""))
	}
	return fmt.Sprintf(`command="sudo %s opmenu",%s%s %s`, path, from, keyOptions, strings.TrimSpace(cfg.TeamKey)), nil
}

// receiveKeyLine authorizes one paired source's backup key for uploads into
// its own directory, and nothing else.
func receiveKeyLine(path string, src sourceConfig) string {
	return fmt.Sprintf(`command="sudo %s receive --source %s",%s,no-pty %s`, path, src.Name, keyOptions, strings.TrimSpace(src.Key))
}

// authorizedKeysContent is the whole file for the main access account.
func authorizedKeysContent(path string) (string, error) {
	line, err := teamKeyLine(path)
	if err != nil {
		return "", err
	}
	lines := []string{line}
	for _, src := range cfg.Sources {
		lines = append(lines, receiveKeyLine(path, src))
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// nologinShellPath locates the shell used to disable suspect accounts.
func nologinShellPath() string {
	for _, candidate := range []string{"/usr/sbin/nologin", "/sbin/nologin"} {
		if info, err := os.Stat(candidate); err == nil && info.Mode()&0o111 != 0 {
			return candidate
		}
	}
	if path, err := exec.LookPath("nologin"); err == nil {
		return path
	}
	return "/bin/false"
}
