package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"warden/internal/fsutil"
	"warden/internal/sentinel"
)

// buildRegistrations is every invariant sentinel-check holds: the spare
// binaries and config mirror, each link of each access account's chain,
// every trigger that runs sentinel itself, and every job timer.
//
// Triggers (any one of them is enough to bring the rest back):
//   - a systemd timer, every minute
//   - a systemd path unit, the instant an access file changes
//   - root's crontab, every two minutes, restoring the binary if missing
//   - a drop-in on sshd's unit, whenever sshd (re)starts
//   - with break-glass: its own timer, and its own /etc/cron.d file
//     restoring from a second spare
//
// Every Check reads files directly rather than trusting systemctl or
// crontab output, except where only systemd can say whether a unit is
// running.
func buildRegistrations(p paths) ([]sentinel.Registration, error) {
	path, err := installPath()
	if err != nil {
		return nil, err
	}
	name, err := binaryName()
	if err != nil {
		return nil, err
	}
	sentinelUnit := name + sentinelSuffix
	accounts, err := accessAccounts()
	if err != nil {
		return nil, err
	}
	mirrorBin := mirrorBinaryPath(p, name)

	regs := []sentinel.Registration{
		fileCopyRegistration("binary-spare", path, spareBinaryPath(path)),
		fileCopyRegistration("binary-mirror", path, mirrorBin),
		configMirrorRegistration(p),
	}

	var watchedAccessFiles []string
	for i, a := range accounts {
		a := a
		keysContent, err := authorizedKeysContent(path)
		if err != nil {
			return nil, err
		}
		if i > 0 {
			// Break-glass carries only the team key.
			line, _ := teamKeyLine(path)
			keysContent = line + "\n"
		}
		sudoers := sudoersDropInContent(a.User, path, i == 0 && len(cfg.Sources) > 0)
		label := "main"
		if i > 0 {
			label = "break-glass"
		}
		regs = append(regs,
			problemRegistration(label+"-account", func() ([]string, error) { return accountProblems(a) }, func() error { return repairAccount(a) }),
			problemRegistration(label+"-keys", func() ([]string, error) { return keyFileProblems(a, keysContent), nil }, func() error { return repairKeyFile(a, keysContent) }),
			sentinel.Registration{
				Name:     label + "-sudoers",
				Check:    func() (bool, error) { return checkSudoersFile(a.Sudoers, sudoers) },
				Recreate: func() error { return recreateSudoersFile(a.Sudoers, sudoers) },
			},
			sentinel.Registration{
				Name:  label + "-sshd-dropin",
				Check: func() (bool, error) { return sshdDropInPresent(a), nil },
				Recreate: func() error {
					changed, err := ensureSSHDDropIn(a)
					if err != nil {
						return err
					}
					if changed {
						return reloadSSHD()
					}
					return nil
				},
			},
			problemRegistration(label+"-sshd-access", func() ([]string, error) { return sshdProblems(a), nil }, func() error {
				if _, err := ensureSSHDDropIn(a); err != nil {
					return err
				}
				if err := reloadSSHD(); err != nil {
					return err
				}
				if len(sshdProblems(a)) > 0 {
					// A drop-in that sorts before ours and targets our
					// account wins over ours. It concerns only our
					// account, so it is ours to remove.
					if moved := quarantineHostileDropIns(p, a); len(moved) > 0 {
						if err := reloadSSHD(); err != nil {
							return err
						}
					}
				}
				if problems := sshdProblems(a); len(problems) > 0 {
					return fmt.Errorf("still blocked: %s", strings.Join(problems, "; "))
				}
				return nil
			}),
		)
		watchedAccessFiles = append(watchedAccessFiles, a.KeysPath, filepath.Dir(a.KeysPath), a.Sudoers)
	}

	regs = append(regs,
		problemRegistration("sshd-service", func() ([]string, error) { return sshdServiceProblems(), nil }, repairSSHDService),
		problemRegistration("firewall-allow", func() ([]string, error) { return firewallProblems(), nil }, repairFirewall),
		flagRegistration("sudo", sudoProblems),
		flagRegistration("ld-preload", preloadProblems),
	)

	// Triggers.
	watchedAccessFiles = append(watchedAccessFiles, "/etc/sudoers.d", sshdConfig, sshdConfigDir, passwdPath, shadowPath)
	regs = append(regs,
		unitRegistration("sentinel-timer", sentinelUnit, map[string]string{
			sentinelUnit + ".service": oneshotServiceContent(sentinelUnit, path, "sentinel-check"),
			sentinelUnit + ".timer":   oneshotTimerContent(sentinelUnit, "30s", sentinelInterval, sentinelJitter),
		}, sentinelUnit+".timer", systemdTimersWantsDir),
		unitRegistration("sentinel-path", sentinelUnit, map[string]string{
			sentinelUnit + ".path": pathUnitContent(sentinelUnit, watchedAccessFiles),
		}, sentinelUnit+".path", systemdPathsWantsDir),
		sentinel.Registration{
			Name:  "cron-entry",
			Check: func() (bool, error) { return checkCronEntryFile(cronSpoolPath(), cronLine(sentinelUnit, path)) },
			Recreate: func() error {
				return recreateCronEntryFile(cronSpoolPath(), cronMarker(sentinelUnit), cronLine(sentinelUnit, path))
			},
		},
	)
	if unit := sshdUnit(); unit != "" {
		dropIn := filepath.Join(systemdUnitDir, unit+".service.d", name+".conf")
		content := sshdDropInContent(systemctlPath(), sentinelUnit)
		regs = append(regs, sentinel.Registration{
			Name:  "sshd-start-hook",
			Check: func() (bool, error) { return fileHas(dropIn, content), nil },
			Recreate: func() error {
				if err := writeOwnFile(dropIn, []byte(content), 0o644); err != nil {
					return err
				}
				return runSystemctl("daemon-reload")
			},
		})
	}
	if bg := cfg.BreakGlassUser; bg != "" {
		bgUnit := bg + sentinelSuffix
		cronD := "/etc/cron.d/" + bg
		cronContent := cronDContent(bgUnit, path, mirrorBin)
		regs = append(regs,
			unitRegistration("break-glass-timer", bgUnit, map[string]string{
				bgUnit + ".service": oneshotServiceContent(bgUnit, path, "sentinel-check"),
				bgUnit + ".timer":   oneshotTimerContent(bgUnit, "45s", "90s", "30"),
			}, bgUnit+".timer", systemdTimersWantsDir),
			sentinel.Registration{
				Name:     "break-glass-cron",
				Check:    func() (bool, error) { return fileHas(cronD, cronContent), nil },
				Recreate: func() error { return writeOwnFile(cronD, []byte(cronContent), 0o644) },
			},
		)
	}

	// Job timers. Each is a whole capability; any of them can be stopped
	// and deleted once, so each is held like sentinel's own.
	jobs := []struct {
		reg, suffix, sub, boot, interval, jitter string
	}{
		{"watch-timer", watchSuffix, "watch", "2min", watchInterval, watchJitter},
		{"snapshot-config-timer", snapshotConfigSuffix, "snapshot --tier config", "3min", snapshotConfigInterval, snapshotConfigJitter},
		{"snapshot-data-timer", snapshotDataSuffix, "snapshot --tier data", "10min", snapshotDataInterval, snapshotDataJitter},
		{"scan-timer", scanSuffix, "scan", "8min", scanInterval, scanJitter},
	}
	if len(cfg.Peers) > 0 {
		jobs = append(jobs, struct{ reg, suffix, sub, boot, interval, jitter string }{"replicate-timer", replicateSuffix, "replicate", "7min", replicateInterval, replicateJitter})
	}
	for _, j := range jobs {
		unit := name + j.suffix
		regs = append(regs, unitRegistration(j.reg, unit, map[string]string{
			unit + ".service": oneshotServiceContent(unit, path, j.sub),
			unit + ".timer":   oneshotTimerContent(unit, j.boot, j.interval, j.jitter),
		}, unit+".timer", systemdTimersWantsDir))
	}
	return regs, nil
}

func problemRegistration(name string, problems func() ([]string, error), repair func() error) sentinel.Registration {
	var last []string
	return sentinel.Registration{
		Name: name,
		Check: func() (bool, error) {
			p, err := problems()
			last = p
			return len(p) == 0, err
		},
		Recreate: repair,
		Problems: func() []string { return last },
	}
}

func flagRegistration(name string, problems func() []string) sentinel.Registration {
	r := problemRegistration(name, func() ([]string, error) { return problems(), nil }, nil)
	r.Recreate = nil
	return r
}

// unitRegistration holds a set of unit files at exactly the given content,
// enabled, and (where systemd can tell us) active. A masked unit is a
// symlink to /dev/null, so content comparison catches that too.
func unitRegistration(name, unitName string, files map[string]string, enable, wantsDir string) sentinel.Registration {
	link := filepath.Join(wantsDir, enable)
	target := filepath.Join(systemdUnitDir, enable)
	return sentinel.Registration{
		Name: name,
		Check: func() (bool, error) {
			for file, content := range files {
				if !fileHas(filepath.Join(systemdUnitDir, file), content) {
					return false, nil
				}
			}
			if dest, err := os.Readlink(link); err != nil || dest != target {
				return false, nil
			}
			return unitActive(enable), nil
		},
		Recreate: func() error {
			for file, content := range files {
				if err := writeOwnFile(filepath.Join(systemdUnitDir, file), []byte(content), 0o644); err != nil {
					return err
				}
			}
			if err := os.MkdirAll(wantsDir, 0o755); err != nil {
				return err
			}
			if dest, err := os.Readlink(link); err != nil || dest != target {
				_ = os.Remove(link)
				if err := os.Symlink(target, link); err != nil {
					return err
				}
			}
			if err := runSystemctl("daemon-reload"); err != nil {
				return err
			}
			return runSystemctl("restart", enable)
		},
	}
}

// unitActive asks systemd whether a timer or path unit is running. A
// stopped timer still has all its files, so files alone cannot answer
// this. Without systemctl (tests, containers without systemd) there is
// nothing to ask, and the files are the whole check.
var unitActive = func(unit string) bool {
	if !commandExists("systemctl") {
		return true
	}
	out, _ := exec.Command("systemctl", "is-active", unit).Output()
	state := strings.TrimSpace(string(out))
	return state == "active" || state == "activating"
}

func sshdDropInPresent(a accessAccount) bool {
	if !sshdReadsDropIns() {
		return true
	}
	return fileHas(a.SSHDDropIn, sshdDropInBody(a, false)) || fileHas(a.SSHDDropIn, sshdDropInBody(a, true))
}

func fileHas(path, content string) bool {
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		return false
	}
	data, err := os.ReadFile(path)
	return err == nil && string(data) == content
}

// fileCopyRegistration keeps dst a byte-identical copy of src.
func fileCopyRegistration(name, src, dst string) sentinel.Registration {
	return sentinel.Registration{
		Name:     name,
		Check:    func() (bool, error) { return checkSpareBinary(src, dst) },
		Recreate: func() error { return recreateSpareBinary(src, dst) },
	}
}

// configMirrorRegistration rewrites both config copies from the loaded
// config if either is missing or differs.
func configMirrorRegistration(p paths) sentinel.Registration {
	return sentinel.Registration{
		Name: "config-copies",
		Check: func() (bool, error) {
			if cfg.TeamKey == "" {
				return true, nil
			}
			for _, path := range []string{p.configPath(), p.configMirrorPath()} {
				data, err := os.ReadFile(path)
				if err != nil {
					return false, nil
				}
				if c, err := parseRuntimeConfig(data); err != nil || !sameConfig(c, cfg) {
					return false, nil
				}
			}
			return true, nil
		},
		Recreate: func() error { return saveRuntimeConfig(p, cfg) },
	}
}

func sameConfig(a, b runtimeConfig) bool {
	return fmt.Sprintf("%#v", a) == fmt.Sprintf("%#v", b)
}

func mirrorBinaryPath(p paths, name string) string {
	return filepath.Join(p.mirrorDir, name)
}

// runSystemctl is used only to activate units; checks read files.
func runSystemctl(args ...string) error {
	out, err := runCommand("systemctl", args...)
	if err != nil {
		return fmt.Errorf("sentinel: systemctl %s: %w: %s", strings.Join(args, " "), err, out)
	}
	return nil
}

// checkAuthorizedKeysFile reports whether path holds exactly the expected
// lines: a dedicated access account carries only our keys.
func checkAuthorizedKeysFile(path, expected string) (bool, error) {
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("sentinel: read %s: %w", path, err)
	}
	return strings.TrimSpace(string(content)) == strings.TrimSpace(expected), nil
}

func recreateAuthorizedKeysFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("sentinel: mkdir for %s: %w", path, err)
	}
	return fsutil.WriteFile(path, []byte(strings.TrimRight(content, "\n")+"\n"), 0o644)
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

// recreateSudoersFile validates with visudo -cf before installing; a
// malformed sudoers file breaks sudo box-wide, for every account.
func recreateSudoersFile(path, content string) error {
	tmp := path + ".warden-tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o440); err != nil {
		return fmt.Errorf("sentinel: write %s: %w", tmp, err)
	}
	if out, err := runCommand("visudo", "-cf", tmp); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("sentinel: generated sudoers content failed validation: %w: %s", err, out)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("sentinel: install %s: %w", path, err)
	}
	return nil
}

// checkCronEntryFile requires our exact line, so an edited schedule or
// command counts as missing.
func checkCronEntryFile(path, line string) (bool, error) {
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("sentinel: read %s: %w", path, err)
	}
	for _, l := range strings.Split(string(content), "\n") {
		if l == line {
			return true, nil
		}
	}
	return false, nil
}

// recreateCronEntryFile drops any stale copy of our marked line and
// appends the current one; every other job is preserved.
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

// spareBinaryPath is the first spare, inside the state directory.
func spareBinaryPath(installedPath string) string {
	return "/var/lib/" + filepath.Base(installedPath) + "/.spare"
}

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
	return writeOwnFile(sparePath, content, 0o700)
}

// quarantineHostileDropIns moves aside every sshd drop-in, other than
// Warden's own, with a Match block naming account a. It returns the paths
// moved.
func quarantineHostileDropIns(p paths, a accessAccount) []string {
	own := ownFiles()
	files, _ := filepath.Glob(filepath.Join(sshdConfigDir, "*.conf"))
	var moved []string
	for _, f := range files {
		if own(f) {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil || !matchNamesUser(string(data), a.User) {
			continue
		}
		if err := os.MkdirAll(p.quarantineDir, 0o700); err != nil {
			continue
		}
		dest := filepath.Join(p.quarantineDir, time.Now().UTC().Format("20060102T150405Z")+strings.ReplaceAll(f, "/", "_"))
		if err := os.WriteFile(dest, data, 0o600); err != nil {
			continue
		}
		if os.Remove(f) == nil {
			moved = append(moved, f)
		}
	}
	return moved
}

// matchNamesUser reports whether sshd config text has a Match line whose
// User criterion names user.
func matchNamesUser(text, user string) bool {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !strings.EqualFold(f[0], "Match") {
			continue
		}
		for i := 1; i+1 < len(f); i++ {
			if strings.EqualFold(f[i], "User") {
				for _, pat := range strings.Split(f[i+1], ",") {
					if ok, _ := filepath.Match(strings.TrimPrefix(pat, "!"), user); ok && !strings.HasPrefix(pat, "!") {
						return true
					}
				}
			}
		}
	}
	return false
}
