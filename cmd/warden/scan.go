package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"warden/internal/accountlock"
	"warden/internal/anomaly"
	"warden/internal/audit"
	"warden/internal/autoban"
	"warden/internal/manifest"
)

// suidScanDirs are the bounded set of common bin directories scan checks
// for new setuid/setgid binaries — not a full filesystem walk, matching
// docs/PLAN.md Phase 9's "bounded, high-signal" scope.
var suidScanDirs = []string{
	"/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/bin", "/sbin",
}

func scanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan",
		Short: "Check for tampering beyond file-content drift, and react if armed",
		Long: `Runs six bounded, high-signal checks that 'watch' doesn't already cover:
new local user/group accounts (and new domain/Active-Directory-backed
accounts, flagged separately), new setuid/setgid binaries, cron tampering
for any account (not just Warden's own entry), authorized_keys tampering
for any account, new listening TCP ports, and newly installed packages.
Not a SIEM replacement — see docs/PLAN.md Phase 9.

Always flags and logs every finding. Once armed it also responds per the
runtime config's lock and ban modes: "flag" logs what it would lock or
ban, "act" locks the responsible local account (and kills its sessions)
and bans the source IP when the evidence points at exactly one. Never
locks root, Warden's accounts, a safe_accounts entry, or an account that
is not local.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan()
		},
	}
}

func runScan() error {
	p, err := loadPaths()
	if err != nil {
		return err
	}

	findings, err := runAllAnomalyChecks(p)
	if err != nil {
		return err
	}

	armed, err := isArmed(p)
	if err != nil {
		return err
	}

	log, err := audit.New(p.auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()

	now := time.Now()
	lockedCount, bannedCount := 0, 0
	for _, f := range findings {
		locked, lockSkippedReason, err := reactToAnomalyFinding(p, f, armed, now)
		if err != nil {
			return err
		}
		if locked {
			lockedCount++
		}

		eventTime := f.EventTime
		if eventTime.IsZero() {
			eventTime = now
		}
		suspect, account, evidence, candidates := attributeChange(eventTime, now)
		autobanned := false
		wouldBan := ""
		if suspect != "" && armed && cfg.Ban == modeFlag {
			wouldBan = suspect
		}
		if suspect != "" && cfg.Ban == modeAct && armed {
			store := autoban.NewStore(p.bannedIPsPath)
			reason := fmt.Sprintf("anomaly (%s): %s (account %q)", f.Check, f.Description, account)
			if err := autoban.Add(store, autoban.IPTables{}, suspect, reason, autobanDuration, now); err != nil {
				return err
			}
			autobanned = true
		}
		if autobanned {
			bannedCount++
		}

		fields := map[string]any{
			"source":         "anomaly",
			"check":          f.Check,
			"description":    f.Description,
			"detail":         f.Detail,
			"locked_account": locked,
			"autobanned":     autobanned,
			"ip_evidence":    evidence,
		}
		if f.Culprit != "" {
			fields["culprit"] = f.Culprit
		}
		if lockSkippedReason != "" {
			fields["lock_skipped_reason"] = lockSkippedReason
		}
		if suspect != "" {
			fields["suspect_ip"] = suspect
		}
		if wouldBan != "" {
			fields["would_ban"] = wouldBan
		}
		if suspect == "" && len(candidates) > 1 {
			fields["candidate_ips"] = candidates
		}
		if err := log.Log("react", "alert", fields); err != nil {
			return err
		}
	}

	// A "pass" entry every run, clean or not, the same as watch and
	// sentinel-check log. Without it, a run with
	// zero findings wrote nothing at all, so neither the audit log nor
	// `status` could tell "scan ran and the box is clean" apart from
	// "scan's timer has been dead for three days": both look like
	// silence.
	if err := log.Log("scan", "pass", map[string]any{
		"armed":    armed,
		"findings": len(findings),
		"locked":   lockedCount,
		"banned":   bannedCount,
	}); err != nil {
		return err
	}

	if len(findings) == 0 {
		fmt.Println("scan: nothing new to report.")
		return nil
	}
	fmt.Printf("scan: %d finding(s), %d account(s) locked, %d IP(s) banned. See 'warden alerts' for detail.\n", len(findings), lockedCount, bannedCount)
	return nil
}

// reactToAnomalyFinding applies the account-lock half of scan's reaction,
// only once armed, only in lock mode "act", and only when canLockAccount
// clears the finding's culprit (force is never automatic). In "flag" mode
// it reports what it would have locked and changes nothing.
func reactToAnomalyFinding(p paths, f anomaly.Finding, armed bool, now time.Time) (locked bool, skippedReason string, err error) {
	if f.Culprit == "" {
		return false, "", nil
	}
	if !armed || cfg.Lock == modeOff {
		return false, "", nil
	}

	ok, reason, err := canLockAccount(f.Culprit, false)
	if err != nil {
		return false, "", err
	}
	if !ok {
		return false, reason, nil
	}
	if cfg.Lock == modeFlag {
		return false, "flag mode: would lock " + f.Culprit, nil
	}

	sys := accountlock.OSAccounts{NologinShell: nologinShellPath()}
	store := accountlock.NewStore(p.accountLocksPath)
	if err := accountlock.Add(store, sys, f.Culprit, f.Description, accountLockDuration, now); err != nil {
		return false, "", err
	}
	_ = sys.KillSessions(f.Culprit)
	return true, "", nil
}

// runAllAnomalyChecks wires cmd/warden's real, box-specific paths into
// each internal/anomaly check.
func runAllAnomalyChecks(p paths) ([]anomaly.Finding, error) {
	var all []anomaly.Finding

	m, err := manifest.New(p.configManifestPath)
	if err != nil {
		return nil, err
	}
	accountFindings, err := anomaly.CheckAccountsWithGroupApprovals(p.anomalyDir, "/etc/passwd", "/etc/group", m.ApprovedGroups)
	if err != nil {
		return nil, fmt.Errorf("scan: accounts check: %w", err)
	}
	all = append(all, accountFindings...)

	suidFindings, err := anomaly.CheckSUID(p.anomalyDir, suidScanDirs)
	if err != nil {
		return nil, fmt.Errorf("scan: suid check: %w", err)
	}
	all = append(all, suidFindings...)

	cronFindings, err := checkCronForThisBox(p)
	if err != nil {
		return nil, fmt.Errorf("scan: cron check: %w", err)
	}
	all = append(all, cronFindings...)

	akFindings, err := checkAuthorizedKeysForThisBox(p)
	if err != nil {
		return nil, fmt.Errorf("scan: authorized_keys check: %w", err)
	}
	all = append(all, akFindings...)

	portFindings, err := anomaly.CheckListeningPorts(p.anomalyDir, "/proc")
	if err != nil {
		return nil, fmt.Errorf("scan: listening-ports check: %w", err)
	}
	all = append(all, portFindings...)

	pkgFindings, err := anomaly.CheckPackages(p.anomalyDir)
	if err != nil {
		return nil, fmt.Errorf("scan: packages check: %w", err)
	}
	all = append(all, pkgFindings...)

	return all, nil
}

// checkCronForThisBox watches root's own crontab (with Warden's own
// sentinel line stripped first, so its legitimate churn never
// false-positives), /etc/cron.d, and the per-user crontab spool
// directory (filename = account name in that layout).
func checkCronForThisBox(p paths) ([]anomaly.Finding, error) {
	rootCrontabPath := cronSpoolPath()
	spoolDir := filepath.Dir(rootCrontabPath)

	var marker string
	if unitName, err := sentinelUnitName(); err == nil {
		marker = cronMarker(unitName)
	}

	own := ownFiles()
	normalize := func(path string, content []byte) []byte {
		if own(path) {
			return nil
		}
		if path != rootCrontabPath || marker == "" {
			return content
		}
		var kept []string
		for _, line := range strings.Split(string(content), "\n") {
			if strings.Contains(line, marker) {
				continue
			}
			kept = append(kept, line)
		}
		return []byte(strings.Join(kept, "\n"))
	}

	sources := []anomaly.CronSource{
		{Path: "/etc/crontab"},
		{Path: "/etc/cron.d", IsDir: true},
		{Path: spoolDir, IsDir: true, CulpritIsFilename: true},
	}
	return anomaly.CheckCron(p.anomalyDir, sources, normalize)
}

// checkAuthorizedKeysForThisBox watches every account's authorized_keys
// file under /home and /root, except Warden's own access accounts, whose
// keys sentinel holds.
func checkAuthorizedKeysForThisBox(p paths) ([]anomaly.Finding, error) {
	var sources []anomaly.AuthorizedKeysSource
	own := ownFiles()

	if matches, err := filepath.Glob("/home/*/.ssh/authorized_keys"); err == nil {
		for _, m := range matches {
			if own(m) {
				continue
			}
			sources = append(sources, anomaly.AuthorizedKeysSource{
				Path:    m,
				Culprit: accountFromHomeAuthorizedKeysPath(m),
			})
		}
	}
	rootAK := "/root/.ssh/authorized_keys"
	if _, err := os.Stat(rootAK); err == nil {
		sources = append(sources, anomaly.AuthorizedKeysSource{Path: rootAK, Culprit: "root"})
	}
	return anomaly.CheckAuthorizedKeys(p.anomalyDir, sources, nil)
}

// accountFromHomeAuthorizedKeysPath extracts <user> from
// /home/<user>/.ssh/authorized_keys.
func accountFromHomeAuthorizedKeysPath(path string) string {
	// path is .../<user>/.ssh/authorized_keys — walk up two directories.
	sshDir := filepath.Dir(path)
	homeDir := filepath.Dir(sshDir)
	return filepath.Base(homeDir)
}
