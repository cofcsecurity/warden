package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"warden/internal/audit"
	"warden/internal/manifest"
	"warden/internal/watch"
)

func watchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "watch",
		Short: "Run one integrity check pass over the watched paths",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWatch()
		},
	}
}

// reloadServiceFor builds watch's reload hook: after a path is restored,
// tell the service that owns it to re-read its config.
//
// Without this the restore is cosmetic for anything long-running. sshd,
// nginx, postgres and the rest parse their config once at startup, so a
// known-good file written underneath a running process changes nothing
// until it re-reads — the attacker's settings stay live, and the box
// looks repaired while still being compromised. It matters most for the
// one file the team's own access depends on: restoring sshd_config after
// someone locks the team out only helps if sshd actually picks it up.
//
// reload-or-restart, not restart: a reload is enough wherever the unit
// defines one and doesn't interrupt anything, including established SSH
// sessions. Each unit is reloaded at most once per pass even when
// several of its config files were restored together, and a unit that
// isn't installed here is skipped rather than failed (serviceForPath
// already resolves among the distro-dependent names).
func reloadServiceFor(log *audit.Logger) watch.Reload {
	done := map[string]bool{}

	return func(path string) error {
		unit, ok := serviceForPath(path)
		if !ok || done[unit] {
			return nil
		}
		done[unit] = true

		err := runSystemctl("reload-or-restart", unit)
		_ = log.Log("watch", "service-reloaded", map[string]any{
			"path":    path,
			"unit":    unit,
			"ok":      err == nil,
			"outcome": systemctlOutcome(err),
		})
		if err != nil {
			return fmt.Errorf("watch: reload %s after restoring %s: %w", unit, path, err)
		}
		return nil
	}
}

func systemctlOutcome(err error) string {
	if err == nil {
		return "reloaded"
	}
	return err.Error()
}

func runWatch() error {
	p, err := loadPaths()
	if err != nil {
		return err
	}

	log, err := audit.New(p.auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()
	recovery := newBackupRecovery(p, log)
	defer recovery.Close()
	if err := recovery.ensureManifest(tierConfig); err != nil {
		return err
	}
	st, err := recovery.store()
	if err != nil {
		return err
	}

	armed, err := isArmed(p)
	if err != nil {
		return err
	}

	q, err := loadReloadQueue(p)
	if err != nil {
		return err
	}
	w := watch.New(p.configManifestPath, watchedPaths, classifyPath, armed, st, log, q.add)
	m, err := manifest.New(p.configManifestPath)
	if err != nil {
		return err
	}
	w.Baseline, err = accountBaseline(p, m, st)
	if err != nil {
		return err
	}
	res, err := w.Check()
	if err != nil {
		return err
	}

	if armed {
		res.ReloadErrors = append(res.ReloadErrors, q.flush()...)
	}
	now := time.Now()
	for _, change := range res.FlaggedChanges {
		if err := reactToGuardedChange(p, change, log, now); err != nil {
			// A failed reaction (e.g. iptables not present) must not stop
			// the rest of the check — the flag itself already happened
			// and is the load-bearing part; the ban/alert is on top of it.
			fmt.Fprintf(os.Stderr, "warning: react to %s: %v\n", change.Path, err)
		}
	}

	// A reload that failed means the file on disk is known-good but the
	// running service isn't using it — worth saying out loud, since
	// every other signal now reports this path as repaired.
	for _, reloadErr := range res.ReloadErrors {
		fmt.Fprintf(os.Stderr, "warning: %v (file restored, running service may still have the old config)\n", reloadErr)
	}

	if err := log.Log("watch", "pass", map[string]any{
		"armed":         armed,
		"auto_restored": len(res.AutoRestored),
		"suppressed":    len(res.Suppressed),
		"flagged":       len(res.Flagged),
		"reload_errors": len(res.ReloadErrors),
	}); err != nil {
		return err
	}

	fmt.Printf("armed: %t, auto-restored: %d, suppressed: %d, flagged: %d\n", armed, len(res.AutoRestored), len(res.Suppressed), len(res.Flagged))
	if !armed && len(res.Suppressed) > 0 {
		fmt.Println("note: disarmed — the paths above were left as-is. run 'warden arm' once hardening is done.")
	}
	return nil
}
