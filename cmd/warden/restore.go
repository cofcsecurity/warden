package main

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"warden/internal/audit"
	"warden/internal/manifest"
	"warden/internal/restore"
	"warden/internal/store"
)

func restoreCmd() *cobra.Command {
	var snapshotID string
	var apply bool

	cmd := &cobra.Command{
		Use:   "restore <target>",
		Short: "Restore a watched path from a snapshot",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRestore(args[0], snapshotID, apply)
		},
	}
	cmd.Flags().StringVar(&snapshotID, "snapshot", "", "snapshot generation to restore from (default: latest)")
	cmd.Flags().BoolVar(&apply, "apply", false, "apply the restore instead of only showing what would change")
	return cmd
}

func runRestore(target, snapshotID string, apply bool) error {
	m, err := loadSnapshot(snapshotID)
	if err != nil {
		return err
	}

	entries, err := restore.Plan(m, target)
	if err != nil {
		return err
	}

	for _, l := range planLines(entries) {
		fmt.Println(l)
	}

	if !apply {
		fmt.Println("dry run: pass --apply to restore")
		return nil
	}

	log, err := audit.New(auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()

	lines, err := applyPlan(entries, log)
	for _, l := range lines {
		fmt.Println(l)
	}
	return err
}

// loadSnapshot loads the requested generation, or the latest live manifest
// when snapshotID is empty.
func loadSnapshot(snapshotID string) (*manifest.Manifest, error) {
	if snapshotID == "" {
		return manifest.New(manifestPath)
	}
	gen, err := strconv.Atoi(snapshotID)
	if err != nil {
		return nil, fmt.Errorf("restore: --snapshot must be a generation number: %w", err)
	}
	return manifest.LoadGeneration(manifestsDir, gen)
}

// planLines renders a restore plan the same way for both `warden restore`
// and opmenu's restore command.
func planLines(entries []restore.PlanEntry) []string {
	lines := make([]string, 0, len(entries))
	for _, e := range entries {
		status := "unchanged"
		if e.Changed {
			status = "DRIFTED"
		}
		lines = append(lines, fmt.Sprintf("%s  %s  current=%s target=%s", status, e.Path, e.CurrentHash, e.TargetHash))
	}
	return lines
}

// applyPlan applies entries and logs each step, shared by `restore --apply`
// and opmenu's restore command so both go through the identical sequence.
func applyPlan(entries []restore.PlanEntry, log *audit.Logger) ([]string, error) {
	st, err := store.New(objectsDir)
	if err != nil {
		return nil, err
	}

	r := restore.New(st, serviceForPath)
	results := r.Apply(entries)

	var lines []string
	var failed int
	for _, res := range results {
		if res.Skipped {
			continue
		}
		action := "restored"
		if res.Err != nil {
			action = "failed"
			failed++
		}
		_ = log.Log("restore", action, map[string]any{
			"path":            res.Path,
			"service_stopped": res.ServiceStopped,
			"service_started": res.ServiceStarted,
			"error":           errString(res.Err),
		})
		if res.Err != nil {
			lines = append(lines, fmt.Sprintf("FAILED  %s: %v", res.Path, res.Err))
		} else {
			lines = append(lines, fmt.Sprintf("restored  %s", res.Path))
		}
	}

	if failed > 0 {
		return lines, fmt.Errorf("restore: %d of %d paths failed", failed, len(results))
	}
	return lines, nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
