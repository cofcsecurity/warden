package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"warden/internal/audit"
	"warden/internal/fsutil"
	"warden/internal/manifest"
	"warden/internal/store"
)

// armCmd snapshots the watched files as they are now and turns on
// auto-restore. The team's configuration at arm time is the approved
// state, so arm once hardening is done and scoring is confirmed working.
func armCmd() *cobra.Command {
	var strict, assumeYes bool

	cmd := &cobra.Command{
		Use:   "arm",
		Short: "Snapshot the current state and turn on auto-restore",
		Long: `Takes a config-tier snapshot of every watched file as it is right now and
turns on auto-restore: from then on watch puts drifted files back,
reloads their service, and quarantines new files in watched drop-in
directories.

Arm after hardening, once services and scoring are confirmed working:
whatever is on disk now is what Warden will hold the box to. Files that
changed since the last snapshot are listed so you can spot anything you
did not do.

To change something protected later: disarm, change it, check it, arm.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := loadPaths()
			if err != nil {
				return err
			}
			if strict {
				report := validateProfile(p)
				if len(report.Issues) > 0 {
					return fmt.Errorf("pre-arm validation: %v", report.Issues)
				}
			}
			return armWithPaths(p, cmd.OutOrStdout())
		},
	}
	cmd.Flags().BoolVar(&strict, "strict", false, "require profile validation to pass before arming")
	cmd.Flags().BoolVarP(&assumeYes, "yes", "y", false, "accepted for compatibility; arm never prompts")
	_ = cmd.Flags().MarkHidden("yes")
	return cmd
}

func disarmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disarm",
		Short: "Turn off auto-restore (watch keeps flagging)",
		Long: `Turns off auto-restore without touching any snapshot. Watch still flags
drift; it just stops overwriting files. Run 'arm' again when done: it
re-baselines on the way.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDisarm()
		},
	}
}

// maxArmChanges caps the change list arm prints.
const maxArmChanges = 25

func armWithPaths(p paths, w io.Writer) error {
	armed, err := isArmed(p)
	if err != nil {
		return err
	}
	if armed {
		fmt.Fprintln(w, "already armed. To re-baseline: disarm, then arm.")
		return nil
	}

	log, err := audit.New(p.auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()

	review, err := reviewSinceBaseline(p.configManifestPath, watchedFiles(), classifyPath)
	if err != nil {
		return err
	}
	if err := stageArmCandidate(p, review.Candidate); err != nil {
		return err
	}
	if err := publishArmCandidate(p, review.Candidate); err != nil {
		return err
	}

	armedAt := time.Now().UTC().Format(time.RFC3339)
	if err := fsutil.WriteFile(p.armedMarkerPath, []byte(armedAt+"\n"), 0o600); err != nil {
		return fmt.Errorf("arm: write marker: %w", err)
	}
	if err := log.Log("arm", "armed", map[string]any{
		"at":      armedAt,
		"changes": review.changeStrings(),
		"files":   len(review.Candidate.Records),
	}); err != nil {
		return err
	}

	printArmReview(w, review, time.Now())
	auto, flag := 0, 0
	for _, r := range review.Candidate.Records {
		if r.Class == manifest.ConfirmFirst {
			flag++
		} else {
			auto++
		}
	}
	fmt.Fprintf(w, "armed: holding %d file(s) (%d auto-restore, %d flag-only).\n", auto+flag, auto, flag)
	if len(cfg.Peers) == 0 {
		fmt.Fprintln(w, "note: no backup peer yet; see 'pair' so losing this box does not lose its backups.")
	}
	fmt.Fprintln(w, "To change a protected file later: disarm, change it, check scoring, arm.")
	return nil
}

// armReview is what changed between the last baseline and now.
type armReview struct {
	Candidate  *manifest.Manifest
	Changes    []manifest.Change
	BaselineAt time.Time
	Generation int
	NoBaseline bool
}

// reviewSinceBaseline diffs the current on-disk state of paths against
// the manifest at manifestPath, without writing anything.
func reviewSinceBaseline(manifestPath string, paths []string, classify manifest.Classify) (armReview, error) {
	last, err := manifest.New(manifestPath)
	if err != nil {
		return armReview{}, fmt.Errorf("arm: load baseline: %w", err)
	}
	current, err := manifest.Generate(paths, classify, last.Generation)
	if err != nil {
		return armReview{}, fmt.Errorf("arm: read current state: %w", err)
	}
	if len(last.Records) == 0 {
		return armReview{NoBaseline: true, Candidate: current}, nil
	}
	changes := manifest.Diff(last, current)
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	return armReview{Candidate: current, Changes: changes, BaselineAt: last.CreatedAt, Generation: last.Generation}, nil
}

func (r armReview) changeStrings() []string {
	out := make([]string, 0, len(r.Changes))
	for _, c := range r.Changes {
		out = append(out, string(c.Kind)+" "+c.Path)
	}
	return out
}

// printArmReview shows only what changed since the last snapshot, so the
// operator can spot anything that was not theirs.
func printArmReview(w io.Writer, r armReview, now time.Time) {
	if r.NoBaseline {
		fmt.Fprintln(w, "first snapshot on this box: everything on disk now becomes the known-good state.")
		return
	}
	if len(r.Changes) == 0 {
		fmt.Fprintln(w, "nothing changed since the last snapshot.")
		return
	}
	age := "an unknown time"
	if !r.BaselineAt.IsZero() {
		age = now.Sub(r.BaselineAt).Round(time.Minute).String()
	}
	fmt.Fprintf(w, "changed since the snapshot %s ago (check these were you):\n", age)
	for i, c := range r.Changes {
		if i == maxArmChanges {
			fmt.Fprintf(w, "  ... and %d more (see 'alerts')\n", len(r.Changes)-maxArmChanges)
			break
		}
		fmt.Fprintf(w, "  %-8s %s\n", c.Kind, c.Path)
	}
}

func runDisarm() error {
	p, err := loadPaths()
	if err != nil {
		return err
	}
	if err := os.Remove(p.armedMarkerPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("disarm: remove marker: %w", err)
	}
	log, err := audit.New(p.auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()
	if err := log.Log("arm", "disarmed", nil); err != nil {
		return err
	}
	fmt.Println("disarmed: auto-restore is off; drift is still flagged. Run 'arm' when done.")
	return nil
}

// isArmed reports whether auto-restore is on. Errors other than the marker
// not existing are surfaced, never read as disarmed.
func isArmed(p paths) (bool, error) {
	_, err := os.Stat(p.armedMarkerPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check armed state: %w", err)
	}
	return true, nil
}

// stageArmCandidate stores exactly the bytes the candidate manifest hashed.
func stageArmCandidate(p paths, candidate *manifest.Manifest) error {
	st, err := store.New(p.storeRoot)
	if err != nil {
		return err
	}
	for _, record := range candidate.Records {
		content, err := manifest.Content(record)
		if err != nil {
			return err
		}
		if err := store.Verify(record.Hash, content); err != nil {
			return fmt.Errorf("arm: %s changed while arming; run arm again: %w", record.Path, err)
		}
		if _, err := st.Put(content); err != nil {
			return err
		}
	}
	return nil
}

func publishArmCandidate(p paths, candidate *manifest.Manifest) error {
	generation, err := allocateGeneration(p, tierConfig, candidate.Generation)
	if err != nil {
		return err
	}
	next := *candidate
	next.Generation = generation
	next.CreatedAt = time.Now().UTC()
	if err := next.Archive(p.configManifestsDir); err != nil {
		return err
	}
	return next.SaveAs(p.configManifestPath)
}
