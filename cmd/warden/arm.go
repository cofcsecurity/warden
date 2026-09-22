package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"warden/internal/audit"
	"warden/internal/manifest"
)

// armCmd and disarmCmd gate watch's auto-restore behind an explicit,
// human-triggered switch. The box comes up disarmed (no marker file) right
// after install.sh, since that's exactly the window a team spends hardening
// the same config files watch would otherwise be reverting out from under
// them every few minutes. Arm once hardening is actually done; disarm again
// before any planned maintenance window that touches a watched file.
func armCmd() *cobra.Command {
	var assumeYes, strict bool

	cmd := &cobra.Command{
		Use:   "arm",
		Short: "Review what's changed, lock in the current state, and turn on auto-restore",
		Long: `Lists every watched path that has changed since the last baseline, then
takes a fresh config-tier snapshot of what's on disk right now and turns
on watch's auto-restore for future drift.

The review step is the point. Everything between installing and arming
happens on an unprotected box: the changes listed are usually the team's
own hardening, but that is exactly the window in which someone else's
edit would also land, and arming makes whatever is there now the
enforced "known good" — a backdoored sshd_config included. Read the list
before confirming it.

Both orders work. Harden then install then arm leaves the shortest
unprotected window and normally lists no changes here, since the
install-time snapshot is already of the hardened box. Install then
harden then arm is the flow docs/DEPLOYMENT.md walks through, and gets
you 'detect' and 'scan' output to aim the hardening with; the changes
this lists are that hardening. What the review is for is the same
either way: you are about to bless whatever is on disk.

Run this once, after hardening is done. Before that point watch still
runs and still flags anything sensitive, it just won't overwrite a
SafeAutoRestore path out from under someone still editing it.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strict {
				p, err := loadPaths()
				if err != nil {
					return err
				}
				report := validateProfile(p)
				if len(report.Issues) > 0 {
					return fmt.Errorf("pre-arm validation: %v", report.Issues)
				}
			}
			return runArm(assumeYes)
		},
	}
	cmd.Flags().BoolVar(&strict, "strict", false, "Require profile validation to pass before arming")
	cmd.Flags().BoolVarP(&assumeYes, "yes", "y", false, "acknowledge the listed changes without being prompted")
	return cmd
}

func disarmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disarm",
		Short: "Turn off auto-restore (e.g. ahead of a planned maintenance window)",
		Long: `Turns off watch's auto-restore without touching the existing snapshot
lineage. Confirm-first paths (passwd, shadow, sudoers, sshd_config, ...)
keep getting flagged either way — disarm only affects whether a drifted
SafeAutoRestore path gets overwritten.

Run 'warden arm' again once the maintenance window is over, so it takes
a fresh snapshot of the post-maintenance state before re-enabling.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDisarm()
		},
	}
}

func runArm(assumeYes bool) error {
	p, err := loadPaths()
	if err != nil {
		return err
	}

	log, err := audit.New(p.auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()

	// What has moved since the last baseline — normally the install-time
	// snapshot, or the pre-maintenance one when re-arming after a
	// disarm. This runs before anything is written, so the operator sees
	// the old state's diff rather than a snapshot that has already
	// absorbed it.
	review, err := reviewSinceBaseline(p.configManifestPath, watchedPaths, classifyPath)
	if err != nil {
		return err
	}

	printArmConfig(os.Stdout, p)
	printArmReview(os.Stdout, review, time.Now())
	if len(review.Changes) > 0 {
		if err := log.Log("arm", "pre-arm-review", review.auditFields()); err != nil {
			return err
		}
		if !assumeYes {
			if err := confirmArm(os.Stdin, len(review.Changes)); err != nil {
				return err
			}
		}
	}

	// Lock in exactly what's on disk right now as the enforced baseline,
	// not whatever snapshot's own timer last happened to catch.
	if err := runSnapshot(tierConfig); err != nil {
		return fmt.Errorf("arm: snapshot before arming: %w", err)
	}

	armedAt := time.Now().UTC().Format(time.RFC3339)
	if err := os.WriteFile(p.armedMarkerPath, []byte(armedAt+"\n"), 0o600); err != nil {
		return fmt.Errorf("arm: write marker: %w", err)
	}

	if err := log.Log("arm", "armed", map[string]any{
		"at":                armedAt,
		"changes_baselined": len(review.Changes),
		"confirm_first":     len(review.confirmFirstPaths()),
	}); err != nil {
		return err
	}

	fmt.Println("\narmed: auto-restore is now on. watch will revert future drift in SafeAutoRestore paths.")
	return nil
}

// printArmConfig summarizes how this box is set up, immediately before
// the operator decides to enforce it.
//
// Arming is the moment every one of these settings starts mattering, and
// it's the last point at which changing one is cheap — several are baked
// in at build time, so "wrong" means rebuild and redeploy rather than
// edit a file. They're printed here rather than left to `debug-config`
// (a build-machine tool) because the failure mode is silent: a box armed
// with no replication peers, no second factor, or an empty data tier
// behaves exactly like a correctly configured one right up until the
// moment that setting is what you needed.
func printArmConfig(w io.Writer, p paths) {
	fmt.Fprintln(w, "==> This box's configuration")

	protectedConfig, protectedData, confirmFirst := protectedCounts()
	fmt.Fprintf(w, "  watched here:       %d config-tier path(s) present, %d of them confirm-first\n", protectedConfig, confirmFirst)
	if protectedData == 0 {
		fmt.Fprintln(w, "  data tier:          nothing configured — no service data is being backed up")
	} else {
		fmt.Fprintf(w, "  data tier:          %d path(s) present\n", protectedData)
	}

	fmt.Fprintf(w, "  access from:        %s\n", orNotSet(buildTeamFromIP))
	fmt.Fprintf(w, "  second factor:      %s\n", secondFactorSummary(p))

	targets := parseReplicateTargets(buildReplicateTargets)
	if len(targets) == 0 {
		fmt.Fprintln(w, "  replication:        none — backups, the audit log and heartbeats stay on this box only")
	} else {
		fmt.Fprintf(w, "  replication:        %d peer(s)\n", len(targets))
		for _, t := range targets {
			fmt.Fprintf(w, "                      %s\n", t.url)
		}
	}

	fmt.Fprintf(w, "  auto-ban IPs:       %s\n", enabledSummary(buildAutobanEnabled != ""))
	fmt.Fprintf(w, "  auto-lock accounts: %s\n", enabledSummary(buildAutolockEnabled != ""))
	if buildAutolockEnabled != "" {
		fmt.Fprintf(w, "  never locked:       root, %s%s\n", opmenuUserOrUnknown(), safeAccountsSuffix())
	}
	fmt.Fprintln(w)
}

// protectedCounts reports what's actually present on this box, not what
// the shipped lists name — a path that doesn't exist here protects
// nothing, and counting it would overstate the coverage being armed.
func protectedCounts() (config, data, confirmFirst int) {
	for _, pp := range currentlyProtected() {
		switch pp.Tier {
		case "config":
			config++
			if pp.Class == "confirm-first" {
				confirmFirst++
			}
		case "data":
			data++
		}
	}
	return config, data, confirmFirst
}

func secondFactorSummary(p paths) string {
	totp := buildTOTPSecret != ""
	_, err := os.Stat(p.staticSecretPath)
	static := err == nil

	switch {
	case totp && static:
		return "TOTP and a static secret"
	case totp:
		return "TOTP only"
	case static:
		return "static secret only (no TOTP baked into this build)"
	default:
		return "NONE — restore/shell/accept/uninstall can't be authorized at all"
	}
}

func enabledSummary(on bool) string {
	if on {
		return "on"
	}
	return "off (flag and log only)"
}

func opmenuUserOrUnknown() string {
	user, err := opmenuUser()
	if err != nil {
		return "the opmenu account"
	}
	return user
}

func safeAccountsSuffix() string {
	if buildSafeAccounts == "" {
		return " (no SAFE_ACCOUNTS set — your own account can be locked)"
	}
	return ", " + buildSafeAccounts
}

// armReview is what changed between the last baseline and now, plus
// enough context to say how old that baseline is.
type armReview struct {
	Changes    []manifest.Change
	BaselineAt time.Time
	Generation int
	// NoBaseline is set when there's nothing to compare against at all
	// (no snapshot has ever been taken here). Every watched path would
	// otherwise read as "new", which is noise rather than a finding.
	NoBaseline bool
}

// reviewSinceBaseline diffs the current on-disk state of paths against
// the manifest at manifestPath, without writing anything.
func reviewSinceBaseline(manifestPath string, paths []string, classify manifest.Classify) (armReview, error) {
	last, err := manifest.New(manifestPath)
	if err != nil {
		return armReview{}, fmt.Errorf("arm: load baseline: %w", err)
	}
	if len(last.Records) == 0 {
		return armReview{NoBaseline: true}, nil
	}

	current, err := manifest.Generate(paths, classify, last.Generation)
	if err != nil {
		return armReview{}, fmt.Errorf("arm: read current state: %w", err)
	}

	changes := manifest.Diff(last, current)
	sort.Slice(changes, func(i, j int) bool {
		// Confirm-first paths first: those are the ones worth reading
		// carefully, and a long list of routine service-config edits
		// shouldn't bury them.
		ci, cj := changeIsConfirmFirst(changes[i]), changeIsConfirmFirst(changes[j])
		if ci != cj {
			return ci
		}
		return changes[i].Path < changes[j].Path
	})

	return armReview{Changes: changes, BaselineAt: last.CreatedAt, Generation: last.Generation}, nil
}

func changeIsConfirmFirst(c manifest.Change) bool {
	switch {
	case c.New != nil:
		return c.New.Class == manifest.ConfirmFirst
	case c.Old != nil:
		return c.Old.Class == manifest.ConfirmFirst
	default:
		return false
	}
}

func (r armReview) confirmFirstPaths() []string {
	var out []string
	for _, c := range r.Changes {
		if changeIsConfirmFirst(c) {
			out = append(out, c.Path)
		}
	}
	return out
}

func (r armReview) auditFields() map[string]any {
	paths := make([]string, 0, len(r.Changes))
	for _, c := range r.Changes {
		paths = append(paths, string(c.Kind)+" "+c.Path)
	}
	fields := map[string]any{
		"baseline_generation": r.Generation,
		"changes":             paths,
	}
	if cf := r.confirmFirstPaths(); len(cf) > 0 {
		fields["confirm_first"] = cf
	}
	return fields
}

// printArmReview renders the review for a human about to decide whether
// this is the state to enforce: the list, and nothing else. The class
// column and the confirm-first-first ordering carry the emphasis —
// standing commentary underneath every run is the kind of text people
// stop reading, which would cost the list itself their attention.
func printArmReview(w io.Writer, r armReview, now time.Time) {
	if r.NoBaseline {
		fmt.Fprintln(w, "==> No previous baseline to compare against — this box has never been snapshotted.")
		fmt.Fprintln(w, "    Everything on disk right now becomes the known-good state.")
		return
	}

	age := "an unknown time ago"
	if !r.BaselineAt.IsZero() {
		age = now.Sub(r.BaselineAt).Round(time.Minute).String() + " ago"
	}

	if len(r.Changes) == 0 {
		// Two very different situations produce this, and which one it
		// is depends on an ordering only the operator knows. Hardening
		// before installing is a perfectly good flow — the install-time
		// snapshot is then already the hardened baseline, and nothing
		// moving since is exactly right. Hardening *after* installing
		// and seeing nothing here is the opposite: the edits landed
		// somewhere no watched path covers, so arming would enforce a
		// baseline that misses the work.
		fmt.Fprintf(w, "==> Nothing has changed since the baseline taken %s (generation %d).\n\n", age, r.Generation)
		fmt.Fprintln(w, "    If this box was hardened BEFORE Warden was installed, that's expected —")
		fmt.Fprintln(w, "    you're arming exactly the state you installed against.")
		fmt.Fprintln(w, "    If it was hardened AFTER, it isn't: nothing you changed is in a watched")
		fmt.Fprintln(w, "    path. Run 'detect' and cover those paths before arming, or the enforced")
		fmt.Fprintln(w, "    baseline won't include the hardening at all.")
		return
	}

	fmt.Fprintf(w, "==> %d watched path(s) changed since the baseline taken %s (generation %d):\n\n", len(r.Changes), age, r.Generation)
	for _, c := range r.Changes {
		class := "auto-restore"
		if changeIsConfirmFirst(c) {
			class = "confirm-first"
		}
		fmt.Fprintf(w, "  %-9s %-13s %s\n", c.Kind, class, c.Path)
	}
}

// confirmArm requires an explicit acknowledgement of the listed changes.
//
// It asks and reads rather than testing whether stdin looks like a
// terminal first: that test can't be done accurately without an ioctl
// (a /dev/null redirect is a character device too, so the obvious check
// calls a cron job interactive), and getting it wrong here would mean
// either arming without anyone reading the list or refusing an operator
// who is sitting right there. Reading answers the question directly —
// nothing to read means nobody is there to confirm.
//
// The case that makes this matter is `ssh box "shell <code>"`, which
// runs over a no-pty channel: stdin is a pipe, the read returns nothing,
// and the operator is told to re-run with --yes rather than silently
// getting an armed box nobody reviewed.
func confirmArm(in io.Reader, count int) error {
	fmt.Printf("\n    Arm with these %d change(s) as the new known-good state? [y/N] ", count)

	answer, err := bufio.NewReader(in).ReadString('\n')
	if answer == "" && err != nil {
		fmt.Println()
		return fmt.Errorf("arm: %d change(s) listed above need acknowledging, and there's no interactive terminal here to ask — re-run as 'arm --yes' once you've read them", count)
	}
	if strings.TrimSpace(strings.ToLower(answer)) != "y" {
		return fmt.Errorf("arm: not confirmed; nothing was armed and nothing was snapshotted")
	}
	return nil
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

	fmt.Println("disarmed: auto-restore is off. confirm-first paths are still flagged. run 'warden arm' when done.")
	return nil
}

// isArmed reports whether auto-restore is currently on. Any error other
// than the marker simply not existing yet is surfaced, rather than quietly
// treated as disarmed, since a permissions problem here should be loud, not
// silently degrade watch's behavior.
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
