package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"warden/internal/audit"
	"warden/internal/manifest"
	"warden/internal/store"
	"warden/internal/totp"
)

// acceptCmd is the deliberate, auth-backed way to tell Warden "this
// specific change to this specific watched path was intentional" without
// a blanket `warden snapshot` (which re-baselines every watched path from
// current disk state, silently absorbing any other, unrelated, unnoticed
// drift along with it) and without needing to disarm/re-arm the whole box
// just to land one change.
//
// It requires a TOTP code the same way opmenu's restore/shell do, even
// though anyone running this already has a local shell (which, in
// production, only exists after passing opmenu's own TOTP check to get
// it) — a second check here means a change can't be silently laundered
// into "known good" by whatever got the shell in the first place, only by
// someone who currently holds a valid code.
func acceptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "accept <path> <totp-code>",
		Short: "Authorize a deliberate change to one watched path as the new known-good state",
		Long: `Re-baselines exactly one path in the config-tier manifest to whatever's on
disk right now, so watch stops flagging (or would stop reverting, once
armed) a change that was actually intentional. Every other watched path's
baseline is left untouched, unlike 'warden snapshot' which regenerates
all of them.

Requires the current TOTP code as proof this is an authorized change, not
just something run from whatever shell happened to be open.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAccept(args[0], args[1])
		},
	}
}

func runAccept(path, code string) error {
	ok, err := totp.Validate(buildTOTPSecret, code, time.Now(), 1)
	if err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	if !ok {
		return fmt.Errorf("accept: invalid or expired TOTP code")
	}

	watched := false
	for _, wp := range configTierPaths {
		if wp == path {
			watched = true
			break
		}
	}
	if !watched {
		return fmt.Errorf("accept: %s is not in configTierPaths — nothing to accept", path)
	}

	p, err := loadPaths()
	if err != nil {
		return err
	}

	last, err := manifest.New(p.configManifestPath)
	if err != nil {
		return err
	}

	// A single-path Generate: empty Records if the path no longer exists
	// (accepting a deletion), one Record with fresh hash/mtime otherwise.
	fresh, err := manifest.Generate([]string{path}, classifyPath, 0)
	if err != nil {
		return err
	}

	var records []manifest.Record
	for _, r := range last.Records {
		if r.Path != path {
			records = append(records, r)
		}
	}
	records = append(records, fresh.Records...) // 0 or 1 entries

	next := &manifest.Manifest{
		Generation: last.Generation + 1,
		CreatedAt:  time.Now().UTC(),
		Records:    records,
	}

	st, err := store.New(p.storeRoot)
	if err != nil {
		return err
	}
	for _, r := range fresh.Records {
		content, err := os.ReadFile(r.Path)
		if err != nil {
			return fmt.Errorf("accept: read %s: %w", r.Path, err)
		}
		if _, err := st.Put(content); err != nil {
			return fmt.Errorf("accept: store %s: %w", r.Path, err)
		}
	}

	if err := next.SaveAs(p.configManifestPath); err != nil {
		return err
	}
	if err := next.Archive(p.configManifestsDir); err != nil {
		return err
	}

	log, err := audit.New(p.auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()

	action := "accepted"
	state := "its current content"
	if len(fresh.Records) == 0 {
		action = "accepted-deletion"
		state = "its absence"
	}
	if err := log.Log("accept", action, map[string]any{
		"path":       path,
		"generation": next.Generation,
	}); err != nil {
		return err
	}

	fmt.Printf("accepted: %s is now known-good for %s (generation %d)\n", state, path, next.Generation)
	return nil
}
