package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"warden/internal/audit"
	"warden/internal/manifest"
	"warden/internal/replicate"
)

// retrieveCmd is Push's reverse: recovering a box's own backups from a
// peer that holds a copy of them, after this box was wiped and rebuilt.
// The peer must be one of the configured peers: its pinned host key comes
// from there, the same source of truth push uses.
func retrieveCmd() *cobra.Command {
	var tierFlag string
	var generationFlag int
	var apply, allowRollback bool

	cmd := &cobra.Command{
		Use:   "retrieve [peer-url]",
		Short: "Pull this box's own backups back from a replication peer",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			peer := ""
			if len(args) > 0 {
				peer = args[0]
			}
			tier, err := parseTier(tierFlag)
			if err != nil {
				return err
			}
			return runRetrieve(peer, tier, generationFlag, apply, allowRollback)
		},
	}
	cmd.Flags().StringVar(&tierFlag, "tier", string(tierConfig), `snapshot tier to pull: "config" or "data"`)
	cmd.Flags().IntVar(&generationFlag, "generation", 0, "generation to pull (default: selected peer's latest, otherwise the local baseline or newest backup)")
	cmd.Flags().BoolVar(&allowRollback, "allow-rollback", false, "Explicitly permit adopting an older generation or an incomplete lineage check")
	cmd.Flags().BoolVar(&apply, "apply", false, "adopt the pulled manifest as this box's live baseline (default: report what's available and stop)")
	return cmd
}

func runRetrieve(peerURL string, tier snapshotTier, generation int, apply bool, allowRollback ...bool) error {
	if generation < 0 {
		return fmt.Errorf("retrieve: generation must be nonnegative")
	}
	if peerURL != "" {
		if _, err := hostKeyForConfiguredTarget(peerURL); err != nil {
			return err
		}
	}
	p, err := loadPaths()
	if err != nil {
		return err
	}
	return retrieveWithRecovery(p, peerURL, tier, generation, apply, allowRollback...)
}

func retrieveWithRecovery(p paths, peerURL string, tier snapshotTier, generation int, apply bool, allowRollback ...bool) error {
	recovery := newBackupRecovery(p, nil)
	defer recovery.Close()
	var m *manifest.Manifest
	// An explicitly selected peer is preferred, with other copies as fallback.
	if peerURL != "" {
		for _, src := range recovery.sources {
			if src.url != peerURL {
				continue
			}
			target, err := recovery.target(src)
			g := generation
			if err == nil && g == 0 {
				g, err = replicate.NewRetriever(target).LatestGeneration(string(tier))
				if err == nil {
					generation = g
				}
			}
			if err == nil {
				data, readErr := target.GetManifest(string(tier), g)
				if readErr == nil {
					m, readErr = manifest.Parse(data)
				}
				if readErr == nil {
					readErr = validateRecoveryManifest(m, g)
				}
				if readErr != nil {
					m = nil
				}
			}
			break
		}
	}
	if m == nil {
		var err error
		if generation == 0 {
			m, err = recovery.loadManifest(tier, "")
		} else {
			m, err = recovery.manifest(tier, generation)
		}
		if err != nil {
			return err
		}
	}
	fmt.Printf("available: %s tier generation %d, %d records\n", tier, m.Generation, len(m.Records))
	if !apply {
		fmt.Println("dry run: pass --apply to recover objects and adopt the baseline")
		return nil
	}
	highest, lineageErr := recovery.highestGeneration(tier)
	permitted := len(allowRollback) > 0 && allowRollback[0]
	if (lineageErr != nil || m.Generation < highest) && !permitted {
		return fmt.Errorf("retrieve requires --allow-rollback: selected %d, highest %d, lineage check: %v", m.Generation, highest, lineageErr)
	}
	log, err := audit.New(p.auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()
	recovery.log = log
	st, err := recovery.store()
	if err != nil {
		return err
	}
	for _, rec := range m.Records {
		if _, err := st.Get(rec.Hash); err != nil {
			return fmt.Errorf("retrieve %s: %w", rec.Path, err)
		}
	}
	if err := recovery.archiveRecovered(tier, m); err != nil {
		return err
	}
	if err := m.SaveAs(p.manifestPathForTier(tier)); err != nil {
		return err
	}
	return log.Log("recovery", "baseline-adopted", map[string]any{"tier": tier, "generation": m.Generation})
}

// hostKeyForConfiguredTarget looks up peerURL in the configured peers and
// returns its pinned host key (empty for a file:// peer, which needs
// none). Recovery only makes sense against a peer this box was already
// configured to trust — an arbitrary, unpinned URL would reintroduce the
// exact TOFU risk pinning was meant to avoid.
func hostKeyForConfiguredTarget(peerURL string) (string, error) {
	for _, t := range configuredPeers() {
		if t.url == peerURL {
			return t.hostKey, nil
		}
	}
	return "", fmt.Errorf("retrieve: %q is not a configured peer (see 'warden pair')", peerURL)
}
