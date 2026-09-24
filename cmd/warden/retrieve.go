package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"warden/internal/audit"
	"warden/internal/manifest"
	"warden/internal/replicate"
)

// retrieveCmd is Push's reverse: recovering a box's own backups from a
// peer that holds a copy of them, after this box was wiped and rebuilt.
// The peer must be one of the URLs baked into buildReplicateTargets — its
// pinned host key comes from there, the same source of truth push uses,
// rather than a separate --host-key flag a rebuilt box wouldn't have any
// principled way to fill in on its own.
func retrieveCmd() *cobra.Command {
	var tierFlag string
	var generationFlag int
	var apply, allowRollback bool
	var auditOut string

	cmd := &cobra.Command{
		Use:   "retrieve [peer-url]",
		Short: "Pull this box's own backups back from a replication peer",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			peer := ""
			if len(args) > 0 {
				peer = args[0]
			}
			if auditOut != "" {
				if peer == "" {
					return fmt.Errorf("audit retrieval requires a peer URL")
				}
				return runRetrieveAudit(peer, auditOut)
			}
			tier, err := parseTier(tierFlag)
			if err != nil {
				return err
			}
			return runRetrieve(peer, tier, generationFlag, apply, allowRollback)
		},
	}
	cmd.Flags().StringVar(&auditOut, "audit", "", "instead of a snapshot, reassemble the replicated audit log into this file (\"-\" for stdout)")
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
					if readErr == nil {
						readErr = verifyManifest(m, tier)
					}
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

// runRetrieveAudit reassembles the audit-log segments a peer holds back
// into one JSON-lines file. This is the recovery half of the reason the
// log is replicated at all: if red team deleted audit.log on this box (or
// the box was rebuilt from scratch), the evidence of what happened is
// still sitting on the peer, and this is how it comes back.
//
// The output is written somewhere the operator names, never over the live
// audit log: mixing a peer's copy back into the file this box is actively
// appending to would muddle the local record with a remote one.
func runRetrieveAudit(peerURL, outPath string) error {
	hostKey, err := hostKeyForConfiguredTarget(peerURL)
	if err != nil {
		return err
	}

	target, closeTarget, err := dialReplicateTarget(peerURL, hostKey)
	if err != nil {
		return err
	}
	defer closeTarget()

	data, err := replicate.NewRetriever(target).PullAudit()
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("retrieve: %s holds no replicated audit log", peerURL)
	}

	if outPath == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(outPath, data, 0o600); err != nil {
		return fmt.Errorf("retrieve: write %s: %w", outPath, err)
	}
	fmt.Printf("wrote %d bytes of replicated audit log from %s to %s\n", len(data), peerURL, outPath)
	return nil
}

// hostKeyForConfiguredTarget looks up peerURL in buildReplicateTargets and
// returns its pinned host key (empty for a file:// peer, which needs
// none). Recovery only makes sense against a peer this box was already
// configured to trust — an arbitrary, unpinned URL would reintroduce the
// exact TOFU risk pinning was meant to avoid.
func hostKeyForConfiguredTarget(peerURL string) (string, error) {
	for _, t := range parseReplicateTargets(buildReplicateTargets) {
		if t.url == peerURL {
			return t.hostKey, nil
		}
	}
	return "", fmt.Errorf("retrieve: %q is not one of this build's configured replicate targets", peerURL)
}
