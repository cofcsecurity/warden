package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"warden/internal/replicate"
	"warden/internal/store"
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
	var apply bool

	cmd := &cobra.Command{
		Use:   "retrieve <peer-url>",
		Short: "Pull this box's own backups back from a replication peer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tier, err := parseTier(tierFlag)
			if err != nil {
				return err
			}
			return runRetrieve(args[0], tier, generationFlag, apply)
		},
	}
	cmd.Flags().StringVar(&tierFlag, "tier", string(tierConfig), `snapshot tier to pull: "config" or "data"`)
	cmd.Flags().IntVar(&generationFlag, "generation", 0, "generation to pull (default: latest available on the peer)")
	cmd.Flags().BoolVar(&apply, "apply", false, "adopt the pulled manifest as this box's live baseline (default: report what's available and stop)")
	return cmd
}

func runRetrieve(peerURL string, tier snapshotTier, generation int, apply bool) error {
	hostKey, err := hostKeyForConfiguredTarget(peerURL)
	if err != nil {
		return err
	}

	p, err := loadPaths()
	if err != nil {
		return err
	}

	target, closeTarget, err := dialReplicateTarget(peerURL, hostKey)
	if err != nil {
		return err
	}
	defer closeTarget()

	st, err := store.New(p.storeRoot)
	if err != nil {
		return err
	}

	r := replicate.NewRetriever(target)
	if generation == 0 {
		generation, err = r.LatestGeneration(string(tier))
		if err != nil {
			return err
		}
	}

	m, err := r.Pull(string(tier), generation, st)
	if err != nil {
		return err
	}

	fmt.Printf("pulled %s tier generation %d from %s: %d records now available in the local store\n",
		tier, m.Generation, peerURL, len(m.Records))

	if !apply {
		fmt.Println("dry run: pass --apply to adopt this as the local live baseline")
		return nil
	}

	manifestPath := p.manifestPathForTier(tier)
	manifestsDir := p.manifestsDirForTier(tier)
	if err := m.SaveAs(manifestPath); err != nil {
		return err
	}
	if err := m.Archive(manifestsDir); err != nil {
		return err
	}

	fmt.Printf("adopted as the live %s-tier baseline; 'warden watch'/'warden restore' will use it from here\n", tier)
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
