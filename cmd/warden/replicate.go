package main

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"warden/internal/manifest"
	"warden/internal/replicate"
	"warden/internal/store"
)

func replicateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "replicate",
		Short: "Push new snapshot objects to the off-host replication target",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReplicate()
		},
	}
}

// runReplicate pushes both tiers, not just config: "always have a path to
// recovering a box" means the off-host copy has to include the same
// backups a local rm -rf would otherwise take out entirely, not just the
// smaller config tier.
func runReplicate() error {
	if buildReplicateURL == "" {
		return fmt.Errorf("replicate: no target configured (build with -ldflags -X main.buildReplicateURL=...)")
	}

	p, err := loadPaths()
	if err != nil {
		return err
	}

	target, closeTarget, err := dialReplicateTarget(buildReplicateURL)
	if err != nil {
		return err
	}
	defer closeTarget()

	st, err := store.New(p.storeRoot)
	if err != nil {
		return err
	}
	r := replicate.New(target)

	pushed := 0
	for _, tier := range []snapshotTier{tierConfig, tierData} {
		m, err := manifest.New(p.manifestPathForTier(tier))
		if err != nil {
			return err
		}
		if m.Generation == 0 && len(m.Records) == 0 {
			continue // this tier has never been snapshotted yet; nothing to push
		}

		manifestData, err := readArchivedManifest(p.manifestsDirForTier(tier), m.Generation)
		if err != nil {
			return err
		}
		if err := r.Push(m, manifestData, st); err != nil {
			return fmt.Errorf("replicate: push %s tier: %w", tier, err)
		}
		pushed++
	}

	if pushed == 0 {
		return fmt.Errorf("replicate: no local manifest yet for either tier; run 'warden snapshot' first")
	}
	return nil
}

// replicateTarget is the subset of replicate.Target dial results this
// command needs: the target itself, plus how to close it (an SSH
// connection needs closing; a filesystem target doesn't).
func dialReplicateTarget(rawURL string) (replicate.Target, func() error, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, fmt.Errorf("replicate: parse target URL: %w", err)
	}

	switch u.Scheme {
	case "file":
		target, err := replicate.NewFSTarget(u.Path)
		if err != nil {
			return nil, nil, err
		}
		return target, func() error { return nil }, nil

	case "ssh":
		return dialSSHReplicateTarget(u)

	default:
		return nil, nil, fmt.Errorf("replicate: unsupported target scheme %q (want ssh:// or file://)", u.Scheme)
	}
}

func dialSSHReplicateTarget(u *url.URL) (replicate.Target, func() error, error) {
	if buildReplicateKey == "" || buildReplicateHostKey == "" {
		return nil, nil, fmt.Errorf("replicate: ssh:// target needs buildReplicateKey and buildReplicateHostKey baked in at build time")
	}

	keyPEM, err := base64.StdEncoding.DecodeString(buildReplicateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("replicate: decode replication key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("replicate: parse replication key: %w", err)
	}

	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(buildReplicateHostKey))
	if err != nil {
		return nil, nil, fmt.Errorf("replicate: parse pinned host key: %w", err)
	}

	user := "warden"
	if u.User != nil {
		user = u.User.Username()
	}

	addr := u.Host
	if !strings.Contains(addr, ":") {
		addr += ":22"
	}

	target, err := replicate.DialSSH(addr, user, signer, hostKey, u.Path)
	if err != nil {
		return nil, nil, err
	}
	return target, target.Close, nil
}

func readArchivedManifest(manifestsDir string, generation int) ([]byte, error) {
	path := manifest.ArchivePath(manifestsDir, generation)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("replicate: read archived manifest %s: %w", path, err)
	}
	return data, nil
}
