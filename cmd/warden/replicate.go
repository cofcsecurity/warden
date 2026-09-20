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

// replicateTarget is one configured replication peer: where to push, and
// (for ssh://) the pinned host key to verify it against.
type replicateTarget struct {
	url     string
	hostKey string // authorized_keys format; empty for file://
}

// parseReplicateTargets decodes buildReplicateTargets: records separated
// by ";;", each an "<url>||<hostkey>" pair (hostkey may be empty).
func parseReplicateTargets(raw string) []replicateTarget {
	var targets []replicateTarget
	for _, rec := range strings.Split(raw, ";;") {
		rec = strings.TrimSpace(rec)
		if rec == "" {
			continue
		}
		parts := strings.SplitN(rec, "||", 2)
		t := replicateTarget{url: strings.TrimSpace(parts[0])}
		if len(parts) == 2 {
			t.hostKey = strings.TrimSpace(parts[1])
		}
		targets = append(targets, t)
	}
	return targets
}

func replicateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "replicate",
		Short: "Push new snapshot objects to every configured replication peer",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReplicate()
		},
	}
}

// runReplicate pushes both tiers to every configured peer, not just
// config: "always have a path to recovering a box" means the off-host
// copy has to include the same backups a local rm -rf would otherwise
// take out entirely. One peer being unreachable doesn't stop the others
// from getting pushed to — errors are collected and reported together.
func runReplicate() error {
	targets := parseReplicateTargets(buildReplicateTargets)
	if len(targets) == 0 {
		return fmt.Errorf("replicate: no targets configured (build with -ldflags -X main.buildReplicateTargets=...)")
	}

	p, err := loadPaths()
	if err != nil {
		return err
	}
	st, err := store.New(p.storeRoot)
	if err != nil {
		return err
	}

	var errs []string
	for _, t := range targets {
		if err := pushToTarget(p, st, t); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", t.url, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("replicate: %d of %d peers failed:\n%s", len(errs), len(targets), strings.Join(errs, "\n"))
	}
	return nil
}

func pushToTarget(p paths, st *store.Store, t replicateTarget) error {
	target, closeTarget, err := dialReplicateTarget(t.url, t.hostKey)
	if err != nil {
		return err
	}
	defer closeTarget()

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
		if err := r.Push(string(tier), m, manifestData, st); err != nil {
			return fmt.Errorf("push %s tier: %w", tier, err)
		}
		pushed++
	}
	if pushed == 0 {
		return fmt.Errorf("no local manifest yet for either tier; run 'warden snapshot' first")
	}
	return nil
}

// dialReplicateTarget dials rawURL (ssh:// or file://), verifying against
// hostKey for an ssh:// target (ignored, and may be empty, for file://).
func dialReplicateTarget(rawURL, hostKey string) (replicate.Target, func() error, error) {
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
		return dialSSHReplicateTarget(u, hostKey)

	default:
		return nil, nil, fmt.Errorf("replicate: unsupported target scheme %q (want ssh:// or file://)", u.Scheme)
	}
}

func dialSSHReplicateTarget(u *url.URL, hostKeyStr string) (replicate.Target, func() error, error) {
	if buildReplicateKey == "" {
		return nil, nil, fmt.Errorf("replicate: ssh:// target needs buildReplicateKey baked in at build time")
	}
	if hostKeyStr == "" {
		return nil, nil, fmt.Errorf("replicate: ssh:// target %s has no pinned host key configured", u)
	}

	keyPEM, err := base64.StdEncoding.DecodeString(buildReplicateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("replicate: decode replication key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("replicate: parse replication key: %w", err)
	}

	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKeyStr))
	if err != nil {
		return nil, nil, fmt.Errorf("replicate: parse pinned host key for %s: %w", u, err)
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
