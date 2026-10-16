package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"warden/internal/audit"
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

// parseReplicateTargets decodes "<url>||<hostkey>" records separated by
// ";;" (hostkey may be empty). Tests use it to build peer lists.
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
		Short: "Push new snapshot objects and manifests to every paired peer",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReplicate()
		},
	}
}

// runReplicate pushes both tiers to every configured peer. One unreachable
// peer does not stop the others; errors are collected and reported together.
func runReplicate() error {
	targets := configuredPeers()
	if len(targets) == 0 {
		return fmt.Errorf("replicate: no peers configured (see 'warden pair')")
	}

	p, err := loadPaths()
	if err != nil {
		return err
	}
	recovery := newBackupRecovery(p, nil)
	defer recovery.Close()
	st, err := recovery.store()
	if err != nil {
		return err
	}
	log, err := audit.New(p.auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()
	recovery.log = log

	var errs []string
	peersOK := 0
	for _, t := range targets {
		if err := pushToTarget(p, st, t); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", t.url, err))
			continue
		}
		peersOK++
	}

	if logErr := log.Log("replicate", "pass", map[string]any{
		"peers":  len(targets),
		"failed": len(errs),
	}); logErr != nil {
		return logErr
	}

	fmt.Printf("replicate: %d of %d peer(s) completed.\n", peersOK, len(targets))
	if len(errs) > 0 {
		return fmt.Errorf("replicate: %d of %d peers failed:\n%s", len(errs), len(targets), strings.Join(errs, "\n"))
	}
	return nil
}

// pushToTarget pushes both snapshot tiers to one peer.
func pushToTarget(p paths, st *store.Store, t replicateTarget) error {
	target, closeTarget, err := dialReplicateTarget(t.url, t.hostKey)
	if err != nil {
		return err
	}
	defer closeTarget()

	r := replicate.New(target)
	recovery := newBackupRecovery(p, nil)
	defer recovery.Close()
	pushed := 0
	var failures []error
	for _, tier := range []snapshotTier{tierConfig, tierData} {
		tierErr := func() error {
			m, err := manifest.New(p.manifestPathForTier(tier))
			if err != nil {
				return err
			}
			if m.Generation == 0 && len(m.Records) == 0 {
				recovered, recoveryErr := recovery.manifest(tier, 0)
				if recoveryErr != nil {
					if tier == tierData && len(dataTierPaths) == 0 {
						return nil
					}
					return recoveryErr
				}
				m = recovered
			}

			manifestData, err := readArchivedManifest(p.manifestsDirForTier(tier), m.Generation)
			if err != nil {
				// The live manifest is another local copy of the same generation.
				manifestData, err = json.Marshal(m)
				if err != nil {
					return err
				}
			}
			if err := r.Push(string(tier), m, manifestData, st); err != nil {
				return fmt.Errorf("push %s tier: %w", tier, err)
			}
			pushed++
			return nil
		}()
		if tierErr != nil {
			failures = append(failures, fmt.Errorf("%s: %w", tier, tierErr))
		}
	}
	if pushed == 0 && len(failures) == 0 {
		failures = append(failures, fmt.Errorf("no snapshot available"))
	}
	return errors.Join(failures...)
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

	case "ssh", "ssh+receiver":
		return dialSSHReplicateTarget(u, hostKey)

	default:
		return nil, nil, fmt.Errorf("replicate: unsupported target scheme %q (want ssh:// or file://)", u.Scheme)
	}
}

func dialSSHReplicateTarget(u *url.URL, hostKeyStr string) (replicate.Target, func() error, error) {
	if hostKeyStr == "" {
		return nil, nil, fmt.Errorf("replicate: ssh target %s has no pinned host key configured", u)
	}
	signer, err := loadPeerSigner()
	if err != nil {
		return nil, nil, err
	}

	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKeyStr))
	if err != nil {
		return nil, nil, fmt.Errorf("replicate: parse pinned host key for %s: %w", u, err)
	}

	user := "warden"
	if u.User != nil {
		user = u.User.Username()
	}

	port := u.Port()
	if port == "" {
		port = "22"
	}
	addr := net.JoinHostPort(u.Hostname(), port)

	target, err := replicate.DialSSH(addr, user, signer, hostKey, u.Path)
	if err != nil {
		return nil, nil, err
	}
	if u.Scheme == "ssh+receiver" {
		return &replicate.ReceiverTarget{Transport: target}, target.Close, nil
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
