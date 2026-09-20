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

func runReplicate() error {
	if buildReplicateURL == "" {
		return fmt.Errorf("replicate: no target configured (build with -ldflags -X main.buildReplicateURL=...)")
	}

	target, closeTarget, err := dialReplicateTarget(buildReplicateURL)
	if err != nil {
		return err
	}
	defer closeTarget()

	m, err := manifest.New(configManifestPath)
	if err != nil {
		return err
	}
	if m.Generation == 0 && len(m.Records) == 0 {
		return fmt.Errorf("replicate: no local manifest yet; run 'warden snapshot' first")
	}

	manifestData, err := readArchivedManifest(m.Generation)
	if err != nil {
		return err
	}

	st, err := store.New(storeRoot)
	if err != nil {
		return err
	}

	r := replicate.New(target)
	return r.Push(m, manifestData, st)
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

func readArchivedManifest(generation int) ([]byte, error) {
	path := manifest.ArchivePath(configManifestsDir, generation)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("replicate: read archived manifest %s: %w", path, err)
	}
	return data, nil
}
