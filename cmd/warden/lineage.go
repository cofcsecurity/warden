package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"warden/internal/manifest"
)

// Supply a separate signing key per source. Verification pins may be deployed
// without the private key on receiving or recovery-only machines.
var buildManifestKey, buildManifestPublicKey, buildManifestSource string

func signManifest(m *manifest.Manifest, tier snapshotTier) error {
	if buildManifestKey == "" {
		if buildManifestPublicKey != "" {
			return fmt.Errorf("manifest signing key is required for new generations")
		}
		return nil
	}
	key, err := base64.StdEncoding.DecodeString(buildManifestKey)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid Ed25519 manifest private key")
	}
	public, err := base64.StdEncoding.DecodeString(buildManifestPublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return fmt.Errorf("manifest public key is required")
	}
	if !ed25519.PublicKey(public).Equal(ed25519.PrivateKey(key).Public()) {
		return fmt.Errorf("manifest key pair does not match")
	}
	return m.Sign(key, buildManifestSource, string(tier))
}
func verifyManifest(m *manifest.Manifest, tier snapshotTier) error {
	if buildManifestPublicKey == "" {
		return nil
	}
	key, err := base64.StdEncoding.DecodeString(buildManifestPublicKey)
	if err != nil {
		return err
	}
	return m.Verify(key, buildManifestSource, string(tier))
}
func (r *backupRecovery) highestGeneration(tier snapshotTier) (int, error) {
	gens, err := manifest.Generations(r.p.manifestsDirForTier(tier))
	if err != nil {
		return 0, err
	}
	highest := 0
	for _, g := range gens {
		if g > highest {
			highest = g
		}
	}
	if current, err := manifest.New(r.p.manifestPathForTier(tier)); err != nil {
		return 0, err
	} else if current.Generation > highest {
		highest = current.Generation
	}
	for _, src := range r.sources {
		target, err := r.target(src)
		if err != nil {
			return 0, fmt.Errorf("cannot check lineage on %s: %w", src.url, err)
		}
		remote, err := target.ManifestGenerations(string(tier))
		if err != nil {
			return 0, err
		}
		for _, g := range remote {
			if g > highest {
				highest = g
			}
		}
	}
	return highest, nil
}

// allocateGeneration consults replicas when local generation history is lost.
func allocateGeneration(p paths, tier snapshotTier, current int) (int, error) {
	gens, err := manifest.Generations(p.manifestsDirForTier(tier))
	if err != nil {
		return 0, err
	}
	if len(gens) == 0 {
		recovery := newBackupRecovery(p, nil)
		defer recovery.Close()
		highest, err := recovery.highestGeneration(tier)
		if err != nil {
			return 0, err
		}
		if highest > current {
			current = highest
		}
	}
	return manifest.NextGeneration(p.manifestsDirForTier(tier), current)
}
