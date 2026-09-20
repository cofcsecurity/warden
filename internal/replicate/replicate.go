// Package replicate pushes new snapshot objects off-box, so a root
// compromise of the monitored host doesn't take the backups with it.
package replicate

import (
	"fmt"

	"golang.org/x/crypto/ssh"
)

// Target is where a Replicator pushes to. Both an SSH host and a local
// filesystem path (e.g. removable media, when no second box is available)
// satisfy this interface, so callers don't branch on which is configured.
type Target interface {
	// Put writes an object if the destination doesn't already have one
	// under this hash. Implementations must never delete or overwrite an
	// existing object — replication is additive-only.
	Put(hash string, content []byte) error
	Has(hash string) (bool, error)
}

// Replicator pushes store objects and the current manifest to a Target.
type Replicator struct {
	target Target
}

// New builds a Replicator against target.
func New(target Target) *Replicator {
	return &Replicator{target: target}
}

// SSHTarget is a Target backed by golang.org/x/crypto/ssh, authenticating
// with a key generated only for replication (never a personal or team
// login key).
type SSHTarget struct {
	client     *ssh.Client
	remoteRoot string
}

// DialSSH connects to addr as user, authenticating with signer, and returns
// a Target rooted at remoteRoot on that host.
//
// TODO: implement the actual object transfer (SFTP subsystem or exec'd
// commands over the session) and host key verification against a pinned
// key baked in at build time.
func DialSSH(addr, user string, signer ssh.Signer, remoteRoot string) (*SSHTarget, error) {
	return nil, fmt.Errorf("replicate: DialSSH not yet implemented")
}

func (t *SSHTarget) Put(hash string, content []byte) error {
	return fmt.Errorf("replicate: SSHTarget.Put not yet implemented")
}

func (t *SSHTarget) Has(hash string) (bool, error) {
	return false, fmt.Errorf("replicate: SSHTarget.Has not yet implemented")
}

// FSTarget is a Target backed by a local (or removable-media) filesystem
// path, used when no second team-controlled box is available.
type FSTarget struct {
	root string
}

// NewFSTarget returns a Target rooted at root.
func NewFSTarget(root string) *FSTarget {
	return &FSTarget{root: root}
}

func (t *FSTarget) Put(hash string, content []byte) error {
	return fmt.Errorf("replicate: FSTarget.Put not yet implemented")
}

func (t *FSTarget) Has(hash string) (bool, error) {
	return false, fmt.Errorf("replicate: FSTarget.Has not yet implemented")
}

// Push replicates every object referenced by manifestData (the manifest's
// raw bytes) plus objects, skipping any hash the target already has.
//
// TODO: parse the manifest, iterate its records, pull each from the local
// store, and call target.Put for anything target.Has reports missing.
func (r *Replicator) Push(manifestData []byte, objects map[string][]byte) error {
	return fmt.Errorf("replicate: Push not yet implemented")
}
