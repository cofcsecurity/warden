package replicate

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHTarget is a Target backed by golang.org/x/crypto/ssh, authenticating
// with a key generated only for replication (never a personal or team
// login key). It has no SFTP dependency: every operation is a small shell
// command run over an exec session, since the destination is a
// team-controlled box the design already trusts to run its own shell.
type SSHTarget struct {
	client *ssh.Client
	root   string
}

// DialSSH connects to addr ("host:port") as user, authenticating with
// signer, and verifies the server against hostKey — a key pinned at build
// time, not learned on first connect (TOFU). It returns a Target rooted at
// root on that host.
func DialSSH(addr, user string, signer ssh.Signer, hostKey ssh.PublicKey, root string) (*SSHTarget, error) {
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		// Without this, algorithm negotiation can settle on a host key
		// type other than the one pinned (e.g. the server's RSA key)
		// even when the server also holds the exact key we pinned —
		// ssh.ClientConfig has no default restriction on which type gets
		// negotiated. FixedHostKey would then correctly reject a
		// perfectly legitimate server for presenting "the wrong" key,
		// when really we just never asked for the right one.
		HostKeyAlgorithms: []string{hostKey.Type()},
		Timeout:           10 * time.Second,
	}

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("replicate: dial %s: %w", addr, err)
	}

	t := &SSHTarget{client: client, root: root}
	if err := t.run(fmt.Sprintf("mkdir -p %s", shellQuote(path.Join(root, "objects")))); err != nil {
		client.Close()
		return nil, fmt.Errorf("replicate: init remote root %s: %w", root, err)
	}
	return t, nil
}

// Close closes the underlying SSH connection.
func (t *SSHTarget) Close() error {
	return t.client.Close()
}

func (t *SSHTarget) objectPath(hash string) string {
	return path.Join(t.root, "objects", hash[:2], hash)
}

func (t *SSHTarget) manifestsDir(namespace string) string {
	return path.Join(t.root, "manifests-"+namespace)
}

func (t *SSHTarget) manifestPath(namespace string, generation int) string {
	return path.Join(t.manifestsDir(namespace), fmt.Sprintf("manifest-%d.json", generation))
}

func (t *SSHTarget) Has(hash string) (bool, error) {
	return t.exists(t.objectPath(hash))
}

func (t *SSHTarget) Put(hash string, content []byte) error {
	return t.writeOnceRemote(t.objectPath(hash), content)
}

func (t *SSHTarget) Get(hash string) ([]byte, error) {
	return t.readRemote(t.objectPath(hash))
}

func (t *SSHTarget) HasManifest(namespace string, generation int) (bool, error) {
	return t.exists(t.manifestPath(namespace, generation))
}

func (t *SSHTarget) PutManifest(namespace string, generation int, data []byte) error {
	return t.writeOnceRemote(t.manifestPath(namespace, generation), data)
}

func (t *SSHTarget) GetManifest(namespace string, generation int) ([]byte, error) {
	return t.readRemote(t.manifestPath(namespace, generation))
}

// ManifestGenerations lists the remote manifests-<namespace> directory and
// parses out generation numbers. A directory that doesn't exist yet (no
// generation ever pushed under this namespace) is treated as empty, not
// an error, matching manifest.Generations' local-filesystem behavior.
func (t *SSHTarget) ManifestGenerations(namespace string) ([]int, error) {
	dir := t.manifestsDir(namespace)

	session, err := t.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("replicate: open session: %w", err)
	}
	defer session.Close()

	var out bytes.Buffer
	session.Stdout = &out
	err = session.Run(fmt.Sprintf("ls -1 %s", shellQuote(dir)))
	if err != nil {
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			return nil, nil // directory doesn't exist (or is empty and ls errored)
		}
		return nil, fmt.Errorf("replicate: list %s: %w", dir, err)
	}

	var gens []int
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var g int
		if _, err := fmt.Sscanf(strings.TrimSpace(line), "manifest-%d.json", &g); err == nil {
			gens = append(gens, g)
		}
	}
	sort.Ints(gens)
	return gens, nil
}

func (t *SSHTarget) exists(remotePath string) (bool, error) {
	err := t.run(fmt.Sprintf("test -e %s", shellQuote(remotePath)))
	if err == nil {
		return true, nil
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return false, nil
	}
	return false, fmt.Errorf("replicate: check %s: %w", remotePath, err)
}

// writeOnceRemote writes content to remotePath unless it's already there.
// The remote shell, not this process, decides existence and does the
// rename, so there's no window where a partial write could look complete:
// the temp file only replaces the target once it's fully written.
func (t *SSHTarget) writeOnceRemote(remotePath string, content []byte) error {
	session, err := t.client.NewSession()
	if err != nil {
		return fmt.Errorf("replicate: open session: %w", err)
	}
	defer session.Close()

	session.Stdin = bytes.NewReader(content)

	// Fixed tmp suffix, not a per-process unique name: only one
	// snapshot/replicate invocation is expected to run at a time (see
	// docs/DESIGN.md), so this isn't racing against a concurrent writer.
	dir := path.Dir(remotePath)
	tmpPath := remotePath + ".tmp"
	cmd := fmt.Sprintf(
		`sh -c 'set -e; mkdir -p %s; if [ ! -e %s ]; then umask 077; cat > %s && mv %s %s; fi'`,
		shellQuote(dir), shellQuote(remotePath), shellQuote(tmpPath), shellQuote(tmpPath), shellQuote(remotePath),
	)
	if err := session.Run(cmd); err != nil {
		return fmt.Errorf("replicate: write %s: %w", remotePath, err)
	}
	return nil
}

func (t *SSHTarget) readRemote(remotePath string) ([]byte, error) {
	session, err := t.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("replicate: open session: %w", err)
	}
	defer session.Close()

	var out bytes.Buffer
	session.Stdout = &out
	if err := session.Run(fmt.Sprintf("cat %s", shellQuote(remotePath))); err != nil {
		return nil, fmt.Errorf("replicate: read %s: %w", remotePath, err)
	}
	return out.Bytes(), nil
}

func (t *SSHTarget) run(cmd string) error {
	session, err := t.client.NewSession()
	if err != nil {
		return fmt.Errorf("replicate: open session: %w", err)
	}
	defer session.Close()
	return session.Run(cmd)
}

// shellQuote wraps s in single quotes for safe use in a remote shell
// command, escaping any single quotes it contains.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
