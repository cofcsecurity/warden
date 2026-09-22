package replicate

import (
	"bytes"
	"errors"
	"fmt"
	"net"
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

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("replicate: dial %s: %w", addr, err)
	}
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		conn.Close()
		return nil, err
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("replicate: handshake %s: %w", addr, err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		sshConn.Close()
		return nil, err
	}
	return &SSHTarget{client: ssh.NewClient(sshConn, chans, reqs), root: root}, nil
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

	lines, err := t.listRemoteDir(dir)
	if err != nil {
		return nil, err
	}

	var gens []int
	for _, line := range lines {
		var g int
		if _, err := fmt.Sscanf(line, "manifest-%d.json", &g); err == nil {
			gens = append(gens, g)
		}
	}
	sort.Ints(gens)
	return gens, nil
}

// listRemoteDir returns the entry names in a remote directory, or no
// names at all if the directory doesn't exist yet — matching
// manifest.Generations' local-filesystem behavior. Existence is checked
// separately rather than reading any non-zero ls exit as "empty": that
// conflated "nothing has been pushed here yet" with a peer whose disk is
// full, whose permissions are wrong, or whose directory we can't read,
// and made retrieve report an empty peer that in fact holds every
// generation this box owns.
func (t *SSHTarget) listRemoteDir(dir string) ([]string, error) {
	present, err := t.exists(dir)
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, nil
	}

	session, err := t.newSession()
	if err != nil {
		return nil, fmt.Errorf("replicate: open session: %w", err)
	}
	defer session.Close()

	var out bytes.Buffer
	session.Stdout = &out
	if err := t.runSession(session, fmt.Sprintf("ls -1 %s", shellQuote(dir))); err != nil {
		return nil, fmt.Errorf("replicate: list %s: %w", dir, err)
	}

	var names []string
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if name := strings.TrimSpace(line); name != "" {
			names = append(names, name)
		}
	}
	return names, nil
}

func (t *SSHTarget) auditDir() string {
	return path.Join(t.root, "audit")
}

// auditPath refuses a name containing a path separator, so a segment
// name can only ever name a file directly inside the audit directory on
// the peer.
func (t *SSHTarget) auditPath(name string) (string, error) {
	if name == "" || strings.Contains(name, "/") {
		return "", fmt.Errorf("replicate: invalid audit segment name %q", name)
	}
	return path.Join(t.auditDir(), name), nil
}

func (t *SSHTarget) HasAudit(name string) (bool, error) {
	p, err := t.auditPath(name)
	if err != nil {
		return false, err
	}
	return t.exists(p)
}

func (t *SSHTarget) PutAudit(name string, data []byte) error {
	p, err := t.auditPath(name)
	if err != nil {
		return err
	}
	return t.writeOnceRemote(p, data)
}

func (t *SSHTarget) GetAudit(name string) ([]byte, error) {
	p, err := t.auditPath(name)
	if err != nil {
		return nil, err
	}
	return t.readRemote(p)
}

func (t *SSHTarget) AuditSegments() ([]string, error) {
	names, err := t.listRemoteDir(t.auditDir())
	if err != nil {
		return nil, err
	}

	var segments []string
	for _, name := range names {
		if strings.HasSuffix(name, ".log") {
			segments = append(segments, name)
		}
	}
	sort.Strings(segments)
	return segments, nil
}

func (t *SSHTarget) PutHeartbeat(name string, data []byte) error {
	if name == "" || strings.Contains(name, "/") {
		return fmt.Errorf("replicate: invalid heartbeat name %q", name)
	}
	return t.writeOnceRemote(path.Join(t.root, "heartbeat", name), data)
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
// The remote shell links a completed temporary file into place without
// replacing an existing copy, including one published by a concurrent writer.
func (t *SSHTarget) writeOnceRemote(remotePath string, content []byte) error {
	session, err := t.newSession()
	if err != nil {
		return fmt.Errorf("replicate: open session: %w", err)
	}
	defer session.Close()

	session.Stdin = bytes.NewReader(content)

	cmd := remoteWriteCommand(remotePath)
	if err := t.runSession(session, cmd); err != nil {
		return fmt.Errorf("replicate: write %s: %w", remotePath, err)
	}
	return nil
}

func remoteWriteCommand(remotePath string) string {
	dir := path.Dir(remotePath)
	return fmt.Sprintf(`set -e; mkdir -p %s; if [ ! -e %s ]; then umask 077; warden_tmp=$(mktemp %s); trap 'rm -f "$warden_tmp"' EXIT; cat > "$warden_tmp"; if ! ln "$warden_tmp" %s; then test -e %s; fi; fi`, shellQuote(dir), shellQuote(remotePath), shellQuote(remotePath+".tmp.XXXXXX"), shellQuote(remotePath), shellQuote(remotePath))
}

func (t *SSHTarget) readRemote(remotePath string) ([]byte, error) {
	session, err := t.newSession()
	if err != nil {
		return nil, fmt.Errorf("replicate: open session: %w", err)
	}
	defer session.Close()

	var out bytes.Buffer
	session.Stdout = &out
	if err := t.runSession(session, fmt.Sprintf("cat %s", shellQuote(remotePath))); err != nil {
		return nil, fmt.Errorf("replicate: read %s: %w", remotePath, err)
	}
	return out.Bytes(), nil
}

func (t *SSHTarget) run(cmd string) error {
	session, err := t.newSession()
	if err != nil {
		return fmt.Errorf("replicate: open session: %w", err)
	}
	defer session.Close()
	return t.runSession(session, cmd)
}

func (t *SSHTarget) newSession() (*ssh.Session, error) {
	type result struct {
		session *ssh.Session
		err     error
	}
	done := make(chan result, 1)
	go func() { session, err := t.client.NewSession(); done <- result{session, err} }()
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	select {
	case result := <-done:
		return result.session, result.err
	case <-timer.C:
		_ = t.client.Close()
		result := <-done
		if result.session != nil {
			_ = result.session.Close()
		}
		return nil, fmt.Errorf("replicate: opening remote session timed out")
	}
}

// A stalled peer must not prevent fallback to another replica.
func (t *SSHTarget) runSession(session *ssh.Session, command string) error {
	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		_ = t.client.Close()
		<-done
		return fmt.Errorf("replicate: remote command timed out")
	}
}

// shellQuote wraps s in single quotes for safe use in a remote shell
// command, escaping any single quotes it contains.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
