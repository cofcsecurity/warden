package replicate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os/exec"
	"testing"

	"golang.org/x/crypto/ssh"
)

// testSSHServer is a minimal SSH server that runs every "exec" request
// through the local shell, standing in for a real destination box so
// SSHTarget's remote commands (mkdir/test/cat/mv) can be exercised without
// any actual network infrastructure.
type testSSHServer struct {
	addr       string
	hostSigner ssh.Signer
	clientKey  ssh.PublicKey
	listener   net.Listener
}

func startTestSSHServer(t *testing.T, clientKey ssh.PublicKey) *testSSHServer {
	t.Helper()

	hostSigner := generateSigner(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := &testSSHServer{
		addr:       listener.Addr().String(),
		hostSigner: hostSigner,
		clientKey:  clientKey,
		listener:   listener,
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), clientKey.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unauthorized key")
		},
	}
	config.AddHostKey(hostSigner)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go srv.handleConn(conn, config)
		}
	}()

	t.Cleanup(func() { listener.Close() })
	return srv
}

func (s *testSSHServer) handleConn(conn net.Conn, config *ssh.ServerConfig) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go handleSession(channel, requests)
	}
}

func handleSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	for req := range requests {
		if req.Type != "exec" {
			req.Reply(false, nil)
			continue
		}

		var payload struct{ Command string }
		if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
			req.Reply(false, nil)
			continue
		}
		req.Reply(true, nil)

		cmd := exec.Command("sh", "-c", payload.Command)
		cmd.Stdin = channel
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		runErr := cmd.Run()

		channel.Write(stdout.Bytes())
		channel.Stderr().Write(stderr.Bytes())

		exitCode := 0
		if runErr != nil {
			if exitErr, ok := runErr.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = 1
			}
		}
		channel.SendRequest("exit-status", false, ssh.Marshal(&struct{ Status uint32 }{uint32(exitCode)}))
		return
	}
}

func generateSigner(t *testing.T) ssh.Signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestSSHTargetPutHasAndAdditiveOnly(t *testing.T) {
	clientSigner := generateSigner(t)
	srv := startTestSSHServer(t, clientSigner.PublicKey())

	root := t.TempDir() + "/warden-replica"
	target, err := DialSSH(srv.addr, "root", clientSigner, srv.hostSigner.PublicKey(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	has, err := target.Has("deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Fatalf("expected object to be absent before Put")
	}

	if err := target.Put("deadbeef", []byte("known-good content")); err != nil {
		t.Fatal(err)
	}

	has, err = target.Has("deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Fatalf("expected object to be present after Put")
	}

	// Additive-only: a second Put under the same hash must not clobber.
	if err := target.Put("deadbeef", []byte("clobbered")); err != nil {
		t.Fatal(err)
	}
	got, err := readRemoteFile(t, srv.addr, clientSigner, srv.hostSigner.PublicKey(), target.objectPath("deadbeef"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "known-good content" {
		t.Fatalf("Put overwrote existing remote content: got %q", got)
	}
}

func TestSSHTargetManifestRoundTrip(t *testing.T) {
	clientSigner := generateSigner(t)
	srv := startTestSSHServer(t, clientSigner.PublicKey())

	root := t.TempDir() + "/warden-replica"
	target, err := DialSSH(srv.addr, "root", clientSigner, srv.hostSigner.PublicKey(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	if err := target.PutManifest("config", 1, []byte(`{"generation":1}`)); err != nil {
		t.Fatal(err)
	}
	has, err := target.HasManifest("config", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Fatalf("expected generation 1 to be present after PutManifest")
	}

	has, err = target.HasManifest("config", 2)
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Fatalf("expected generation 2 to be absent")
	}

	got, err := target.GetManifest("config", 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"generation":1}` {
		t.Fatalf("got %q", got)
	}

	// A different namespace (the data tier) must not see config's
	// generation 1 — separate lineages, same remote root.
	has, err = target.HasManifest("data", 1)
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Fatalf("expected data tier generation 1 to be absent; namespaces collided")
	}

	gens, err := target.ManifestGenerations("config")
	if err != nil {
		t.Fatal(err)
	}
	if len(gens) != 1 || gens[0] != 1 {
		t.Fatalf("got %v, want [1]", gens)
	}
}

func TestDialSSHRejectsWrongHostKey(t *testing.T) {
	clientSigner := generateSigner(t)
	srv := startTestSSHServer(t, clientSigner.PublicKey())

	wrongHostKey := generateSigner(t).PublicKey()
	_, err := DialSSH(srv.addr, "root", clientSigner, wrongHostKey, t.TempDir())
	if err == nil {
		t.Fatal("expected DialSSH to reject an unpinned host key")
	}
}

func TestDialSSHRejectsWrongClientKey(t *testing.T) {
	authorizedSigner := generateSigner(t)
	srv := startTestSSHServer(t, authorizedSigner.PublicKey())

	wrongClientSigner := generateSigner(t)
	_, err := DialSSH(srv.addr, "root", wrongClientSigner, srv.hostSigner.PublicKey(), t.TempDir())
	if err == nil {
		t.Fatal("expected DialSSH to fail authentication with an unauthorized client key")
	}
}

// readRemoteFile is a test-only helper, independent of SSHTarget's own
// code paths, so the additive-only assertion isn't just checking Has again.
func readRemoteFile(t *testing.T, addr string, signer ssh.Signer, hostKey ssh.PublicKey, remotePath string) ([]byte, error) {
	t.Helper()
	config := &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
	}
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	var out bytes.Buffer
	session.Stdout = &out
	if err := session.Run(fmt.Sprintf("cat %s", shellQuote(remotePath))); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
