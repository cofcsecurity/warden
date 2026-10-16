package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"warden/internal/fsutil"
)

// pairCmd sets up off-host backups between two boxes with nothing prepared
// in advance and no private key ever leaving the box that made it.
//
// Three steps, each one line of output feeding the next, so the whole
// exchange runs from a laptop that has only ssh (bash or PowerShell):
//
//	ssh <userA>@A pair add $(ssh <userB>@B pair accept $(ssh <userA>@A pair key))
//
// After that A pushes its backups to B on a timer. B stores them under a
// directory only A's key can write to, through a forced command with no
// shell and no delete. Run it again the other way round (or in a ring) so
// every box has at least one peer.
func pairCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pair",
		Short: "Pair this box with a peer that keeps a copy of its backups",
		Long: `Pairing gives this box's backups a home on another box. From a machine
with only ssh:

  ssh <userA>@A pair add $(ssh <userB>@B pair accept $(ssh <userA>@A pair key))

'pair key' prints this box's name and backup public key (generating the key
on first use). 'pair accept' on the peer authorizes that key for uploads
only, and prints the address and host key to push to. 'pair add' records
that peer here and schedules replication.`,
	}
	cmd.AddCommand(pairKeyCmd(), pairAcceptCmd(), pairAddCmd(), pairListCmd(), pairRemoveCmd())
	return cmd
}

func pairKeyCmd() *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Print this box's name and backup public key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := loadPaths()
			if err != nil {
				return err
			}
			signer, err := ensurePeerKey(p)
			if err != nil {
				return err
			}
			if name == "" {
				name = defaultSourceName()
			}
			if !validSourceName(name) {
				return fmt.Errorf("pair key: invalid name %q", name)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", name, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))))
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "name this box is known by on its peers (default: hostname)")
	return cmd
}

func pairAcceptCmd() *cobra.Command {
	var address string
	cmd := &cobra.Command{
		Use:   "accept <source-name> <public-key...>",
		Short: "Let a source box store its backups here (uploads only)",
		Args:  cobra.MinimumNArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := loadPaths()
			if err != nil {
				return err
			}
			spec, err := runPairAccept(p, args[0], strings.Join(args[1:], " "), address)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), spec)
			return nil
		},
	}
	cmd.Flags().StringVar(&address, "address", "", "address the source should push to (default: the address this ssh session reached)")
	return cmd
}

func runPairAccept(p paths, source, key, address string) (string, error) {
	if !validSourceName(source) {
		return "", fmt.Errorf("pair accept: invalid source name %q", source)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		return "", fmt.Errorf("pair accept: not an SSH public key: %w", err)
	}
	if cfg.TeamKey != "" && sameKey(parsed, cfg.TeamKey) {
		return "", fmt.Errorf("pair accept: that is the team key, not a box's backup key")
	}
	key = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(parsed)))

	user, err := opmenuUser()
	if err != nil {
		return "", err
	}
	if address == "" {
		address = localAddress()
	}
	if address == "" {
		return "", fmt.Errorf("pair accept: could not determine this box's address; pass --address")
	}
	hostKey, err := localHostKey()
	if err != nil {
		return "", err
	}

	next := cfg
	next.Sources = nil
	for _, src := range cfg.Sources {
		// Re-pairing a rebuilt source replaces its key but keeps its
		// directory, so its old backups are still there to retrieve.
		if src.Name != source {
			next.Sources = append(next.Sources, src)
		}
	}
	next.Sources = append(next.Sources, sourceConfig{Name: source, Key: key})
	if err := saveRuntimeConfig(p, next); err != nil {
		return "", err
	}
	if err := repairAccess(p); err != nil {
		return "", err
	}

	u := url.URL{Scheme: "ssh+receiver", User: url.User(user), Host: hostPort(address), Path: "/" + source}
	return u.String() + " " + hostKey, nil
}

func pairAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add <peer-url> [host-key...]",
		Short: "Push this box's backups to a peer that accepted it",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := loadPaths()
			if err != nil {
				return err
			}
			if err := runPairAdd(p, args[0], strings.Join(args[1:], " ")); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "paired: backups now replicate to %s\n", args[0])
			// Push straight away so a broken pairing shows up now.
			if err := runReplicate(); err != nil {
				fmt.Fprintf(os.Stderr, "warning: first push failed (the timer will retry): %v\n", err)
			}
			return nil
		},
	}
}

func runPairAdd(p paths, rawURL, hostKey string) error {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "ssh+receiver" && u.Scheme != "file") {
		return fmt.Errorf("pair add: %q is not an ssh+receiver:// or file:// URL", rawURL)
	}
	if u.Scheme == "ssh+receiver" {
		parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKey))
		if err != nil {
			return fmt.Errorf("pair add: host key: %w", err)
		}
		hostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(parsed)))
		if _, err := ensurePeerKey(p); err != nil {
			return err
		}
	} else {
		hostKey = ""
	}
	next := cfg
	next.Peers = nil
	for _, peer := range cfg.Peers {
		if peer.URL != rawURL {
			next.Peers = append(next.Peers, peer)
		}
	}
	next.Peers = append(next.Peers, peerConfig{URL: rawURL, HostKey: hostKey})
	if err := saveRuntimeConfig(p, next); err != nil {
		return err
	}
	return repairAccess(p)
}

func pairListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List peers this box pushes to and sources that push here",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			w := cmd.OutOrStdout()
			if len(cfg.Peers) == 0 {
				fmt.Fprintln(w, "peers: none")
			}
			for _, peer := range cfg.Peers {
				fmt.Fprintf(w, "peer   %s\n", peer.URL)
			}
			if len(cfg.Sources) == 0 {
				fmt.Fprintln(w, "sources: none")
			}
			for _, src := range cfg.Sources {
				fmt.Fprintf(w, "source %s\n", src.Name)
			}
			return nil
		},
	}
}

func pairRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <peer-url|source-name>",
		Short: "Stop pushing to a peer, or stop accepting a source (its stored copies stay)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := loadPaths()
			if err != nil {
				return err
			}
			next := cfg
			next.Peers, next.Sources = nil, nil
			removed := false
			for _, peer := range cfg.Peers {
				if peer.URL == args[0] {
					removed = true
					continue
				}
				next.Peers = append(next.Peers, peer)
			}
			for _, src := range cfg.Sources {
				if src.Name == args[0] {
					removed = true
					continue
				}
				next.Sources = append(next.Sources, src)
			}
			if !removed {
				return fmt.Errorf("pair remove: no peer or source %q", args[0])
			}
			if err := saveRuntimeConfig(p, next); err != nil {
				return err
			}
			return repairAccess(p)
		},
	}
}

// ensurePeerKey returns this box's backup key, generating it on first use.
func ensurePeerKey(p paths) (ssh.Signer, error) {
	if signer, err := loadPeerSignerAt(p.peerKeyPath); err == nil {
		return signer, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(p.dataDir, 0o700); err != nil {
		return nil, err
	}
	if err := fsutil.WriteFile(p.peerKeyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, err
	}
	return loadPeerSignerAt(p.peerKeyPath)
}

func loadPeerSigner() (ssh.Signer, error) {
	p, err := loadPaths()
	if err != nil {
		return nil, err
	}
	signer, err := loadPeerSignerAt(p.peerKeyPath)
	if err != nil {
		return nil, fmt.Errorf("replicate: no backup key on this box (run 'warden pair key'): %w", err)
	}
	return signer, nil
}

func loadPeerSignerAt(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}

func sameKey(a ssh.PublicKey, authorized string) bool {
	b, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorized))
	return err == nil && string(a.Marshal()) == string(b.Marshal())
}

func defaultSourceName() string {
	host, _ := os.Hostname()
	host = strings.SplitN(host, ".", 2)[0]
	var b strings.Builder
	for _, r := range host {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "box"
	}
	return b.String()
}

// localAddress is the address the current ssh client reached this box on,
// which is by construction one that other boxes on that network can use.
func localAddress() string {
	if fields := strings.Fields(os.Getenv("SSH_CONNECTION")); len(fields) == 4 {
		return fields[2]
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return ""
}

func hostPort(address string) string {
	if strings.Contains(address, ":") && net.ParseIP(address) != nil {
		return "[" + address + "]"
	}
	return address
}

var hostKeyPaths = []string{
	"/etc/ssh/ssh_host_ed25519_key.pub",
	"/etc/ssh/ssh_host_ecdsa_key.pub",
	"/etc/ssh/ssh_host_rsa_key.pub",
}

func localHostKey() (string, error) {
	for _, path := range hostKeyPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			continue
		}
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), nil
	}
	return "", fmt.Errorf("pair accept: no readable sshd host key under /etc/ssh")
}
