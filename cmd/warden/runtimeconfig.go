package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"warden/internal/fsutil"
)

// runtimeConfig is everything that used to be baked in with -ldflags. It is
// written by `warden install` on the box itself and read on every
// invocation, so nothing per-competition is ever compiled in or committed:
// a plain clone builds a binary with nothing worth stealing in it.
//
// The only secret this box needs is the private half of the team key, and
// that never comes here. TeamKey is the public half.
type runtimeConfig struct {
	// TeamKey is the team's SSH public key, in authorized_keys format.
	TeamKey string `json:"team_key"`
	// AllowFrom restricts where TeamKey may connect from: a comma-separated
	// list of addresses or CIDRs, in sshd's from= syntax, or "any".
	AllowFrom string `json:"allow_from"`
	// BreakGlassUser is the second, independent access account (see
	// access.go). Empty disables break-glass.
	BreakGlassUser string `json:"break_glass_user,omitempty"`
	// Ban and Lock select the response mode for IP bans and account locks:
	// off, flag (log what would happen, change nothing) or act.
	Ban  string `json:"ban"`
	Lock string `json:"lock"`
	// SafeAccounts are never locked, in any mode.
	SafeAccounts []string `json:"safe_accounts,omitempty"`
	// Peers receive this box's backups (see pair.go).
	Peers []peerConfig `json:"peers,omitempty"`
	// Sources are boxes that back up to this one. Each source's key may
	// only run `receive` into its own directory.
	Sources []sourceConfig `json:"sources,omitempty"`
	// PeerQuotaMB caps how much each source may store on this box when it
	// acts as a backup peer. Zero means the default.
	PeerQuotaMB int `json:"peer_quota_mb,omitempty"`
}

type sourceConfig struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type peerConfig struct {
	URL     string `json:"url"`
	HostKey string `json:"host_key,omitempty"`
}

const (
	modeOff  = "off"
	modeFlag = "flag"
	modeAct  = "act"

	allowAny = "any"

	defaultPeerQuotaMB = 2048
)

// cfg is the loaded configuration for this invocation. Commands read it
// directly; tests set its fields.
var cfg = defaultRuntimeConfig()

func defaultRuntimeConfig() runtimeConfig {
	return runtimeConfig{Ban: modeFlag, Lock: modeFlag}
}

// configPath is the primary copy, inside the state directory. A mirror next
// to the spare binary lets sentinel rebuild access if the state directory
// is deleted.
func (p paths) configPath() string { return filepath.Join(p.dataDir, "config.json") }

func (p paths) configMirrorPath() string { return filepath.Join(p.mirrorDir, "config.json") }

// loadRuntimeConfig reads the primary config, falling back to the mirror.
// A missing config leaves the defaults in place: an uninstalled dev build
// still runs its read-only commands.
func loadRuntimeConfig(p paths) error {
	for _, path := range []string{p.configPath(), p.configMirrorPath()} {
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("config: read %s: %w", path, err)
		}
		c, err := parseRuntimeConfig(data)
		if err != nil {
			// A damaged primary must not lock anyone out while the
			// mirror is intact.
			fmt.Fprintf(os.Stderr, "warning: %s: %v\n", path, err)
			continue
		}
		cfg = c
		return nil
	}
	return nil
}

func parseRuntimeConfig(data []byte) (runtimeConfig, error) {
	c := defaultRuntimeConfig()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return runtimeConfig{}, fmt.Errorf("config: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return runtimeConfig{}, fmt.Errorf("config: expected one JSON object")
	}
	if err := c.validate(); err != nil {
		return runtimeConfig{}, err
	}
	return c, nil
}

func (c runtimeConfig) validate() error {
	if c.TeamKey != "" {
		if err := validateTeamKey(c.TeamKey); err != nil {
			return err
		}
	}
	if c.AllowFrom != "" {
		if err := validateAllowFrom(c.AllowFrom); err != nil {
			return err
		}
	}
	if c.BreakGlassUser != "" && !validAccountName(c.BreakGlassUser) {
		return fmt.Errorf("config: invalid break_glass_user %q", c.BreakGlassUser)
	}
	for name, mode := range map[string]string{"ban": c.Ban, "lock": c.Lock} {
		if mode != modeOff && mode != modeFlag && mode != modeAct {
			return fmt.Errorf("config: %s must be off, flag or act (got %q)", name, mode)
		}
	}
	for _, a := range c.SafeAccounts {
		if !validAccountName(a) {
			return fmt.Errorf("config: invalid safe account %q", a)
		}
	}
	for _, peer := range c.Peers {
		if peer.URL == "" || strings.ContainsAny(peer.URL, " \t\n") {
			return fmt.Errorf("config: invalid peer url %q", peer.URL)
		}
	}
	for _, src := range c.Sources {
		if !validSourceName(src.Name) {
			return fmt.Errorf("config: invalid source name %q", src.Name)
		}
		if err := validateTeamKey(src.Key); err != nil {
			return fmt.Errorf("config: source %s: %w", src.Name, err)
		}
	}
	if c.PeerQuotaMB < 0 {
		return fmt.Errorf("config: peer_quota_mb cannot be negative")
	}
	return nil
}

// saveRuntimeConfig writes the primary copy and its mirror.
func saveRuntimeConfig(p paths, c runtimeConfig) error {
	if err := c.validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	for _, path := range []string{p.configPath(), p.configMirrorPath()} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if err := fsutil.WriteFile(path, data, 0o600); err != nil {
			return fmt.Errorf("config: write %s: %w", path, err)
		}
	}
	cfg = c
	return nil
}

func validateTeamKey(key string) error {
	if strings.ContainsAny(strings.TrimSpace(key), "\n\r") {
		return fmt.Errorf("config: team_key must be a single public key line")
	}
	parsed, _, options, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		return fmt.Errorf("config: team_key is not an SSH public key: %w", err)
	}
	if len(options) > 0 {
		return fmt.Errorf("config: team_key must not carry authorized_keys options")
	}
	_ = parsed
	return nil
}

// validateAllowFrom accepts "any" or a comma-separated list of IPs and
// CIDRs. Hostnames and wildcards are refused: they are easy to get wrong
// and easy for red to spoof via DNS.
func validateAllowFrom(s string) error {
	if s == allowAny {
		return nil
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if net.ParseIP(part) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(part); err == nil {
			continue
		}
		return fmt.Errorf("config: allow_from entry %q is not an IP or CIDR (use %q for no restriction)", part, allowAny)
	}
	return nil
}

// validSourceName keeps a source name safe as a directory name and as a
// forced-command argument.
func validSourceName(name string) bool {
	if name == "" || len(name) > 64 || name[0] == '-' || name[0] == '.' {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

func validAccountName(name string) bool {
	if name == "" || len(name) > 32 || name[0] == '-' {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// configuredPeers returns the replication peers in the form the transport
// code uses.
func configuredPeers() []replicateTarget {
	out := make([]replicateTarget, 0, len(cfg.Peers))
	for _, peer := range cfg.Peers {
		out = append(out, replicateTarget{url: peer.URL, hostKey: peer.HostKey})
	}
	return out
}

func peerQuotaBytes() int64 {
	mb := cfg.PeerQuotaMB
	if mb == 0 {
		mb = defaultPeerQuotaMB
	}
	return int64(mb) << 20
}

// teamNetworkContains reports whether ip is inside the configured team
// network. "any" never matches: with no restriction there is no team
// network to exempt, only the team key.
func teamNetworkContains(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil || cfg.AllowFrom == "" || cfg.AllowFrom == allowAny {
		return false
	}
	for _, part := range strings.Split(cfg.AllowFrom, ",") {
		part = strings.TrimSpace(part)
		if other := net.ParseIP(part); other != nil && other.Equal(parsed) {
			return true
		}
		if _, cidr, err := net.ParseCIDR(part); err == nil && cidr.Contains(parsed) {
			return true
		}
	}
	return false
}
