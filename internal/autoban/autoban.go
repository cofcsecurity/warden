// Package autoban tracks temporary IP bans and keeps a firewall in sync
// with them. It never decides *who* to ban — that judgment call (checking
// an IP isn't the team's own, isn't a replication peer, and actually
// overlapped a guarded file changing) belongs to the caller, in
// cmd/warden. This package only ever does what it's told: persist a ban,
// apply/remove the corresponding firewall rule, and expire it on schedule.
package autoban

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// Ban is one active or expired IP ban.
type Ban struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	BannedAt  time.Time `json:"banned_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Expired reports whether the ban's window has passed as of now.
func (b Ban) Expired(now time.Time) bool {
	return now.After(b.ExpiresAt)
}

// Firewall is the actual block/unblock mechanism. An interface so
// Reconcile is testable without running as root or touching real
// iptables rules.
type Firewall interface {
	Block(ip string) error
	Unblock(ip string) error
}

// IPTables blocks by inserting (idempotently) a DROP rule for the source
// IP at the top of the INPUT chain, and removes it the same way restore
// and sentinel already make their one shell-out exception each (see
// docs/DESIGN.md) — there's no way to touch netfilter rules from the
// standard library alone.
type IPTables struct{}

func (IPTables) Block(ip string) error {
	// -C checks whether the rule already exists; only insert if it
	// doesn't, so calling Block repeatedly (every sentinel-check pass,
	// by design — see Reconcile) never stacks duplicate rules.
	if err := exec.Command("iptables", "-C", "INPUT", "-s", ip, "-j", "DROP").Run(); err == nil {
		return nil
	}
	out, err := exec.Command("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP").CombinedOutput()
	if err != nil {
		return fmt.Errorf("autoban: iptables block %s: %w: %s", ip, err, out)
	}
	return nil
}

func (IPTables) Unblock(ip string) error {
	out, err := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP").CombinedOutput()
	if err != nil {
		// Already gone (e.g. removed by hand, or a prior partial
		// Reconcile) is not a failure worth surfacing.
		if err := exec.Command("iptables", "-C", "INPUT", "-s", ip, "-j", "DROP").Run(); err != nil {
			return nil
		}
		return fmt.Errorf("autoban: iptables unblock %s: %w: %s", ip, err, out)
	}
	return nil
}

// Store persists the ban list as JSON. Not a manifest/store object —
// bans aren't backup content, just small local state.
type Store struct {
	path string
}

func NewStore(path string) *Store {
	return &Store{path: path}
}

// Load returns the persisted ban list, or an empty one if the file
// doesn't exist yet.
func (s *Store) Load() ([]Ban, error) {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("autoban: read %s: %w", s.path, err)
	}
	var bans []Ban
	if err := json.Unmarshal(data, &bans); err != nil {
		return nil, fmt.Errorf("autoban: parse %s: %w", s.path, err)
	}
	return bans, nil
}

func (s *Store) Save(bans []Ban) error {
	data, err := json.MarshalIndent(bans, "", "  ")
	if err != nil {
		return fmt.Errorf("autoban: encode: %w", err)
	}
	if err := os.WriteFile(s.path, data, 0o600); err != nil {
		return fmt.Errorf("autoban: write %s: %w", s.path, err)
	}
	return nil
}

// Add records a new ban and applies it immediately. Banning an IP that's
// already banned refreshes its expiry rather than adding a duplicate
// entry.
func Add(store *Store, fw Firewall, ip, reason string, duration time.Duration, now time.Time) error {
	bans, err := store.Load()
	if err != nil {
		return err
	}

	found := false
	for i := range bans {
		if bans[i].IP == ip {
			bans[i].Reason = reason
			bans[i].BannedAt = now
			bans[i].ExpiresAt = now.Add(duration)
			found = true
			break
		}
	}
	if !found {
		bans = append(bans, Ban{IP: ip, Reason: reason, BannedAt: now, ExpiresAt: now.Add(duration)})
	}

	if err := fw.Block(ip); err != nil {
		return err
	}
	return store.Save(bans)
}

// Remove un-bans ip immediately, regardless of its expiry.
func Remove(store *Store, fw Firewall, ip string) error {
	bans, err := store.Load()
	if err != nil {
		return err
	}

	kept := bans[:0]
	for _, b := range bans {
		if b.IP != ip {
			kept = append(kept, b)
		}
	}

	if err := fw.Unblock(ip); err != nil {
		return err
	}
	return store.Save(kept)
}

// Reconcile re-applies every still-active ban's firewall rule (in case it
// was flushed — e.g. a reboot, or red team running `iptables -F`) and
// removes anything expired. Meant to be called on sentinel-check's
// schedule, the same "reassert desired state every pass" pattern the rest
// of sentinel already follows.
func Reconcile(store *Store, fw Firewall, now time.Time) (active []string, expired []string, err error) {
	bans, err := store.Load()
	if err != nil {
		return nil, nil, err
	}

	var kept []Ban
	for _, b := range bans {
		if b.Expired(now) {
			if err := fw.Unblock(b.IP); err != nil {
				return active, expired, err
			}
			expired = append(expired, b.IP)
			continue
		}
		if err := fw.Block(b.IP); err != nil {
			return active, expired, err
		}
		active = append(active, b.IP)
		kept = append(kept, b)
	}

	if err := store.Save(kept); err != nil {
		return active, expired, err
	}
	return active, expired, nil
}
