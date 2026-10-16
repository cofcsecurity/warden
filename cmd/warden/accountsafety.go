package main

import (
	"fmt"
	"strings"

	"warden/internal/anomaly"
)

// hardProtectedAccounts returns account names that must NEVER be locked,
// no override possible: root (locking it out is catastrophic — no admin
// left on the box at all) and the opmenu account itself (locking it
// breaks Warden's whole access layer).
func hardProtectedAccounts() (map[string]bool, error) {
	opUser, err := opmenuUser()
	if err != nil {
		return nil, err
	}
	m := map[string]bool{"root": true, opUser: true}
	if cfg.BreakGlassUser != "" {
		m[cfg.BreakGlassUser] = true
	}
	return m, nil
}

// configuredSafeAccounts is the config's safe_accounts list: the team's
// own operating accounts and any scoring accounts. A human can override it
// with --force; hardProtectedAccounts has no override.
func configuredSafeAccounts() map[string]bool {
	m := map[string]bool{}
	for _, a := range cfg.SafeAccounts {
		a = strings.TrimSpace(a)
		if a != "" {
			m[a] = true
		}
	}
	return m
}

// canLockAccount reports whether user is safe to lock. Checked in order:
// a genuine local account first (accountlock's Lock is nothing but
// `passwd`/`usermod` against local files — it does nothing meaningful
// against a domain-backed account, Active Directory via sssd/winbind or
// LDAP, so this is never overridable, technical fact rather than
// policy); then hardProtectedAccounts (also never overridable); then
// configuredSafeAccounts, which force bypasses. ok=false always comes
// with a human-readable reason — scan.go and lockaccount.go both still
// want to record *why* a finding with a culprit didn't result in a lock.
func canLockAccount(user string, force bool) (ok bool, reason string, err error) {
	if user == "" {
		return false, "no account could be attributed to this finding", nil
	}

	local, err := anomaly.IsLocalAccount(user, "/etc/passwd")
	if err != nil {
		return false, "", err
	}
	if !local {
		return false, fmt.Sprintf("%s isn't a local account (likely Active Directory/directory-backed) — a local lock has no effect on it; lock it down in Active Directory (or whatever directory service backs it) instead", user), nil
	}

	hard, err := hardProtectedAccounts()
	if err != nil {
		return false, "", err
	}
	if hard[user] {
		return false, fmt.Sprintf("%s is root or one of Warden's access accounts — never locked, no override", user), nil
	}

	if configuredSafeAccounts()[user] && !force {
		return false, fmt.Sprintf("%s is in the configured safe_accounts — re-run with --force if this is genuinely wrong", user), nil
	}

	return true, "", nil
}
