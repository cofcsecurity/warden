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
	return map[string]bool{"root": true, opUser: true}, nil
}

// configuredSafeAccounts parses buildSafeAccounts — the team's own
// operating account(s) on this box, and the scoring engine's account if
// it uses one. Unlike hardProtectedAccounts, this is a team-supplied
// policy choice, not a technical impossibility, so a human operator can
// override it with --force (canLockAccount's force param) — there's no
// equivalent override for hardProtectedAccounts. See buildSafeAccounts'
// doc comment in main.go for why this can't be inferred automatically
// the way TEAM_FROM_IP lets IP-autoban exclude the team's own address.
func configuredSafeAccounts() map[string]bool {
	m := map[string]bool{}
	for _, a := range strings.Split(buildSafeAccounts, ",") {
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
		return false, fmt.Sprintf("%s is root or the opmenu account itself — never locked, no override", user), nil
	}

	if configuredSafeAccounts()[user] && !force {
		return false, fmt.Sprintf("%s is on the configured SAFE_ACCOUNTS list — re-run with --force if this is genuinely wrong", user), nil
	}

	return true, "", nil
}
