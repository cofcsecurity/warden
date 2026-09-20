package main

import (
	"fmt"
	"net"
	"time"

	"warden/internal/attribution"
	"warden/internal/audit"
	"warden/internal/autoban"
	"warden/internal/manifest"
)

// reactToGuardedChange is watch.go's hook for every ConfirmFirst change:
// it tries to identify who had a root SSH session open at the moment the
// file changed, and — only if that's an IP that's neither the team's own
// nor unidentifiable — bans it. It always logs a loud, distinct audit
// entry either way, since "warden alerts" (see alerts.go) surfaces
// exactly that entry to whoever's watching, regardless of whether a ban
// happened.
//
// The bar for actually banning is deliberately high: no evidence, or
// evidence that only points at the team's own key, means no ban. A wrong
// ban (locking out a teammate, or worse, the scoring engine) is a bigger
// self-inflicted loss than letting one suspicious change go un-banned —
// it still gets flagged and logged either way, for a human to act on.
func reactToGuardedChange(p paths, change manifest.Change, log *audit.Logger, now time.Time) error {
	eventTime := now
	if change.New != nil {
		eventTime = change.New.MTime
	}

	suspect, account, evidence := attributeChange(eventTime, now)

	fields := map[string]any{
		"path":     change.Path,
		"kind":     change.Kind,
		"evidence": evidence,
	}
	if suspect != "" {
		fields["suspect_ip"] = suspect
		fields["account"] = account
	}

	autobanned := false
	if suspect != "" && buildAutobanEnabled != "" {
		store := autoban.NewStore(p.bannedIPsPath)
		reason := fmt.Sprintf("touched guarded path %s as %q", change.Path, account)
		if err := autoban.Add(store, autoban.IPTables{}, suspect, reason, autobanDuration, now); err != nil {
			return fmt.Errorf("react: ban %s: %w", suspect, err)
		}
		autobanned = true
	}
	fields["autobanned"] = autobanned

	// "alert" is its own action name, distinct from watch's own
	// "flagged" — this is the entry warden alerts filters for, and it's
	// deliberately louder/more specific than the plain flag.
	return log.Log("react", "alert", fields)
}

// attributeChange returns the single non-team root IP that had a session
// open at eventTime, if exactly one exists, along with the account name
// on record for it and a short human-readable note on how confident that
// is. It returns suspect="" whenever the evidence doesn't clearly point at
// one outside party — including "no auth log," "no session found," "the
// only session was the team's own," and "more than one candidate IP" —
// since a ban needs to be confident, not just plausible.
func attributeChange(eventTime, now time.Time) (suspect, account, evidence string) {
	logPath, ok := findAuthLog()
	if !ok {
		return "", "", "no auth log found on this box (checked " + fmt.Sprint(authLogPaths) + ")"
	}

	sessions, err := attribution.SessionsFromAuthLog(logPath, now)
	if err != nil {
		return "", "", "could not read auth log: " + err.Error()
	}

	// Only root sessions matter here: the team's own forced-command entry
	// always logs in as root (see docs/DESIGN.md's opmenu section), and a
	// replication peer's inbound session authenticates as the
	// low-privilege warden-backup account, which is command="/usr/bin/false"
	// restricted and never touches a config-tier path — see
	// docs/DEPLOYMENT.md's receiving-account setup. Filtering to root
	// keeps those out of consideration entirely rather than needing to
	// know every peer's IP here.
	var rootSessions []attribution.Session
	for _, s := range sessions {
		if s.User == "root" {
			rootSessions = append(rootSessions, s)
		}
	}

	candidates := attribution.Overlapping(rootSessions, eventTime)

	var foreign []string
	for _, ip := range candidates {
		if !ipMatchesTeam(ip) {
			foreign = append(foreign, ip)
		}
	}

	switch {
	case len(candidates) == 0:
		return "", "", "no root SSH session was open when this changed (console access, or the log doesn't cover it)"
	case len(foreign) == 0:
		return "", "", fmt.Sprintf("only the team's own IP (%s) had a session open at the time", buildTeamFromIP)
	case len(foreign) > 1:
		return "", "", fmt.Sprintf("more than one non-team IP had a session open (%v) — too ambiguous to single one out", foreign)
	default:
		ip := foreign[0]
		return ip, attribution.UserFor(rootSessions, ip, eventTime), "exactly one non-team root session was open at the time"
	}
}

// ipMatchesTeam reports whether ip is (or falls inside, if
// buildTeamFromIP is a CIDR) the team's own configured source address.
func ipMatchesTeam(ip string) bool {
	if buildTeamFromIP == "" {
		return false
	}
	if ip == buildTeamFromIP {
		return true
	}
	if _, cidr, err := net.ParseCIDR(buildTeamFromIP); err == nil {
		if parsed := net.ParseIP(ip); parsed != nil {
			return cidr.Contains(parsed)
		}
	}
	return false
}
