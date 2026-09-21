package main

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

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

	suspect, account, evidence, candidates := attributeChange(eventTime, now)

	fields := map[string]any{
		"path":     change.Path,
		"kind":     change.Kind,
		"evidence": evidence,
	}
	if suspect != "" {
		fields["suspect_ip"] = suspect
		fields["account"] = account
	}
	// When attribution was ambiguous, the candidate IPs go in as a
	// structured field rather than only inside the prose evidence
	// string. Opening a second throwaway root session from anywhere is
	// all it takes to push a change into this branch and suppress the
	// automatic ban (deliberately — see attributeChange), so the least
	// this can do is hand an operator the exact shortlist to act on:
	// `warden alerts` prints them, and `warden ban <ip>` takes it from
	// there.
	if suspect == "" && len(candidates) > 1 {
		fields["candidate_ips"] = candidates
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
// on record for it, a short human-readable note on how confident that is,
// and every non-team candidate IP it considered. It returns suspect=""
// whenever the evidence doesn't clearly point at one outside party —
// including "no auth log," "no session found," "the only session was the
// team's own," and "more than one candidate IP" — since a ban needs to be
// confident, not just plausible.
//
// The last of those is cheap for an attacker to force on purpose: a
// second root session open from anywhere else at the moment they touch a
// guarded file is enough to make this return no suspect. That's still the
// right call for an *automatic* ban (the alternative is banning an IP
// that might be the scoring engine's), but it's exactly why candidates
// comes back too — the flag, the log entry, and the shortlist all still
// happen, so a human loses nothing but the automation.
func attributeChange(eventTime, now time.Time) (suspect, account, evidence string, candidates []string) {
	sessions, err := authSessions(eventTime, now)
	if err != nil {
		return "", "", "could not read SSH attribution evidence: " + err.Error(), nil
	}

	// Recognize the team's key across all login accounts before limiting
	// suspects to root sessions. The opmenu account is not root, and its
	// source IP must still be excluded if another root session shares it.
	teamIPs := map[string]bool{}
	if key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(buildTeamPubKey)); err == nil {
		fingerprint := ssh.FingerprintSHA256(key)
		for _, s := range sessions {
			if s.KeyFingerprint == fingerprint {
				teamIPs[s.IP] = true
			}
		}
	}
	var rootSessions []attribution.Session
	for _, s := range sessions {
		if s.User == "root" {
			rootSessions = append(rootSessions, s)
		}
	}

	open := attribution.Overlapping(rootSessions, eventTime)

	var foreign []string
	for _, ip := range open {
		if !ipMatchesTeam(ip) && !teamIPs[ip] {
			foreign = append(foreign, ip)
		}
	}

	switch {
	case len(open) == 0:
		return "", "", "no root SSH session was open when this changed (console access, or the log doesn't cover it)", nil
	case len(foreign) == 0:
		return "", "", "all overlapping root IPs match the configured team address or a logged team key", nil
	case len(foreign) > 1:
		return "", "", fmt.Sprintf("more than one non-team IP had a session open (%v) — too ambiguous to single one out automatically; ban whichever is yours to ban with 'warden ban <ip>'", foreign), foreign
	default:
		ip := foreign[0]
		return ip, attribution.UserFor(rootSessions, ip, eventTime), "exactly one non-team root session was open at the time", foreign
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
