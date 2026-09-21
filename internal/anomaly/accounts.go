package anomaly

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// getentPasswd resolves every account NSS knows about, local or
// directory-backed (sssd/winbind against Active Directory, LDAP, ...) —
// a var so tests can fake it without a real getent binary or NSS setup.
// A box with no directory service joined, or no getent at all, just
// means this signal isn't available; CheckAccounts treats that as
// "nothing extra to check," not an error.
var getentPasswd = func() ([]byte, error) {
	return exec.Command("getent", "passwd").Output()
}

// CheckAccounts flags any local user or group that didn't exist as of the
// last run, and separately, any *domain-backed* account (Active
// Directory via sssd/winbind, LDAP, ...) that newly resolves through NSS.
// A brand-new account is itself the finding — nothing else needs to have
// happened for its mere appearance to be worth flagging.
func CheckAccounts(baselineDir, passwdPath, groupPath string) ([]Finding, error) {
	var findings []Finding

	localUsers, err := colonFileFirstFields(passwdPath)
	if err != nil {
		return nil, err
	}
	localSet := map[string]bool{}
	for _, n := range localUsers {
		localSet[n] = true
	}

	uf, err := diffAccountNames(filepath.Join(baselineDir, "accounts-users.json"), localUsers,
		func(name string) Finding {
			return Finding{
				Check:       "accounts",
				Description: fmt.Sprintf("new local user account: %s", name),
				Detail:      passwdPath,
				Culprit:     name,
			}
		})
	if err != nil {
		return nil, err
	}
	findings = append(findings, uf...)

	groups, err := colonFileFirstFields(groupPath)
	if err != nil {
		return nil, err
	}
	gf, err := diffAccountNames(filepath.Join(baselineDir, "accounts-groups.json"), groups,
		func(name string) Finding {
			// No Culprit: a group isn't an account accountlock can do
			// anything with, only its own appearance is the signal.
			return Finding{
				Check:       "accounts",
				Description: fmt.Sprintf("new local group: %s", name),
				Detail:      groupPath,
			}
		})
	if err != nil {
		return nil, err
	}
	findings = append(findings, gf...)

	// Domain-backed accounts never appear in the raw passwd FILE at all —
	// NSS resolves them dynamically through sssd/winbind/LDAP, not from a
	// static line accountlock or anything else here can read directly.
	// `getent passwd` walks the full nsswitch chain, so anything it
	// reports that ISN'T in the raw file is, by construction, not local.
	// accountlock's Lock (passwd -l / usermod -s) only ever touches local
	// account state — it does nothing meaningful against one of these —
	// so these are flagged with no Culprit (scan.go never attempts an
	// auto-lock here) and a Description that tells a human exactly where
	// the real control actually is.
	if out, err := getentPasswd(); err == nil {
		var domainUsers []string
		for _, name := range colonLinesFirstFields(out) {
			if !localSet[name] {
				domainUsers = append(domainUsers, name)
			}
		}
		df, err := diffAccountNames(filepath.Join(baselineDir, "accounts-domain-users.json"), domainUsers,
			func(name string) Finding {
				return Finding{
					Check: "accounts",
					Description: fmt.Sprintf(
						"new domain/directory-backed account: %s — this is a cloud/AD user, not a local Linux account (it doesn't appear in %s); a local account lock has no effect on it — lock this user down in Active Directory (or whatever directory service backs it) instead",
						name, passwdPath,
					),
					Detail: "resolved via getent passwd, absent from " + passwdPath,
				}
			})
		if err != nil {
			return nil, err
		}
		findings = append(findings, df...)
	}

	return findings, nil
}

// diffAccountNames reports one Finding (built by describe) for every name
// in names that wasn't present in the baseline recorded at baselinePath,
// then saves names as the new baseline. On the very first run (no
// baseline file yet), it seeds the baseline and reports nothing — see
// firstRun's doc comment for why.
func diffAccountNames(baselinePath string, names []string, describe func(name string) Finding) ([]Finding, error) {
	bootstrap := firstRun(baselinePath)
	old, err := loadBaseline(baselinePath)
	if err != nil {
		return nil, err
	}

	var findings []Finding
	next := baseline{}
	for _, name := range names {
		next[name] = "1"
		if bootstrap {
			continue
		}
		if _, existed := old[name]; existed {
			continue
		}
		findings = append(findings, describe(name))
	}

	if err := saveBaseline(baselinePath, next); err != nil {
		return nil, err
	}
	return findings, nil
}

// colonFileFirstFields reads a colon-delimited file in /etc/passwd or
// /etc/group's format and returns the first field (name) of each real
// entry, skipping blank lines and comments.
func colonFileFirstFields(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("anomaly: read %s: %w", path, err)
	}
	return colonLinesFirstFields(data), nil
}

// colonLinesFirstFields is colonFileFirstFields' parsing half, split out
// so getent passwd's output (already in memory, not a file on disk) goes
// through the exact same parsing as the real file.
func colonLinesFirstFields(data []byte) []string {
	var names []string
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, ":", 2)
		if fields[0] == "" {
			continue
		}
		names = append(names, fields[0])
	}
	return names
}

// IsLocalAccount reports whether username is a genuine local account —
// present in the raw passwdPath file itself, not just resolvable through
// NSS (which would also match a domain-backed account via sssd/winbind,
// LDAP, ...). Anything that's about to modify local account state — in
// particular accountlock's Lock, which is only ever `passwd`/`usermod`
// against local files — must check this first: attempting to lock a
// domain account either fails outright or does nothing effective, since
// its real, authoritative state lives on the domain controller, not on
// this box. Other checks in this package (suid.go's file-owner lookup,
// cron.go/authorizedkeys.go's per-account culprit) all resolve a
// username the same NSS-backed way `getent`/`id` would, so any of their
// Culprit values can be a domain account too, not just CheckAccounts' own
// — callers must run every non-empty Culprit through this gate before
// acting on it, not just ones this file produced.
func IsLocalAccount(username, passwdPath string) (bool, error) {
	names, err := colonFileFirstFields(passwdPath)
	if err != nil {
		return false, err
	}
	for _, n := range names {
		if n == username {
			return true, nil
		}
	}
	return false, nil
}
