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
// last run, any existing local account or group *modified* since then,
// and separately, any *domain-backed* account (Active Directory via
// sssd/winbind, LDAP, ...) that newly resolves through NSS.
//
// A brand-new account is itself the finding — nothing else needs to have
// happened for its mere appearance to be worth flagging. Modification
// matters just as much, and used not to be checked at all: the actual
// privilege-escalation moves against an existing account — setting its
// UID to 0, giving a service account a real login shell, adding someone
// to sudo/wheel — never change a single name, so a check that only
// diffed names saw nothing at all.
func CheckAccounts(baselineDir, passwdPath, groupPath string) ([]Finding, error) {
	var findings []Finding

	localUsers, err := colonFileEntries(passwdPath)
	if err != nil {
		return nil, err
	}
	localSet := map[string]bool{}
	for _, u := range localUsers {
		localSet[u.name] = true
	}

	uf, err := diffAccountEntries(filepath.Join(baselineDir, "accounts-users.json"), localUsers, passwdFields,
		func(e colonEntry) Finding {
			return Finding{
				Check:       "accounts",
				Description: fmt.Sprintf("new local user account: %s", e.name),
				Detail:      passwdPath,
				Culprit:     e.name,
			}
		},
		func(e colonEntry, changes []string) Finding {
			// Culprit is the modified account itself, same as for a
			// brand-new one: whoever's UID just became 0 is the account
			// that now has root, whatever put it there.
			return Finding{
				Check:       "accounts",
				Description: fmt.Sprintf("existing local account modified: %s (%s)", e.name, strings.Join(changes, "; ")),
				Detail:      passwdPath,
				Culprit:     e.name,
			}
		})
	if err != nil {
		return nil, err
	}
	findings = append(findings, uf...)

	groups, err := colonFileEntries(groupPath)
	if err != nil {
		return nil, err
	}
	gf, err := diffAccountEntries(filepath.Join(baselineDir, "accounts-groups.json"), groups, groupFields,
		func(e colonEntry) Finding {
			// No Culprit: a group isn't an account accountlock can do
			// anything with, only its own appearance is the signal.
			return Finding{
				Check:       "accounts",
				Description: fmt.Sprintf("new local group: %s", e.name),
				Detail:      groupPath,
			}
		},
		func(e colonEntry, changes []string) Finding {
			// Still no Culprit, for a subtler reason than above: a
			// membership line says who was *added to* the group, not who
			// did the adding, and "locked the account someone else just
			// put in wheel" is exactly the kind of confident-but-wrong
			// reaction docs/DESIGN.md rules out. Flagged loudly, left to
			// a human.
			return Finding{
				Check:       "accounts",
				Description: fmt.Sprintf("local group modified: %s (%s)", e.name, strings.Join(changes, "; ")),
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
		for _, e := range colonLineEntries(out) {
			if !localSet[e.name] {
				domainUsers = append(domainUsers, e.name)
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
// then saves names as the new baseline. Used for accounts whose contents
// this box isn't authoritative for (domain/directory-backed ones, whose
// real state lives on a domain controller) — for local accounts, see
// diffAccountEntries, which also catches in-place modification. On the
// very first run (no baseline file yet), it seeds the baseline and
// reports nothing — see firstRun's doc comment for why.
func diffAccountNames(baselinePath string, names []string, describe func(name string) Finding) ([]Finding, error) {
	bootstrap := firstRun(baselinePath)
	old, err := loadBaseline(baselinePath)
	if err != nil {
		return nil, err
	}

	var findings []Finding
	next := baseline{}
	for _, name := range names {
		next[name] = legacyPresenceValue
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

// accountField names one colon-separated field worth watching for
// change, by its index in the line. Deliberately not every field: GECOS
// churns for entirely boring reasons, and the password column of
// /etc/passwd and /etc/group is an "x" placeholder on any modern box
// (the real hash is in shadow/gshadow, which watch already guards as a
// ConfirmFirst path).
type accountField struct {
	index int
	name  string
}

// passwdFields and groupFields are the privilege-relevant columns: UID 0
// or a group membership is what actually grants power, and a login shell
// is what makes a service account usable as one.
var (
	passwdFields = []accountField{{2, "uid"}, {3, "gid"}, {5, "home"}, {6, "shell"}}
	groupFields  = []accountField{{2, "gid"}, {3, "members"}}
)

// colonEntry is one parsed line of a /etc/passwd- or /etc/group-format
// file: its name (first field) and every field as read.
type colonEntry struct {
	name   string
	fields []string
}

// field returns the value at index, or "" when the line is short — a
// malformed or truncated line reads as empty rather than panicking, and
// an empty-to-nonempty transition is itself reported as a change.
func (e colonEntry) field(index int) string {
	if index >= len(e.fields) {
		return ""
	}
	return e.fields[index]
}

// state renders the watched fields of an entry as the baseline value
// stored for it. Stored in the clear rather than hashed, so a finding can
// say "uid 1000 -> 0" instead of only "something changed" — these lines
// hold no secrets (the password hashes live in shadow/gshadow, which this
// never reads).
func (e colonEntry) state(fields []accountField) string {
	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		parts = append(parts, f.name+"="+e.field(f.index))
	}
	return strings.Join(parts, " ")
}

// diffAccountEntries reports a Finding for every entry that's new since
// the last run (via describeNew) and for every entry whose watched
// fields changed in place (via describeChanged, which also gets a
// human-readable list of what moved). Entries that disappeared are just
// dropped from the baseline, matching the rest of this package.
func diffAccountEntries(
	baselinePath string,
	entries []colonEntry,
	fields []accountField,
	describeNew func(colonEntry) Finding,
	describeChanged func(colonEntry, []string) Finding,
) ([]Finding, error) {
	bootstrap := firstRun(baselinePath)
	old, err := loadBaseline(baselinePath)
	if err != nil {
		return nil, err
	}

	var findings []Finding
	next := baseline{}
	for _, e := range entries {
		state := e.state(fields)
		next[e.name] = state
		if bootstrap {
			continue
		}

		previous, existed := old[e.name]
		switch {
		case !existed:
			findings = append(findings, describeNew(e))
		case previous == legacyPresenceValue:
			// Upgraded from a name-only baseline: nothing to compare
			// against, so record today's state and start watching from
			// here rather than reporting every account as modified.
		case previous != state:
			if changes := describeStateChange(previous, state); len(changes) > 0 {
				findings = append(findings, describeChanged(e, changes))
			}
		}
	}

	if err := saveBaseline(baselinePath, next); err != nil {
		return nil, err
	}
	return findings, nil
}

// describeStateChange turns two "uid=0 gid=0 ..." states into one
// "uid 1000 -> 0" phrase per field that actually moved.
func describeStateChange(previous, current string) []string {
	oldFields := parseState(previous)
	var changes []string
	for _, pair := range strings.Split(current, " ") {
		name, value, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		if was, seen := oldFields[name]; seen && was != value {
			changes = append(changes, fmt.Sprintf("%s %s -> %s", name, quoteEmpty(was), quoteEmpty(value)))
		}
	}
	return changes
}

func parseState(state string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(state, " ") {
		if name, value, ok := strings.Cut(pair, "="); ok {
			out[name] = value
		}
	}
	return out
}

func quoteEmpty(s string) string {
	if s == "" {
		return `""`
	}
	return s
}

// colonFileFirstFields reads a colon-delimited file in /etc/passwd or
// /etc/group's format and returns the first field (name) of each real
// entry, skipping blank lines and comments.
func colonFileFirstFields(path string) ([]string, error) {
	entries, err := colonFileEntries(path)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.name)
	}
	return names, nil
}

// colonFileEntries is colonFileFirstFields with every field kept, for the
// checks that need to notice a line changing rather than appearing.
func colonFileEntries(path string) ([]colonEntry, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("anomaly: read %s: %w", path, err)
	}
	return colonLineEntries(data), nil
}

// colonLineEntries is colonFileEntries' parsing half, split out so getent
// passwd's output (already in memory, not a file on disk) goes through
// the exact same parsing as the real file.
func colonLineEntries(data []byte) []colonEntry {
	var entries []colonEntry
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if fields[0] == "" {
			continue
		}
		entries = append(entries, colonEntry{name: fields[0], fields: fields})
	}
	return entries
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
