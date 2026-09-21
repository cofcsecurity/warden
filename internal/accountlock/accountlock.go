// Package accountlock tracks local-account lockouts and keeps
// the box's actual account state in sync with them. Mirrors
// internal/autoban's shape exactly (Store/Add/Remove/Reconcile), just for
// a local account instead of a firewalled IP. It never decides *who* to
// lock — that judgment call belongs to the caller, in cmd/warden — this
// package only ever does what it's told: persist a lock, apply/remove the
// corresponding account state, and expire it on schedule.
package accountlock

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Lock is one active or expired account lockout.
type Lock struct {
	User      string    `json:"user"`
	Reason    string    `json:"reason"`
	LockedAt  time.Time `json:"locked_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// PreviousShell is what the account's login shell was before locking,
	// so Unlock restores it rather than guessing.
	PreviousShell string `json:"previous_shell"`
}

// Expired reports whether a timed lock has elapsed. A zero expiry is indefinite.
func (l Lock) Expired(now time.Time) bool {
	return !l.ExpiresAt.IsZero() && !now.Before(l.ExpiresAt)
}

// System is the actual lock/unlock/kill mechanism. An interface so
// Reconcile is testable without running as root or touching real
// accounts.
type System interface {
	// Lock disables user's login — both password auth and interactive
	// shell access, since a password lock alone doesn't stop SSH-key-based
	// login — and reports the shell it had before locking.
	Lock(user string) (previousShell string, err error)
	// Unlock restores password auth and sets the shell back to shell
	// (the PreviousShell a prior Lock call reported).
	Unlock(user, shell string) error
	// KillSessions best-effort terminates user's currently running
	// processes/sessions. Never an error just because there's nothing to
	// kill.
	KillSessions(user string) error
}

// OSAccounts is the real System, via passwd/usermod/pkill — there's no way
// to lock a local account or read/restore its shell from the standard
// library alone, the same reasoning autoban's IPTables shells out for
// firewall rules.
type OSAccounts struct {
	// NologinShell is the shell Lock assigns, e.g. /usr/sbin/nologin —
	// blocks any interactive shell regardless of which auth method got
	// someone in, unlike a password lock alone.
	NologinShell string
}

func (o OSAccounts) Lock(user string) (string, error) {
	previous, err := currentShell(user)
	if err != nil {
		return "", err
	}
	// If the account is *already* shut out — a lock this box's store no
	// longer knows about (the JSON was deleted or restored from an older
	// copy), or an account the team themselves disabled — then its
	// current shell is not a shell worth restoring. Recording it would
	// make the eventual Unlock "restore" the account to nologin
	// permanently, which reads as Warden having silently kept it locked
	// forever. Recording nothing instead means Unlock leaves the shell
	// alone for a human to set, which is recoverable.
	if isNoLoginShell(previous, o.NologinShell) {
		previous = ""
	}
	if out, err := exec.Command("passwd", "-l", user).CombinedOutput(); err != nil {
		return "", fmt.Errorf("accountlock: passwd -l %s: %w: %s", user, err, out)
	}
	if out, err := exec.Command("usermod", "-s", o.NologinShell, user).CombinedOutput(); err != nil {
		return "", fmt.Errorf("accountlock: usermod -s %s %s: %w: %s", o.NologinShell, user, err, out)
	}
	return previous, nil
}

func (o OSAccounts) Unlock(user, shell string) error {
	if out, err := exec.Command("passwd", "-u", user).CombinedOutput(); err != nil {
		return fmt.Errorf("accountlock: passwd -u %s: %w: %s", user, err, out)
	}
	if shell == "" {
		return nil
	}
	if out, err := exec.Command("usermod", "-s", shell, user).CombinedOutput(); err != nil {
		return fmt.Errorf("accountlock: usermod -s %s %s: %w: %s", shell, user, err, out)
	}
	return nil
}

func (o OSAccounts) KillSessions(user string) error {
	// Exit status alone doesn't distinguish "nothing to kill" (pkill's
	// normal outcome once Lock has already shut the account out) from a
	// real failure, and killing sessions is best-effort on top of the
	// account lock itself, not the primary control — never surfaced as
	// an error either way.
	_ = exec.Command("pkill", "-KILL", "-u", user).Run()
	return nil
}

// isNoLoginShell reports whether shell is one of the conventional "this
// account cannot log in" shells, including whichever one this box uses
// for locking (nologinShell, from units.go's nologinShellPath).
func isNoLoginShell(shell, nologinShell string) bool {
	if shell == "" {
		return true
	}
	if nologinShell != "" && shell == nologinShell {
		return true
	}
	switch shell {
	case "/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false":
		return true
	}
	return false
}

// currentShell reads user's login shell straight out of /etc/passwd —
// there's no other portable way to learn it before Lock overwrites it.
func currentShell(user string) (string, error) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return "", fmt.Errorf("accountlock: read /etc/passwd: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 7 && fields[0] == user {
			return fields[6], nil
		}
	}
	return "", fmt.Errorf("accountlock: user %q not found in /etc/passwd", user)
}

// Store persists the lock list as JSON. Not a manifest/store object —
// locks aren't backup content, just small local state.
type Store struct {
	path string
}

func NewStore(path string) *Store {
	return &Store{path: path}
}

// Load returns the persisted lock list, or an empty one if the file
// doesn't exist yet.
func (s *Store) Load() ([]Lock, error) {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("accountlock: read %s: %w", s.path, err)
	}
	var locks []Lock
	if err := json.Unmarshal(data, &locks); err != nil {
		return nil, fmt.Errorf("accountlock: parse %s: %w", s.path, err)
	}
	return locks, nil
}

func (s *Store) Save(locks []Lock) error {
	data, err := json.MarshalIndent(locks, "", "  ")
	if err != nil {
		return fmt.Errorf("accountlock: encode: %w", err)
	}
	if err := os.WriteFile(s.path, data, 0o600); err != nil {
		return fmt.Errorf("accountlock: write %s: %w", s.path, err)
	}
	return nil
}

// Add records a new lock and applies it immediately. Locking an account
// that's already locked refreshes its expiry rather than adding a
// duplicate entry (and keeps the originally recorded PreviousShell, not a
// second Lock call's now-already-nologin shell). Zero duration is indefinite;
// negative durations are invalid.
func Add(store *Store, sys System, user, reason string, duration time.Duration, now time.Time) error {
	if duration < 0 {
		return fmt.Errorf("accountlock: duration must be nonnegative (0 means indefinite)")
	}
	var expires time.Time
	if duration > 0 {
		expires = now.Add(duration)
	}
	locks, err := store.Load()
	if err != nil {
		return err
	}

	for i := range locks {
		if locks[i].User == user {
			locks[i].Reason = reason
			locks[i].LockedAt = now
			locks[i].ExpiresAt = expires
			return store.Save(locks)
		}
	}

	previousShell, err := sys.Lock(user)
	if err != nil {
		return err
	}
	locks = append(locks, Lock{
		User:          user,
		Reason:        reason,
		LockedAt:      now,
		ExpiresAt:     expires,
		PreviousShell: previousShell,
	})
	return store.Save(locks)
}

// Remove unlocks user immediately, regardless of its expiry.
func Remove(store *Store, sys System, user string) error {
	locks, err := store.Load()
	if err != nil {
		return err
	}

	var previousShell string
	kept := locks[:0]
	for _, l := range locks {
		if l.User == user {
			previousShell = l.PreviousShell
			continue
		}
		kept = append(kept, l)
	}

	if err := sys.Unlock(user, previousShell); err != nil {
		return err
	}
	return store.Save(kept)
}

// Reconcile lifts every expired lock (restoring the recorded shell) and
// leaves active ones as they are — locking is a one-time state change
// (unlike a firewall rule, it doesn't need re-asserting every pass if
// nothing else could have silently reverted it), so unlike
// autoban.Reconcile this doesn't re-apply active locks, only expires
// them. Meant to be called on sentinel-check's schedule, same as
// autoban.Reconcile.
func Reconcile(store *Store, sys System, now time.Time) (active []string, expired []string, err error) {
	locks, err := store.Load()
	if err != nil {
		return nil, nil, err
	}

	// One account that won't unlock (a usermod that fails, an account
	// deleted out from under us) must not strand every later lock in the
	// list as still-locked: each is handled independently and the errors
	// are reported together at the end. A lock whose Unlock failed stays
	// in the store so the next pass tries it again.
	var kept []Lock
	var errs []error
	for _, l := range locks {
		if l.Expired(now) {
			if err := sys.Unlock(l.User, l.PreviousShell); err != nil {
				errs = append(errs, err)
				kept = append(kept, l)
				continue
			}
			expired = append(expired, l.User)
			continue
		}
		active = append(active, l.User)
		kept = append(kept, l)
	}

	if err := store.Save(kept); err != nil {
		errs = append(errs, err)
	}
	return active, expired, errors.Join(errs...)
}
