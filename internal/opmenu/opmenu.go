// Package opmenu is what the forced SSH command runs — deliberately not a
// shell. It reads $SSH_ORIGINAL_COMMAND, dispatches against a small
// whitelist, and requires a second factor before anything beyond read-only
// status.
package opmenu

import (
	"crypto/subtle"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"warden/internal/audit"
	"warden/internal/totp"
)

// timeNow is a var so tests can override it.
var timeNow = time.Now

// Command is one whitelisted opmenu entry point.
type Command string

const (
	CommandStatus  Command = "status"
	CommandRestore Command = "restore"
	CommandShell   Command = "shell"
)

// Request is one parsed invocation, built from $SSH_ORIGINAL_COMMAND and
// the connection's source IP (already constrained by authorized_keys'
// from= restriction, but recorded here for the audit trail).
type Request struct {
	Command  Command
	Args     []string
	SourceIP string
	TOTPCode string
}

// Handler dispatches Requests against the whitelist. StatusFn and RestoreFn
// are injected so this package doesn't import watch/restore directly and
// stays independently testable; ShellPath is the binary execed for the
// shell command once the second factor passes.
type Handler struct {
	Secret string // TOTP secret, baked in at build time; "" disables TOTP
	// StaticSecretPath is a file holding a rotatable, non-time-based
	// passphrase accepted as an alternative second factor — for
	// competitions where phones/authenticator apps aren't available at
	// all (e.g. PCDC). "" disables this path. Read fresh on every check,
	// never cached, so rotating it (see cmd/warden's rotate-secret) takes
	// effect immediately with no rebuild or redeploy. Weaker than TOTP —
	// it doesn't expire on its own — so TOTP is still checked first and
	// this is purely additive, not a replacement.
	StaticSecretPath string
	StatusFn         func() (string, error)
	RestoreFn        func(target string, args []string) (string, error)
	ShellPath        string
	Log              *audit.Logger
}

// New builds a Handler.
func New(secret, staticSecretPath string, statusFn func() (string, error), restoreFn func(target string, args []string) (string, error), shellPath string, log *audit.Logger) *Handler {
	return &Handler{
		Secret:           secret,
		StaticSecretPath: staticSecretPath,
		StatusFn:         statusFn,
		RestoreFn:        restoreFn,
		ShellPath:        shellPath,
		Log:              log,
	}
}

// Handle dispatches req. Status never requires a second factor; restore and
// shell do. A rejected or malformed request is logged the same as an
// accepted one — the audit trail needs both.
func (h *Handler) Handle(req Request) (string, error) {
	switch req.Command {
	case CommandStatus:
		out, err := h.StatusFn()
		h.log(req, true, err)
		return out, err

	case CommandRestore:
		if !h.checkSecondFactor(req) {
			h.log(req, false, fmt.Errorf("second factor check failed"))
			return "", fmt.Errorf("opmenu: second factor required")
		}
		if len(req.Args) == 0 {
			h.log(req, false, fmt.Errorf("missing restore target"))
			return "", fmt.Errorf("opmenu: restore requires a target")
		}
		out, err := h.RestoreFn(req.Args[0], req.Args[1:])
		h.log(req, err == nil, err)
		return out, err

	case CommandShell:
		if !h.checkSecondFactor(req) {
			h.log(req, false, fmt.Errorf("second factor check failed"))
			return "", fmt.Errorf("opmenu: second factor required")
		}
		h.log(req, true, nil)
		return "", h.execShell()

	default:
		h.log(req, false, fmt.Errorf("unrecognized command %q", req.Command))
		return "", fmt.Errorf("opmenu: unrecognized command %q", req.Command)
	}
}

// checkSecondFactor accepts either a valid TOTP code or, if configured, an
// exact match against the current static secret file — see StaticSecretPath.
func (h *Handler) checkSecondFactor(req Request) bool {
	if req.TOTPCode == "" {
		return false
	}
	if h.Secret != "" {
		if ok, err := totp.Validate(h.Secret, req.TOTPCode, timeNow(), 1); err == nil && ok {
			return true
		}
	}
	if h.StaticSecretPath != "" {
		stored, err := os.ReadFile(h.StaticSecretPath)
		if err == nil {
			expected := strings.TrimSpace(string(stored))
			if expected != "" && subtle.ConstantTimeCompare([]byte(expected), []byte(req.TOTPCode)) == 1 {
				return true
			}
		}
	}
	return false
}

// execShell is the only path in opmenu that leaves the Go binary. It's
// reached only after checkSecondFactor has passed.
func (h *Handler) execShell() error {
	if h.ShellPath == "" {
		return fmt.Errorf("opmenu: no shell path configured")
	}
	return syscall.Exec(h.ShellPath, []string{h.ShellPath}, os.Environ())
}

func (h *Handler) log(req Request, ok bool, err error) {
	if h.Log == nil {
		return
	}
	fields := map[string]any{
		"command":   string(req.Command),
		"source_ip": req.SourceIP,
		"totp_used": req.TOTPCode != "",
		"accepted":  ok,
	}
	if err != nil {
		fields["error"] = err.Error()
	}
	action := "accepted"
	if !ok {
		action = "rejected"
	}
	_ = h.Log.Log("opmenu", action, fields)
}
