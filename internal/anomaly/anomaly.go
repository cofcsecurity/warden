// Package anomaly is a bounded set of high-signal checks for tampering
// beyond file-content drift — new SUID/SGID binaries, cron/authorized_keys
// changes outside what sentinel already covers, and new local accounts.
// Deliberately not a SIEM replacement (see docs/PLAN.md Phase 9): each
// check flags what it finds, it never decides what to do about it — that
// judgment call belongs to the caller, in cmd/warden, the same separation
// internal/autoban and internal/accountlock already keep.
package anomaly

import "time"

// Finding is one suspicious change a check detected.
type Finding struct {
	// Check names which check produced this (e.g. "cron", "suid").
	Check string
	// Description is a one-line, human-readable summary.
	Description string
	// Detail is extra context — the path, old/new value, etc.
	Detail string
	// Culprit is the local account this finding is directly,
	// unambiguously attributable to — e.g. whose crontab file changed,
	// whose authorized_keys grew a new line, the name of a newly-created
	// account, or a SUID binary's current file owner. Empty whenever the
	// finding itself doesn't make that safe to infer (e.g. a change to a
	// root-level file like /etc/cron.d/foo, which isn't obviously any one
	// account's doing).
	Culprit string
	// EventTime is the best available estimate of when this actually
	// happened — a file's mtime, when there's one concrete file the
	// finding is about (cron, authorized_keys, SUID). Zero when there
	// isn't one (accounts, listening ports, packages) — callers fall
	// back to "now" for those, which is a reasonable approximation since
	// those checks report state that's closer to instantaneous (a port
	// is either listening right now or it isn't) than something with a
	// meaningful historical timestamp of its own.
	EventTime time.Time
}
