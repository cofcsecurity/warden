package main

import "warden/internal/manifest"

// Local, on-disk paths. Deliberately not overridable by flag or env var —
// see docs/DESIGN.md's "Configuration" section for why these stay fixed
// rather than becoming a discoverable config file.
const (
	dataDir      = "/var/lib/warden"
	manifestPath = dataDir + "/manifest.json"
	objectsDir   = dataDir + "/objects"
	auditLogPath = dataDir + "/audit.log"
)

// watchedPaths and classifyPath are per-box: fill these in for the target
// distro's actual config layout before building for a competition. Left
// empty here so a dev build doesn't silently watch nothing meaningful.
var watchedPaths []string

func classifyPath(path string) manifest.Class {
	// TODO: return manifest.ConfirmFirst for keys, passwd, sudoers, and
	// anything else that should never be auto-reverted; SafeAutoRestore
	// for everything else.
	return manifest.SafeAutoRestore
}

// serviceForPath maps a watched path to the systemd unit that owns it, for
// restore's stop/write/restart sequence. Returns ok=false for paths with no
// mapped service.
func serviceForPath(path string) (unit string, ok bool) {
	// TODO: fill in per box, e.g. "/etc/nginx/nginx.conf" -> "nginx".
	return "", false
}
