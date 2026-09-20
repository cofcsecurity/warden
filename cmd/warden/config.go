package main

import (
	"fmt"
	"strings"

	"warden/internal/manifest"
)

// Local, on-disk paths. Deliberately not overridable by flag or env var —
// see docs/DESIGN.md's "Configuration" section for why these stay fixed
// rather than becoming a discoverable config file.
const (
	dataDir      = "/var/lib/warden"
	manifestPath = dataDir + "/manifest.json"
	manifestsDir = dataDir + "/manifests" // archived generations, one file each
	objectsDir   = dataDir + "/objects"
	auditLogPath = dataDir + "/audit.log"

	// retainGenerations bounds store.Prune's mark-and-sweep: objects
	// referenced only by generations older than the last N are dropped.
	retainGenerations = 10

	// authorizedKeysPath, systemdUnitDir, and cronSpoolPath are what
	// sentinel-check verifies and repairs. They match deploy/install.sh's
	// defaults, not something baked in at build time, since they're paths
	// on the box rather than per-competition secrets.
	authorizedKeysPath    = "/root/.ssh/authorized_keys"
	systemdUnitDir        = "/etc/systemd/system"
	systemdTimersWantsDir = systemdUnitDir + "/timers.target.wants"
	// cronSpoolPath is Debian/Ubuntu's root crontab location. RHEL-family
	// distros use /var/spool/cron/root instead — adjust for the target
	// distro (see docs/PLAN.md Phase 1's config.go note).
	cronSpoolPath = "/var/spool/cron/crontabs/root"

	sentinelInterval = "10min"
	sentinelJitter   = "120"
)

// EXAMPLE VALUES — everything below this line is a starting template, not
// a real watch list. Replace configTierPaths, dataTierPaths, classifyPath,
// and serviceForPath with the actual paths and services for whatever this
// season's target distro and scoring services are before building for a
// competition (docs/PLAN.md Phase 1).

// configTierPaths is the fast snapshot/watch tier: small, frequently
// checked files whose drift usually means tampering rather than normal
// service operation.
var configTierPaths = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/sudoers",
	"/etc/ssh/sshd_config",
	"/etc/nginx/nginx.conf",
	"/etc/apache2/apache2.conf",
	"/etc/mysql/my.cnf",
}

// dataTierPaths is the slow snapshot tier: larger service data, snapshotted
// less often. watch only ever runs against configTierPaths.
var dataTierPaths []string

// watchedPaths is what `warden watch` checks; it's the config tier, since
// that's what drift-detection is actually meant to catch.
var watchedPaths = configTierPaths

var confirmFirstPaths = map[string]bool{
	"/etc/passwd":          true,
	"/etc/shadow":          true,
	"/etc/group":           true,
	"/etc/sudoers":         true,
	"/etc/ssh/sshd_config": true,
}

func classifyPath(path string) manifest.Class {
	if confirmFirstPaths[path] {
		return manifest.ConfirmFirst
	}
	return manifest.SafeAutoRestore
}

var pathServices = map[string]string{
	"/etc/nginx/nginx.conf":     "nginx",
	"/etc/apache2/apache2.conf": "apache2",
	"/etc/mysql/my.cnf":         "mysql",
	"/etc/ssh/sshd_config":      "sshd",
}

// serviceForPath maps a watched path to the systemd unit that owns it, for
// restore's stop/write/restart sequence. Returns ok=false for paths with no
// mapped service (e.g. passwd/shadow/sudoers, which don't need a restart).
func serviceForPath(path string) (unit string, ok bool) {
	unit, ok = pathServices[path]
	return unit, ok
}

// snapshotTier selects which path list a snapshot covers.
type snapshotTier string

const (
	tierConfig snapshotTier = "config"
	tierData   snapshotTier = "data"
)

func pathsForTier(tier snapshotTier) []string {
	switch tier {
	case tierData:
		return dataTierPaths
	default:
		return configTierPaths
	}
}

func parseTier(s string) (snapshotTier, error) {
	switch strings.ToLower(s) {
	case "", string(tierConfig):
		return tierConfig, nil
	case string(tierData):
		return tierData, nil
	default:
		return "", fmt.Errorf("config: unknown tier %q (want %q or %q)", s, tierConfig, tierData)
	}
}
