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

	// retainGenerations bounds store.Prune's mark-and-sweep: objects
	// referenced only by generations older than the last N are dropped.
	retainGenerations = 10

	sentinelInterval = "10min"
	sentinelJitter   = "120"

	// replicateInterval/replicateJitter match deploy/install.sh's
	// REPLICATE_INTERVAL/REPLICATE_JITTER — used only when
	// sentinel-check has to recreate a missing replicate timer from
	// scratch (see registrations.go).
	replicateInterval = "15min"
	replicateJitter   = "180"
)

// paths is every fixed, per-box path for backup state (manifests, objects,
// the audit log). It's derived from the binary's own install path rather
// than hardcoded to something literal like /var/lib/warden — a directory
// named after the tool would give away exactly what it is to anyone who
// runs `ls /var/lib`, undoing the point of installing the binary itself
// under a blended-in name. Deriving it from the same binaryName() that
// already names the systemd units and cron entry means choosing
// INSTALL_PATH once (in install.sh) is still the only naming decision
// anyone has to make.
type paths struct {
	dataDir            string
	configManifestPath string
	configManifestsDir string
	dataManifestPath   string
	dataManifestsDir   string
	// storeRoot is passed straight to store.New, which creates its own
	// "objects" subdirectory under whatever root it's given — it is NOT
	// dataDir+"/objects" itself, or store.New would nest it twice (a real
	// bug the Phase 6 VM test caught: watch's own repair write failed
	// with ".../objects/objects/<hash prefix>/<hash>: no such file or
	// directory").
	storeRoot    string
	auditLogPath string
}

// loadPaths resolves paths for the current box. configManifestPath and
// configManifestsDir track the config tier's own lineage — this is what
// watch, restore, status, and replicate all mean by "the" manifest, since
// the config tier is what's actually watched. The data tier gets its own
// separate lineage: sharing one manifest.json between tiers would mean
// the tier snapshotted last clobbers the other's "last known good"
// pointer, which is exactly the bug an earlier version of this file had
// (caught by the Phase 6 VM test — install.sh runs `snapshot --tier
// config` then `--tier data`, and the data snapshot silently erased
// watch's baseline immediately after installation).
func loadPaths() (paths, error) {
	name, err := binaryName()
	if err != nil {
		return paths{}, err
	}
	dir := "/var/lib/" + name

	return paths{
		dataDir:            dir,
		configManifestPath: dir + "/manifest-config.json",
		configManifestsDir: dir + "/manifests-config",
		dataManifestPath:   dir + "/manifest-data.json",
		dataManifestsDir:   dir + "/manifests-data",
		storeRoot:          dir,
		auditLogPath:       dir + "/audit.log",
	}, nil
}

// EXAMPLE VALUES — everything below this line is a starting template, not
// a real watch list. Replace configTierPaths, dataTierPaths, classifyPath,
// and serviceForPath with the actual paths and services for whatever this
// season's target distro and scoring services are before building for a
// competition (docs/PLAN.md Phase 1).
//
// WARNING when doing that: never add a scoring engine's own credentials
// (a scoring account's authorized_keys, an app login the scoring checks
// authenticate with, anything the scoring engine itself rotates) as
// SafeAutoRestore. If the scoring engine legitimately changes it and
// watch reverts it back to a stale snapshot, that's Warden silently
// breaking the box's own score, indistinguishable from red team having
// done it. If such a path needs watching at all, classify it
// ConfirmFirst — flagged for a human, never auto-reverted — the same
// way passwd/shadow/sudoers already are below.

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

func (p paths) manifestPathForTier(tier snapshotTier) string {
	if tier == tierData {
		return p.dataManifestPath
	}
	return p.configManifestPath
}

func (p paths) manifestsDirForTier(tier snapshotTier) string {
	if tier == tierData {
		return p.dataManifestsDir
	}
	return p.configManifestsDir
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
