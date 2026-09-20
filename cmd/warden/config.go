package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"warden/internal/manifest"
)

// Local, on-disk paths. Deliberately not overridable by flag or env var —
// see docs/DESIGN.md's "Configuration" section for why these stay fixed
// rather than becoming a discoverable config file.
const (
	// systemdUnitDir is what sentinel-check verifies and repairs. Matches
	// deploy/install.sh's default, not something baked in at build time,
	// since it's a path on the box rather than a per-competition secret.
	// authorizedKeysPath and cronSpoolPath used to live here too, back
	// when they were fixed paths — both are now functions below, since
	// they depend on the disguised binary name or the distro family.
	systemdUnitDir        = "/etc/systemd/system"
	systemdTimersWantsDir = systemdUnitDir + "/timers.target.wants"

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

	// autobanDuration is how long an auto-triggered ban (see watch.go's
	// reactToConfirmFirstChange) lasts before sentinel-check's Reconcile
	// call lifts it — long enough to matter, short enough that a
	// mis-attributed ban on a legitimate but unlisted IP self-heals
	// rather than needing a human to notice and run `warden unban`.
	autobanDuration = time.Hour
)

// authLogPaths are checked in order; the first one that exists is used.
// Debian/Ubuntu ships /var/log/auth.log via rsyslog by default; RHEL-family
// distros use /var/log/secure for the same sshd log lines. If neither
// exists (no rsyslog, journald-only), attribution has no evidence to work
// from and auto-ban simply doesn't fire — see docs/DESIGN.md's note on
// why a wrong auto-response is worse than none.
var authLogPaths = []string{"/var/log/auth.log", "/var/log/secure"}

func findAuthLog() (string, bool) {
	for _, p := range authLogPaths {
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}
	return "", false
}

// authorizedKeysPath is the opmenu account's own authorized_keys file —
// never root's; see units.go's opmenuUser for why. A function rather than
// a const since it depends on the disguised binary name, not a fixed
// system path.
func authorizedKeysPath() (string, error) {
	user, err := opmenuUser()
	if err != nil {
		return "", err
	}
	return opmenuUserHome(user) + "/.ssh/authorized_keys", nil
}

// cronSpoolPath auto-detects Debian/Ubuntu's crontab layout
// (/var/spool/cron/crontabs/, a directory of one file per user) versus
// RHEL-family's (/var/spool/cron/, root's crontab directly in it) by
// checking which directory actually exists, rather than assuming one and
// leaving the other distro family silently broken — sentinel-check would
// otherwise write a cron entry cron itself never reads.
func cronSpoolPath() string {
	if info, err := os.Stat("/var/spool/cron/crontabs"); err == nil && info.IsDir() {
		return "/var/spool/cron/crontabs/root"
	}
	return "/var/spool/cron/root"
}

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
	// armedMarkerPath's presence is the only thing that gates watch's
	// auto-restore — see arm.go. Its absence (the state right after
	// install) is the safe default: drift is still detected and logged,
	// just never overwritten, so the box can be hardened without watch
	// fighting that work every few minutes.
	armedMarkerPath string
	bannedIPsPath   string
	// staticSecretPath is opmenu's rotatable, non-TOTP second factor — see
	// internal/opmenu's StaticSecretPath and cmd/warden/rotatesecret.go.
	// Absent until `warden rotate-secret` is run at least once, which is
	// the safe default: opmenu simply never matches on it until then.
	staticSecretPath string
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
		armedMarkerPath:    dir + "/armed",
		bannedIPsPath:      dir + "/banned_ips.json",
		staticSecretPath:   dir + "/second-factor",
	}, nil
}

// STARTING DEFAULTS, not a substitute for a real pass per docs/PLAN.md
// Phase 1. configTierPaths below is deliberately broad — every entry that
// doesn't exist on a given box is silently skipped by manifest.Generate,
// so it's safe to ship a list covering common CCDC-image services across
// both Debian- and RHEL-family paths rather than a single distro's exact
// layout. Still confirm the real path list before a competition: run
// `warden detect` on the actual target box (or an image of it) to see
// which of these are actually present, plus anything it finds running
// that isn't on this list yet — see internal/detect for the full table of
// known services it checks for.
//
// WARNING when editing this list: never add a scoring engine's own
// credentials (a scoring account's authorized_keys, an app login the
// scoring checks authenticate with, anything the scoring engine itself
// rotates) as SafeAutoRestore. If the scoring engine legitimately changes
// it and watch reverts it back to a stale snapshot, that's Warden silently
// breaking the box's own score, indistinguishable from red team having
// done it. If such a path needs watching at all, classify it
// ConfirmFirst — flagged for a human, never auto-reverted — the same way
// passwd/shadow/sudoers already are below.

// configTierPaths is the fast snapshot/watch tier: small, frequently
// checked files whose drift usually means tampering rather than normal
// service operation. Grouped by what they're for; anything not installed
// on a given box just never shows up in a manifest.
var configTierPaths = []string{
	// Core identity/access — always watched, always ConfirmFirst below.
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/gshadow",
	"/etc/sudoers",
	"/etc/ssh/sshd_config",
	"/etc/hosts",
	"/etc/hostname",
	"/etc/crontab",

	// Web servers
	"/etc/nginx/nginx.conf",
	"/etc/apache2/apache2.conf",
	"/etc/httpd/conf/httpd.conf", // RHEL-family Apache

	// Databases
	"/etc/mysql/my.cnf",
	"/etc/my.cnf", // RHEL-family MySQL/MariaDB
	"/etc/postgresql/postgresql.conf",

	// Mail
	"/etc/postfix/main.cf",
	"/etc/dovecot/dovecot.conf",
	"/etc/mail/sendmail.cf",

	// DNS
	"/etc/bind/named.conf",
	"/etc/named.conf", // RHEL-family BIND

	// File transfer / sharing
	"/etc/vsftpd.conf",
	"/etc/proftpd/proftpd.conf",
	"/etc/samba/smb.conf",
	"/etc/exports", // NFS

	// DHCP
	"/etc/dhcp/dhcpd.conf",
}

// dataTierPaths is the slow snapshot tier: larger service data, snapshotted
// less often. watch only ever runs against configTierPaths. Left empty by
// default — unlike configTierPaths, this needs the season's real scored
// service data files named explicitly (e.g. a specific database dump path
// or web root file), since manifest.Generate only records individual
// files, not whole directories (see docs/PLAN.md Phase 1).
var dataTierPaths []string

// watchedPaths is what `warden watch` checks; it's the config tier, since
// that's what drift-detection is actually meant to catch.
var watchedPaths = configTierPaths

var confirmFirstPaths = map[string]bool{
	"/etc/passwd":          true,
	"/etc/shadow":          true,
	"/etc/group":           true,
	"/etc/gshadow":         true,
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
	"/etc/nginx/nginx.conf":           "nginx",
	"/etc/apache2/apache2.conf":       "apache2",
	"/etc/httpd/conf/httpd.conf":      "httpd",
	"/etc/mysql/my.cnf":               "mysql",
	"/etc/my.cnf":                     "mariadb",
	"/etc/postgresql/postgresql.conf": "postgresql",
	"/etc/postfix/main.cf":            "postfix",
	"/etc/dovecot/dovecot.conf":       "dovecot",
	"/etc/mail/sendmail.cf":           "sendmail",
	"/etc/bind/named.conf":            "bind9",
	"/etc/named.conf":                 "named",
	"/etc/vsftpd.conf":                "vsftpd",
	"/etc/proftpd/proftpd.conf":       "proftpd",
	"/etc/samba/smb.conf":             "smbd",
	"/etc/dhcp/dhcpd.conf":            "isc-dhcp-server",
	"/etc/ssh/sshd_config":            "sshd",
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
