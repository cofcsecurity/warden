package main

import (
	"fmt"
	"os"
	"path/filepath"
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

	// Every interval/jitter pair below matches deploy/install.sh's own
	// defaults for the same timer. They're used only when sentinel-check
	// has to recreate a missing timer from scratch (see
	// registrations.go): a recreated timer has to fire on the same
	// schedule the installed one did, or "repaired" would quietly mean
	// "running at some other cadence than the box was deployed with".
	sentinelInterval = "10min"
	sentinelJitter   = "120"

	replicateInterval = "15min"
	replicateJitter   = "180"

	watchInterval = "5min"
	watchJitter   = "90"

	snapshotConfigInterval = "5min"
	snapshotConfigJitter   = "60"

	snapshotDataInterval = "1h"
	snapshotDataJitter   = "300"

	scanInterval = "10min"
	scanJitter   = "120"

	// heartbeatInterval is how often a box is expected to leave a
	// heartbeat on its peers — every replicate pass, so it tracks
	// replicateInterval exactly rather than being a second schedule to
	// keep in step. A peer reads it out of the beat itself (see
	// internal/heartbeat's IntervalSeconds) rather than assuming this
	// value, so boxes built with different intervals still judge each
	// other correctly.
	heartbeatInterval = 15 * time.Minute

	// heartbeatStaleGrace is how far past a peer's own declared interval
	// it has to go silent before sentinel-check calls it out. Two full
	// missed pushes plus the jitter on them: short enough that a box
	// going dark is noticed inside an hour, long enough that one failed
	// push, a reboot, or a brief network blip doesn't cry wolf.
	heartbeatStaleGrace = 35 * time.Minute

	// Zero keeps bans and account locks active until explicitly removed.
	autobanDuration     time.Duration = 0
	accountLockDuration time.Duration = 0
)

// inboundHeartbeatGlobs is where *other* boxes' heartbeats land on this
// box: one directory per peer that replicates here, under the receiving
// account's home (docs/DEPLOYMENT.md creates `warden-backup` with roots
// like /home/warden-backup/from-box1). The account name isn't hardcoded
// — any home directory containing a replication root matches — since
// that name is a deployment convention rather than something the binary
// controls.
//
// Anything readable here is treated as a report, not as proof: a beat is
// written by whatever account receives replication, so anyone able to
// write in that directory can forge one. Nothing automatic acts on them
// (see cmd/warden/heartbeat.go's checkPeerHeartbeats).
var inboundHeartbeatGlobs = []string{"/home/*/*/heartbeat/*.json"}

// Prefer a plaintext auth log; fall back to the system journal when absent.
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
	// spentTOTPPath is opmenu's TOTP replay guard: the last accepted
	// time step, so a captured code can't be used a second time within
	// its skew window.
	spentTOTPPath string
	// anomalyDir holds every internal/anomaly check's own baseline file —
	// see scan.go. accountLocksPath is accountlock's Store, the local-
	// account equivalent of bannedIPsPath above.
	anomalyDir       string
	accountLocksPath string
	// auditPushStatePath records how much of the audit log has already
	// been pushed to each replication peer, so each pass only sends
	// what's new — see cmd/warden/replicate.go's pushAuditLog.
	auditPushStatePath string
	// heartbeatAlertsPath remembers which silent peers have already been
	// alerted on, so one dark box produces one alert rather than one
	// every sentinel-check pass — see cmd/warden/heartbeat.go.
	heartbeatAlertsPath string
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
		dataDir:             dir,
		configManifestPath:  dir + "/manifest-config.json",
		configManifestsDir:  dir + "/manifests-config",
		dataManifestPath:    dir + "/manifest-data.json",
		dataManifestsDir:    dir + "/manifests-data",
		storeRoot:           dir,
		auditLogPath:        dir + "/audit.log",
		armedMarkerPath:     dir + "/armed",
		bannedIPsPath:       dir + "/banned_ips.json",
		staticSecretPath:    dir + "/second-factor",
		spentTOTPPath:       dir + "/second-factor-spent",
		anomalyDir:          dir + "/anomaly",
		accountLocksPath:    dir + "/account_locks.json",
		auditPushStatePath:  dir + "/audit-replicated.json",
		heartbeatAlertsPath: dir + "/heartbeat-alerts.json",
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
	// Core identity/access — always watched. Most of these are
	// auto-restored (see confirmFirstPaths below for the two that
	// aren't, and why).
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

	// Containers — the runtime's own config, not anything inside a
	// container. A container's contents aren't reachable from a path
	// list like this one; what's here is the daemon's configuration
	// (exposed sockets, registries, runtime flags).
	"/etc/docker/daemon.json",
	"/etc/containerd/config.toml",

	// NoSQL, cache, search
	"/etc/mongod.conf",
	"/etc/redis/redis.conf",
	"/etc/redis.conf", // RHEL-family Redis
	"/etc/elasticsearch/elasticsearch.yml",

	// Java application servers
	"/etc/tomcat/server.xml",  // RHEL-family Tomcat
	"/etc/tomcat9/server.xml", // Debian/Ubuntu Tomcat 9
	"/var/lib/tomcat9/conf/server.xml",

	// Application configs that hold their own database credentials.
	// Read the WARNING above before adding more of these: an app config
	// the scoring engine itself rewrites must be ConfirmFirst, not
	// auto-restored.
	"/var/www/html/wp-config.php",
	"/var/www/wordpress/wp-config.php",

	// Time. Worth watching despite looking mundane: skewing a box's
	// clock breaks TOTP, log correlation, and anything Kerberos-backed
	// all at once.
	"/etc/chrony/chrony.conf",
	"/etc/chrony.conf", // RHEL-family chrony
	"/etc/ntp.conf",

	// Monitoring and remote management — each one is both a service to
	// keep working and a way in if it's reconfigured.
	"/etc/snmp/snmpd.conf",
	"/etc/xrdp/xrdp.ini",
	"/etc/tigervnc/vncserver.users",

	// The authentication stack itself. Auto-restored, like the rest of
	// the access path: a PAM edit is how an attacker makes every login
	// succeed, and putting the known-good stack back is what fixes that.
	// See confirmFirstPaths below for why so few things are flag-only.
	"/etc/pam.d/common-auth",     // Debian/Ubuntu
	"/etc/pam.d/common-password", // Debian/Ubuntu
	"/etc/pam.d/common-account",  // Debian/Ubuntu
	"/etc/pam.d/common-session",  // Debian/Ubuntu
	"/etc/pam.d/system-auth",     // RHEL-family
	"/etc/pam.d/password-auth",   // RHEL-family
	"/etc/pam.d/sshd",
	"/etc/pam.d/sudo",
	"/etc/pam.d/su",
	"/etc/nsswitch.conf",
	"/etc/login.defs",

	// Persistent firewall rules — one of the few things left flag-only;
	// see confirmFirstPaths below.
	"/etc/iptables/rules.v4",
	"/etc/iptables/rules.v6",
	"/etc/sysconfig/iptables",  // RHEL-family
	"/etc/sysconfig/ip6tables", // RHEL-family
	"/etc/nftables.conf",
	"/etc/ufw/user.rules",
	"/etc/ufw/user6.rules",
	"/etc/firewalld/firewalld.conf",
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

// confirmFirstPaths are the watched paths watch will *never* revert on
// its own: drift is flagged for a human and left on disk. Everything else
// is auto-restored within a watch cycle.
//
// Read that the right way round: confirm-first is the *weaker* setting.
// An auto-restored file is back to known-good in a few minutes with
// nobody involved; a confirm-first file stays exactly as the attacker
// left it until a person notices and acts. So a path only belongs here
// when reverting it automatically would do more damage than leaving it
// wrong for a while.
//
// That's why the obvious candidates are deliberately NOT here:
//
//   - /etc/ssh/sshd_config is the team's own way in. If red team edits
//     it to lock everyone out, "flag it and wait for a human" is a
//     deadlock — the human can't get in to act on the flag. It's
//     auto-restored, and watch reloads sshd afterwards so the running
//     daemon actually picks the known-good config back up.
//   - /etc/passwd, /etc/group and /etc/sudoers are how an attacker keeps
//     access: a new account, a group membership, a NOPASSWD rule.
//     Auto-restoring makes all three disappear on their own. A *legitimate*
//     account added after arming is reverted too — that's the cost, and
//     'warden accept <path> <code>' is how the team lands one deliberately.
//   - The PAM stack and what feeds it are how an attacker makes every
//     login succeed. Reverting to the known-good stack restores working
//     authentication rather than breaking it.
var confirmFirstPaths = map[string]bool{
	// Credential material. Reverting these undoes a password rotation
	// the team performed minutes ago, silently and with no sign it
	// happened — and would fight a scoring engine that rotates
	// credentials of its own. Denying an attacker's account is already
	// handled by restoring /etc/passwd, which is what NSS reads; the
	// orphaned hash left behind in shadow grants nothing on its own.
	"/etc/shadow":  true,
	"/etc/gshadow": true,

	// Persistent firewall rules, for two reasons. These files are
	// loaded at boot, so reverting one doesn't change the live ruleset
	// anyway — the recovery people imagine here doesn't happen. And the
	// team edits them mid-incident (block an attacker, save the
	// ruleset), which auto-restore would undo a few minutes later.
	// Warden's own bans are live rules re-asserted by sentinel-check,
	// so they never depend on these files.
	"/etc/iptables/rules.v4":        true,
	"/etc/iptables/rules.v6":        true,
	"/etc/sysconfig/iptables":       true,
	"/etc/sysconfig/ip6tables":      true,
	"/etc/nftables.conf":            true,
	"/etc/ufw/user.rules":           true,
	"/etc/ufw/user6.rules":          true,
	"/etc/firewalld/firewalld.conf": true,
}

func classifyPath(path string) manifest.Class {
	if confirmFirstPaths[path] {
		return manifest.ConfirmFirst
	}
	return manifest.SafeAutoRestore
}

// pathServices maps a watched path to the systemd unit(s) that might own
// it. Several of these genuinely differ by distro for the *same* config
// file (chrony vs chronyd, redis vs redis-server, ssh vs sshd), so each
// entry is a candidate list and serviceForPath picks whichever unit
// actually exists on this box. Guessing wrong isn't harmless: restore
// stops the unit before writing, and a stop that fails aborts that path's
// restore entirely — so "no unit found" has to mean "just write the
// file," not "try a name that isn't there."
var pathServices = map[string][]string{
	"/etc/nginx/nginx.conf":           {"nginx"},
	"/etc/apache2/apache2.conf":       {"apache2"},
	"/etc/httpd/conf/httpd.conf":      {"httpd"},
	"/etc/mysql/my.cnf":               {"mysql", "mariadb"},
	"/etc/my.cnf":                     {"mariadb", "mysqld", "mysql"},
	"/etc/postgresql/postgresql.conf": {"postgresql"},
	"/etc/postfix/main.cf":            {"postfix"},
	"/etc/dovecot/dovecot.conf":       {"dovecot"},
	"/etc/mail/sendmail.cf":           {"sendmail"},
	"/etc/bind/named.conf":            {"bind9", "named"},
	"/etc/named.conf":                 {"named", "bind9"},
	"/etc/vsftpd.conf":                {"vsftpd"},
	"/etc/proftpd/proftpd.conf":       {"proftpd"},
	"/etc/samba/smb.conf":             {"smbd", "smb"},
	"/etc/dhcp/dhcpd.conf":            {"isc-dhcp-server", "dhcpd"},
	"/etc/ssh/sshd_config":            {"sshd", "ssh"},

	// Containers. Restarting the container runtime bounces every
	// container on the box, which is a far wider blast radius than any
	// other entry here — deliberately still mapped, since a daemon
	// config that's been reverted but not reloaded is a restore that
	// didn't actually restore anything, and the operator running
	// 'warden restore' on this path is asking for exactly that.
	"/etc/docker/daemon.json":              {"docker"},
	"/etc/containerd/config.toml":          {"containerd"},
	"/etc/mongod.conf":                     {"mongod"},
	"/etc/redis/redis.conf":                {"redis-server", "redis"},
	"/etc/redis.conf":                      {"redis", "redis-server"},
	"/etc/elasticsearch/elasticsearch.yml": {"elasticsearch"},
	"/etc/tomcat/server.xml":               {"tomcat", "tomcat9"},
	"/etc/tomcat9/server.xml":              {"tomcat9", "tomcat"},
	"/var/lib/tomcat9/conf/server.xml":     {"tomcat9", "tomcat"},
	"/etc/chrony/chrony.conf":              {"chrony", "chronyd"},
	"/etc/chrony.conf":                     {"chronyd", "chrony"},
	"/etc/ntp.conf":                        {"ntp", "ntpd"},
	"/etc/snmp/snmpd.conf":                 {"snmpd"},
	"/etc/xrdp/xrdp.ini":                   {"xrdp"},
}

// systemdUnitSearchDirs is where serviceForPath looks for a unit file. A
// var so tests can point it somewhere harmless instead of the real box.
var systemdUnitSearchDirs = []string{
	systemdUnitDir,
	"/etc/systemd/system",
	"/lib/systemd/system",
	"/usr/lib/systemd/system",
}

// serviceForPath maps a watched path to the systemd unit that owns it, for
// restore's stop/write/restart sequence. Returns ok=false for paths with
// no mapped service (passwd/shadow/sudoers and friends, which don't need
// a restart) and, just as importantly, for a mapped path whose unit isn't
// installed here under any of its known names — writing the file without
// a restart beats failing the restore over a unit that doesn't exist.
func serviceForPath(path string) (unit string, ok bool) {
	for _, candidate := range pathServices[path] {
		if unitFileExists(candidate) {
			return candidate, true
		}
	}
	return "", false
}

func unitFileExists(unit string) bool {
	for _, dir := range systemdUnitSearchDirs {
		if _, err := os.Stat(filepath.Join(dir, unit+".service")); err == nil {
			return true
		}
	}
	return false
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
