package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"warden/internal/manifest"
)

// systemd unit locations. Vars so tests can point them at a temp dir.
var (
	systemdUnitDir        = "/etc/systemd/system"
	systemdTimersWantsDir = systemdUnitDir + "/timers.target.wants"
	systemdPathsWantsDir  = systemdUnitDir + "/paths.target.wants"
)

const (
	// retainGenerations bounds store.Prune's mark-and-sweep: objects
	// referenced only by generations older than the last N are dropped.
	retainGenerations = 10

	// Timer schedules. sentinel-check writes these units at install and
	// rewrites them whenever they drift, so this is the only definition.
	// Access repair runs every minute or two; the path unit and the sshd
	// hook cover the gaps in between.
	sentinelInterval = "1min"
	sentinelJitter   = "30"

	replicateInterval = "15min"
	replicateJitter   = "180"

	watchInterval = "2min"
	watchJitter   = "30"

	snapshotConfigInterval = "5min"
	snapshotConfigJitter   = "60"

	snapshotDataInterval = "1h"
	snapshotDataJitter   = "300"

	scanInterval = "10min"
	scanJitter   = "120"

	// Zero keeps bans and account locks active until explicitly removed.
	autobanDuration     time.Duration = 0
	accountLockDuration time.Duration = 0
)

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

// paths is every fixed, per-box path for state. It derives from the
// installed binary's name rather than a literal like /var/lib/warden, which
// would name the tool to anyone running `ls /var/lib`; the name `install`
// chooses is the only naming decision.
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
	// anomalyDir holds every internal/anomaly check's own baseline file —
	// see scan.go. accountLocksPath is accountlock's Store, the local-
	// account equivalent of bannedIPsPath above.
	anomalyDir       string
	accountLocksPath string
	// mirrorDir holds a second copy of the binary and the runtime config
	// outside the state directory, so deleting /var/lib/<name> does not
	// take access repair with it.
	mirrorDir string
	// peerKeyPath is this box's own replication key, generated on the box
	// by `warden pair key`. It never leaves the box.
	peerKeyPath string
	// quarantineDir keeps a copy of every file watch removed from a
	// watched drop-in directory.
	quarantineDir string
	// profilePath is the optional host protection profile.
	profilePath string
	// peerRoot is where other boxes' backups land when this box is their
	// peer.
	peerRoot string
}

// loadPaths resolves paths for the current box. configManifestPath and
// configManifestsDir track the config tier's own lineage — this is what
// watch, restore, status, and replicate all mean by "the" manifest, since
// the config tier is what's actually watched. The data tier gets its own
// separate lineage: sharing one manifest.json between tiers would mean
// the tier snapshotted last clobbers the other's "last known good"
// pointer, which is exactly the bug an earlier version of this file had
// (install snapshots config then data, and the data snapshot erased
// watch's baseline).
func loadPaths() (paths, error) {
	name, err := binaryName()
	if err != nil {
		return paths{}, err
	}
	return pathsForName(name), nil
}

// pathsForName is the layout for a binary installed under name.
func pathsForName(name string) paths {
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
		anomalyDir:         dir + "/anomaly",
		accountLocksPath:   dir + "/account_locks.json",
		mirrorDir:          "/usr/lib/" + name,
		peerKeyPath:        dir + "/peer_key",
		quarantineDir:      dir + "/quarantine",
		profilePath:        dir + "/profile.json",
		peerRoot:           "/var/lib/" + name + "-peers",
	}
}

// The default watch profile follows the team's Linux hardening reference:
// it protects exactly the files that workflow touches, so a team that
// follows the sheet gets sensible behavior without writing a profile.
// Entries are exact paths, single-level globs ("/etc/pam.d/*"), or a
// directory tree ("/var/www/**"). Anything absent on this box is skipped.
//
// Two classes:
//   - auto-restore (the default): red edits these to lock the team out or
//     backdoor the box, so once armed they go straight back. A new file
//     in an auto-restore directory (sshd_config.d, sudoers.d, pam.d,
//     cron.d, ...) is the classic override or backdoor: it is copied to
//     quarantine and removed. To add one on purpose: disarm, add, arm.
//   - confirm-first (confirmFirstPaths): the team changes these on purpose
//     while hardening (passwords, firewall rules, units, user keys), so
//     drift is flagged and never overwritten.
var configTierPaths = []string{
	// Access: sshd, PAM, sudo, accounts.
	"/etc/ssh/sshd_config",
	"/etc/ssh/sshd_config.d/*",
	"/etc/pam.conf",
	"/etc/pam.d/*",
	"/etc/security/*",
	"/etc/security/*.d/*",
	"/etc/sudoers",
	"/etc/sudoers.d/*",
	"/etc/passwd",
	"/etc/group",
	"/etc/shadow",
	"/etc/gshadow",
	"/etc/nsswitch.conf",
	"/etc/login.defs",
	"/etc/ld.so.preload",
	"/etc/hosts",
	"/etc/hostname",

	// Scheduled jobs.
	"/etc/crontab",
	"/etc/cron.d/*",
	"/etc/cron.hourly/*",
	"/etc/cron.daily/*",
	"/etc/cron.weekly/*",
	"/etc/cron.monthly/*",
	"/var/spool/cron/*",
	"/var/spool/cron/crontabs/*",

	// Services and units.
	"/etc/systemd/system/*",
	"/etc/systemd/system/*/*",

	// SSH keys for every account. Warden's own access accounts are
	// excluded (see ownFiles); sentinel holds those.
	"/root/.ssh/authorized_keys",
	"/root/.ssh/authorized_keys2",
	"/home/*/.ssh/authorized_keys",
	"/home/*/.ssh/authorized_keys2",

	// Firewall state.
	"/etc/iptables/rules.v4",
	"/etc/iptables/rules.v6",
	"/etc/sysconfig/iptables",
	"/etc/sysconfig/ip6tables",
	"/etc/nftables.conf",
	"/etc/ufw/*",
	"/etc/firewalld/*",
	"/etc/firewalld/zones/*",

	// Scored service configs. Restored and their service reloaded.
	"/etc/nginx/nginx.conf",
	"/etc/apache2/apache2.conf",
	"/etc/httpd/conf/httpd.conf",
	"/etc/mysql/my.cnf",
	"/etc/my.cnf",
	"/etc/postgresql/postgresql.conf",
	"/etc/postfix/main.cf",
	"/etc/dovecot/dovecot.conf",
	"/etc/mail/sendmail.cf",
	"/etc/bind/named.conf",
	"/etc/named.conf",
	"/etc/vsftpd.conf",
	"/etc/proftpd/proftpd.conf",
	"/etc/samba/smb.conf",
	"/etc/exports",
	"/etc/dhcp/dhcpd.conf",
	"/etc/docker/daemon.json",
	"/etc/containerd/config.toml",
	"/etc/mongod.conf",
	"/etc/redis/redis.conf",
	"/etc/redis.conf",
	"/etc/elasticsearch/elasticsearch.yml",
	"/etc/tomcat/server.xml",
	"/etc/tomcat9/server.xml",
	"/var/lib/tomcat9/conf/server.xml",
	"/var/www/html/wp-config.php",
	"/var/www/wordpress/wp-config.php",
	"/etc/chrony/chrony.conf",
	"/etc/chrony.conf",
	"/etc/ntp.conf",
	"/etc/snmp/snmpd.conf",
	"/etc/xrdp/xrdp.ini",
	"/etc/tigervnc/vncserver.users",
}

// dataTierPaths is snapshotted hourly and restored only by a human: data
// that changes legitimately but that "destroy our stuff" goes after.
var dataTierPaths = []string{
	"/var/www/**",
}

// maxDataFileBytes skips huge files in data-tier trees (uploads, logs) so a
// web root cannot fill the backup store or a peer's quota.
const maxDataFileBytes = 64 << 20

// confirmFirstPaths are flag-only: drift is reported and left on disk.
// Keys may be patterns from configTierPaths.
var confirmFirstPaths = map[string]bool{
	// chpasswd and usermod --expiredate write these while hardening.
	"/etc/shadow":  true,
	"/etc/gshadow": true,

	// Firewall rules the team saves mid-incident.
	"/etc/iptables/rules.v4":   true,
	"/etc/iptables/rules.v6":   true,
	"/etc/sysconfig/iptables":  true,
	"/etc/sysconfig/ip6tables": true,
	"/etc/nftables.conf":       true,
	"/etc/ufw/*":               true,
	"/etc/firewalld/*":         true,
	"/etc/firewalld/zones/*":   true,

	// Per-user crontabs and units change legitimately; new ones are
	// flagged for a human.
	"/var/spool/cron/*":          true,
	"/var/spool/cron/crontabs/*": true,
	"/etc/systemd/system/*":      true,
	"/etc/systemd/system/*/*":    true,

	// New keys for other accounts are flagged, never removed.
	"/root/.ssh/authorized_keys":    true,
	"/root/.ssh/authorized_keys2":   true,
	"/home/*/.ssh/authorized_keys":  true,
	"/home/*/.ssh/authorized_keys2": true,
}

func classifyPath(path string) manifest.Class {
	if confirmFirstPaths[path] {
		return manifest.ConfirmFirst
	}
	// The first pattern that matches decides, so an exact profile entry
	// listed before a glob wins.
	for _, pattern := range configTierPaths {
		if matchesPattern(pattern, path) {
			if confirmFirstPaths[pattern] {
				return manifest.ConfirmFirst
			}
			return manifest.SafeAutoRestore
		}
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
	"/etc/ssh/sshd_config.d/*":        {"sshd", "ssh"},

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
	candidates := pathServices[path]
	if len(candidates) == 0 {
		for pattern, units := range pathServices {
			if isPattern(pattern) && matchesPattern(pattern, path) {
				candidates = units
				break
			}
		}
	}
	for _, candidate := range candidates {
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
