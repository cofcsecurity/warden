// Package detect answers one question ahead of a competition: what's
// actually running on this box, out of the services Warden knows how to
// watch? It's read-only and makes no changes — the output is meant for a
// human deciding what to add to cmd/warden/config.go's watch list, not
// something Warden acts on automatically. See docs/PLAN.md Phase 1's note
// that the shipped watch list is a starting template, not a real season's
// scored image.
package detect

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Service is one thing detect knows how to look for: a process name to
// match against what's running, and the config file paths that process
// typically reads, across the distro families a CCDC-style image is likely
// to use (mainly Debian- and RHEL-family layouts differ).
type Service struct {
	// Name is a short human label, not necessarily the exact process or
	// package name (e.g. "Apache" covers both apache2 and httpd).
	Name string
	// ProcessNames are matched against /proc/<pid>/comm, which the kernel
	// truncates to 15 bytes — every entry here is chosen to already fit
	// under that limit rather than relying on prefix matching.
	ProcessNames []string
	// ConfigPaths are candidate config file locations; not all of them
	// will exist on any one box.
	ConfigPaths []string
}

// KnownServices is every service detect checks for: the common CCDC-image
// services named in docs/EXPLAINER.md and DESIGN.md's worked examples —
// web, database, mail, DNS, file transfer/sharing, and DHCP — plus SSH
// itself, since sshd_config is already a default watched path, and the
// second wave of things that turn up on modern scored images (containers,
// NoSQL/cache/search, Java app servers, a CMS, time, SNMP, remote
// desktop, the firewall).
//
// Still a template, not a season's real image: this list is what makes
// `warden detect` able to *ask the question* about a service, and every
// entry that isn't on a given box simply never matches. A service nobody
// here has thought of still won't be found, which is why detect also
// reports what's running that it has no entry for.
//
// A few entries have no ProcessNames at all. That's deliberate rather
// than an omission: anything JVM-based reports `java` in
// /proc/<pid>/comm, so Tomcat and Elasticsearch are indistinguishable
// from each other (and from any other Java process) by process name —
// their config path is the honest signal. Same for a CMS, which has no
// process of its own at all; it's files served by someone else's.
var KnownServices = []Service{
	{
		Name:         "nginx",
		ProcessNames: []string{"nginx"},
		ConfigPaths:  []string{"/etc/nginx/nginx.conf"},
	},
	{
		Name:         "Apache",
		ProcessNames: []string{"apache2", "httpd"},
		ConfigPaths:  []string{"/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf"},
	},
	{
		Name:         "MySQL/MariaDB",
		ProcessNames: []string{"mysqld", "mariadbd"},
		ConfigPaths:  []string{"/etc/mysql/my.cnf", "/etc/my.cnf"},
	},
	{
		Name:         "PostgreSQL",
		ProcessNames: []string{"postgres"},
		ConfigPaths:  []string{"/etc/postgresql/postgresql.conf"},
	},
	{
		Name:         "Postfix",
		ProcessNames: []string{"master"}, // postfix's own master process; ambiguous alone, config path is the real signal
		ConfigPaths:  []string{"/etc/postfix/main.cf"},
	},
	{
		Name:         "Dovecot",
		ProcessNames: []string{"dovecot"},
		ConfigPaths:  []string{"/etc/dovecot/dovecot.conf"},
	},
	{
		Name:         "Sendmail",
		ProcessNames: []string{"sendmail"},
		ConfigPaths:  []string{"/etc/mail/sendmail.cf"},
	},
	{
		Name:         "BIND (DNS)",
		ProcessNames: []string{"named"},
		ConfigPaths:  []string{"/etc/bind/named.conf", "/etc/named.conf"},
	},
	{
		Name:         "vsftpd",
		ProcessNames: []string{"vsftpd"},
		ConfigPaths:  []string{"/etc/vsftpd.conf"},
	},
	{
		Name:         "ProFTPD",
		ProcessNames: []string{"proftpd"},
		ConfigPaths:  []string{"/etc/proftpd/proftpd.conf"},
	},
	{
		Name:         "Samba",
		ProcessNames: []string{"smbd"},
		ConfigPaths:  []string{"/etc/samba/smb.conf"},
	},
	{
		Name:         "NFS",
		ProcessNames: []string{"nfsd", "rpc.nfsd"},
		ConfigPaths:  []string{"/etc/exports"},
	},
	{
		Name:         "ISC DHCP",
		ProcessNames: []string{"dhcpd"},
		ConfigPaths:  []string{"/etc/dhcp/dhcpd.conf"},
	},
	{
		Name:         "SSH",
		ProcessNames: []string{"sshd"},
		ConfigPaths:  []string{"/etc/ssh/sshd_config"},
	},
	{
		Name:         "Docker",
		ProcessNames: []string{"dockerd"},
		ConfigPaths:  []string{"/etc/docker/daemon.json"},
	},
	{
		Name:         "containerd",
		ProcessNames: []string{"containerd"},
		ConfigPaths:  []string{"/etc/containerd/config.toml"},
	},
	{
		Name:         "MongoDB",
		ProcessNames: []string{"mongod"},
		ConfigPaths:  []string{"/etc/mongod.conf"},
	},
	{
		Name:         "Redis",
		ProcessNames: []string{"redis-server"},
		ConfigPaths:  []string{"/etc/redis/redis.conf", "/etc/redis.conf"},
	},
	{
		Name:        "Elasticsearch",
		ConfigPaths: []string{"/etc/elasticsearch/elasticsearch.yml"},
	},
	{
		Name:        "Tomcat",
		ConfigPaths: []string{"/etc/tomcat/server.xml", "/etc/tomcat9/server.xml", "/var/lib/tomcat9/conf/server.xml"},
	},
	{
		Name:        "WordPress",
		ConfigPaths: []string{"/var/www/html/wp-config.php", "/var/www/wordpress/wp-config.php"},
	},
	{
		Name:         "NTP (chrony/ntpd)",
		ProcessNames: []string{"chronyd", "ntpd"},
		ConfigPaths:  []string{"/etc/chrony/chrony.conf", "/etc/chrony.conf", "/etc/ntp.conf"},
	},
	{
		Name:         "SNMP",
		ProcessNames: []string{"snmpd"},
		ConfigPaths:  []string{"/etc/snmp/snmpd.conf"},
	},
	{
		Name:         "RDP (xrdp)",
		ProcessNames: []string{"xrdp", "xrdp-sesman"},
		ConfigPaths:  []string{"/etc/xrdp/xrdp.ini"},
	},
	{
		Name:         "VNC",
		ProcessNames: []string{"Xvnc", "vncserver"},
		ConfigPaths:  []string{"/etc/tigervnc/vncserver.users"},
	},
	{
		Name:         "Firewall",
		ProcessNames: []string{"firewalld"},
		ConfigPaths: []string{
			"/etc/iptables/rules.v4",
			"/etc/sysconfig/iptables",
			"/etc/nftables.conf",
			"/etc/ufw/user.rules",
			"/etc/firewalld/firewalld.conf",
		},
	},
	{
		// Not a service anyone runs, but the file set that decides
		// whether every other login on the box succeeds — worth
		// reporting under detect's "is this watched?" check like
		// anything else.
		Name: "PAM (authentication stack)",
		ConfigPaths: []string{
			"/etc/pam.d/common-auth",
			"/etc/pam.d/system-auth",
			"/etc/pam.d/password-auth",
			"/etc/pam.d/sshd",
			"/etc/pam.d/sudo",
			"/etc/nsswitch.conf",
			"/etc/login.defs",
		},
	},
}

// Finding is what Scan found for one Service.
type Finding struct {
	Unknown        bool // running process with no known service metadata
	Service        Service
	PIDs           []int    // every matching process found, empty if none
	ConfigsPresent []string // subset of Service.ConfigPaths that exist on disk
}

// Detected is true if there's any evidence this service is actually in use
// on this box — running, configured, or both.
func (f Finding) Detected() bool {
	return len(f.PIDs) > 0 || len(f.ConfigsPresent) > 0
}

// Scan checks every KnownServices entry against the box's running processes
// (read from procRoot, normally "/proc") and on-disk config paths. It never
// writes anything — see the package doc.
func Scan(procRoot string) ([]Finding, error) {
	return scanServices(procRoot, KnownServices)
}

// scanServices is Scan's actual logic, parameterized over the service list
// so tests can exercise it against temp files instead of real /etc paths.
func scanServices(procRoot string, services []Service) ([]Finding, error) {
	running, err := runningProcessNames(procRoot)
	if err != nil {
		return nil, err
	}

	findings := make([]Finding, 0, len(services))
	for _, svc := range services {
		f := Finding{Service: svc}

		for _, name := range svc.ProcessNames {
			if pids, ok := running[name]; ok {
				f.PIDs = append(f.PIDs, pids...)
			}
		}
		sort.Ints(f.PIDs)

		for _, path := range svc.ConfigPaths {
			if _, err := os.Stat(path); err == nil {
				f.ConfigsPresent = append(f.ConfigsPresent, path)
			}
		}

		findings = append(findings, f)
	}

	known := map[string]bool{}
	for _, svc := range services {
		for _, name := range svc.ProcessNames {
			known[name] = true
		}
	}
	var unknown []string
	for name := range running {
		if !known[name] {
			unknown = append(unknown, name)
		}
	}
	sort.Strings(unknown)
	for _, name := range unknown {
		pids := running[name]
		sort.Ints(pids)
		findings = append(findings, Finding{Service: Service{Name: name, ProcessNames: []string{name}}, PIDs: pids, Unknown: true})
	}
	return findings, nil
}

// runningProcessNames maps each distinct /proc/<pid>/comm value to every
// pid presenting it. comm is read directly rather than shelling out to ps,
// consistent with the rest of Warden never trusting an external binary for
// something this cheap to read itself (see docs/DESIGN.md's threat model).
func runningProcessNames(procRoot string) (map[string][]int, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}

	names := map[string][]int{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a pid directory (self, net, etc.)
		}

		comm, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "comm"))
		if err != nil {
			continue // process exited between ReadDir and here, or unreadable
		}

		name := strings.TrimSpace(string(comm))
		names[name] = append(names[name], pid)
	}

	return names, nil
}
