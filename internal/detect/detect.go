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
// itself, since sshd_config is already a default watched path.
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
}

// Finding is what Scan found for one Service.
type Finding struct {
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
