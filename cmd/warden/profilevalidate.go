package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"warden/internal/detect"
	"warden/internal/fsutil"

	"github.com/spf13/cobra"
)

var ignoredProcesses = map[string]bool{}

// systemDaemons are ubiquitous OS processes that are never scored
// services, so detect and profile validate don't report them as unknown.
var systemDaemons = map[string]bool{
	"systemd": true, "dbus-daemon": true, "dbus-broker": true, "dbus-broker-lau": true,
	"agetty": true, "login": true, "cron": true, "crond": true, "atd": true,
	"rsyslogd": true, "irqbalance": true, "polkitd": true, "udisksd": true,
	"networkd-dispatch": true, "NetworkManager": true, "wpa_supplicant": true,
	"chronyd": true, "auditd": true, "multipathd": true, "unattended-upgr": true,
	"gdm3": true, "sudo": true, "su": true, "seer": true, "warden": true, "accounts-daemon": true, "rtkit-daemon": true, "bash": true, "sh": true,
}

// ignoredProcess reports whether a process name should not be reported as
// an unknown process: the profile's ignore list, common system daemons, and
// the systemd-* family.
func ignoredProcess(name string) bool {
	if exe, err := os.Executable(); err == nil {
		// comm is the executable name cut to 15 characters.
		own := filepath.Base(exe)
		if len(own) > 15 {
			own = own[:15]
		}
		if name == own {
			return true
		}
	}
	return ignoredProcesses[name] || systemDaemons[name] || strings.HasPrefix(name, "systemd-") || strings.HasPrefix(name, "(sd-pam")
}

type profileReport struct {
	Issues      []string `json:"issues"`
	Attribution string   `json:"attribution"`
	Peers       int      `json:"readable_peers"`
}

func profileCmd() *cobra.Command {
	root := &cobra.Command{Use: "profile", Short: "Inspect the host protection profile"}
	var strict bool
	cmd := &cobra.Command{Use: "validate", Short: "Check coverage, services, logs, and backup connectivity", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		p, err := loadPaths()
		if err != nil {
			return err
		}
		report := validateProfile(p)
		if err := json.NewEncoder(c.OutOrStdout()).Encode(report); err != nil {
			return err
		}
		if strict && len(report.Issues) > 0 {
			return fmt.Errorf("profile validation found %d issues", len(report.Issues))
		}
		return nil
	}}
	cmd.Flags().BoolVar(&strict, "strict", false, "Return failure when any coverage or readiness issue exists")
	root.AddCommand(cmd)
	return root
}
func validateProfile(p paths) profileReport {
	report := profileReport{}
	paths := map[string]bool{}
	for _, entry := range configTierPaths {
		if coveredBy(dataTierPaths, entry) {
			report.Issues = append(report.Issues, "path in both tiers: "+entry)
		}
	}
	// Absent entries are normal (the defaults cover many distros); only
	// what is present here is checked.
	for _, list := range [][]string{watchedFiles(), pathsForTier(tierData)} {
		for _, path := range list {
			paths[path] = true
			if _, err := os.Lstat(path); err != nil {
				report.Issues = append(report.Issues, "unreadable path: "+path)
				continue
			}
			if len(pathServices[path]) > 0 {
				if _, ok := serviceForPath(path); !ok {
					report.Issues = append(report.Issues, "no installed mapped unit: "+path)
				}
			}
		}
	}
	findings, err := detect.Scan(procRoot)
	if err != nil {
		report.Issues = append(report.Issues, "service detection: "+err.Error())
	}
	for _, f := range findings {
		if !f.Detected() {
			continue
		}
		if f.Unknown {
			if ignoredProcess(f.Service.Name) {
				continue
			}
			report.Issues = append(report.Issues, "unknown running process: "+f.Service.Name)
			continue
		}
		covered := false
		for _, path := range f.ConfigsPresent {
			if paths[path] {
				covered = true
				if len(pathServices[path]) == 0 {
					report.Issues = append(report.Issues, "service config has no reload mapping: "+path)
				}
			} else {
				report.Issues = append(report.Issues, "uncovered config: "+path)
			}
		}
		if !covered {
			report.Issues = append(report.Issues, "detected service not covered: "+f.Service.Name)
		}
	}
	if path, ok := findAuthLog(); ok {
		f, err := fsutil.OpenRegular(path)
		if err != nil {
			report.Issues = append(report.Issues, "auth log unavailable: "+err.Error())
		} else {
			f.Close()
			report.Attribution = path
		}
	} else {
		now := time.Now()
		if _, err := journalSessions(now, now); err != nil {
			report.Issues = append(report.Issues, "journal unavailable: "+err.Error())
		} else {
			report.Attribution = "journald"
		}
	}
	recovery := newBackupRecovery(p, nil)
	defer recovery.Close()
	if len(recovery.sources) == 0 {
		report.Issues = append(report.Issues, "no backup replicas configured")
	}
	for _, src := range recovery.sources {
		target, err := recovery.target(src)
		if err == nil {
			_, err = target.ManifestGenerations("config")
		}
		if err != nil {
			report.Issues = append(report.Issues, "replica unreadable: "+src.url+": "+err.Error())
		} else {
			report.Peers++
		}
	}
	sort.Strings(report.Issues)
	return report
}
