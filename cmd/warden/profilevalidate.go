package main

import (
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"sort"
	"time"
	"warden/internal/detect"
	"warden/internal/fsutil"
)

var ignoredProcesses = map[string]bool{}

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
	for _, list := range [][]string{configTierPaths, dataTierPaths} {
		for _, path := range list {
			if paths[path] {
				report.Issues = append(report.Issues, "conflicting tier or duplicate path: "+path)
			}
			paths[path] = true
			info, err := os.Lstat(path)
			if err != nil {
				report.Issues = append(report.Issues, "missing or unreadable path: "+path)
				continue
			}
			if !info.Mode().IsRegular() {
				report.Issues = append(report.Issues, "non-regular watched path: "+path)
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
			if ignoredProcesses[f.Service.Name] {
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
