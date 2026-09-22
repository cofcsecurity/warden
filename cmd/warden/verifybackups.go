package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
	"sort"
	"time"
	"warden/internal/fsutil"
	"warden/internal/manifest"
	"warden/internal/store"
)

type backupCheck struct {
	Hash   string            `json:"hash"`
	Copies map[string]string `json:"copies"`
}
type backupReport struct {
	LastSuccessfulAt time.Time     `json:"last_successful_at,omitempty"`
	CheckedAt        time.Time     `json:"checked_at"`
	Checks           []backupCheck `json:"objects"`
	Problems         []string      `json:"problems,omitempty"`
	UsableReplicas   int           `json:"usable_replicas"`
	Repaired         int           `json:"repaired"`
	Healthy          bool          `json:"healthy"`
}

func verifyBackupsCmd() *cobra.Command {
	var repair, record bool
	cmd := &cobra.Command{Use: "verify-backups", Short: "Verify active and retained backups on every configured replica", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		p, err := loadPaths()
		if err != nil {
			return err
		}
		report := checkBackups(p, repair)
		if data, err := os.ReadFile(filepath.Join(p.storeRoot, "backup-health.json")); err == nil {
			var previous backupReport
			if json.Unmarshal(data, &previous) == nil {
				report.LastSuccessfulAt = previous.LastSuccessfulAt
			}
		}
		if report.Healthy {
			report.LastSuccessfulAt = report.CheckedAt
		}
		if repair || record {
			data, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				return err
			}
			if err := fsutil.WriteFile(filepath.Join(p.storeRoot, "backup-health.json"), data, 0600); err != nil {
				return err
			}
		}
		if err := json.NewEncoder(c.OutOrStdout()).Encode(report); err != nil {
			return err
		}
		if !report.Healthy {
			return fmt.Errorf("backup verification found missing, corrupt, or unreachable copies")
		}
		return nil
	}}
	cmd.Flags().BoolVar(&repair, "repair", false, "Recover local objects from verified replicas and record results")
	cmd.Flags().BoolVar(&record, "record", false, "Save verification results for status; default only reads")
	return cmd
}
func checkBackups(p paths, repair bool) backupReport {
	report := backupReport{CheckedAt: time.Now().UTC(), Healthy: true}
	r := newBackupRecovery(p, nil)
	defer r.Close()
	sources := []string{"local"}
	usable := map[string]bool{}
	for _, src := range r.sources {
		sources = append(sources, src.url)
		usable[src.url] = true
	}
	problem := func(msg string) { report.Problems = append(report.Problems, msg); report.Healthy = false }
	hashes := map[string]bool{}
	for _, tier := range []snapshotTier{tierConfig, tierData} {
		gens, err := manifest.Generations(p.manifestsDirForTier(tier))
		if err != nil {
			problem(err.Error())
		}
		live, err := manifest.New(p.manifestPathForTier(tier))
		if err != nil {
			problem(err.Error())
			live = &manifest.Manifest{}
		}
		for _, src := range r.sources {
			target, err := r.target(src)
			if err != nil {
				usable[src.url] = false
				problem(src.url + ": unreachable: " + err.Error())
				continue
			}
			remote, err := target.ManifestGenerations(string(tier))
			if err != nil {
				usable[src.url] = false
				problem(src.url + ": " + err.Error())
				continue
			}
			gens = append(gens, remote...)
		}
		unique := map[int]bool{}
		for _, g := range gens {
			unique[g] = true
		}
		gens = nil
		for g := range unique {
			gens = append(gens, g)
		}
		sort.Ints(gens)
		if len(gens) > retainGenerations {
			gens = gens[len(gens)-retainGenerations:]
		}
		selected := map[int]bool{}
		for _, g := range gens {
			selected[g] = true
		}
		if live.Generation > 0 {
			selected[live.Generation] = true
		}
		for generation := range selected {
			m, err := r.manifest(tier, generation)
			if err != nil {
				problem(err.Error())
				continue
			}
			for _, rec := range m.Records {
				hashes[rec.Hash] = true
			}
			canonical, _ := json.Marshal(m)
			for _, src := range r.sources {
				target, err := r.target(src)
				if err != nil {
					continue
				}
				data, err := target.GetManifest(string(tier), generation)
				if err != nil {
					usable[src.url] = false
					problem(fmt.Sprintf("%s: %s manifest %d missing or unreadable", src.url, tier, generation))
					continue
				}
				peer, err := manifest.Parse(data)
				if err == nil {
					err = validateRecoveryManifest(peer, generation)
				}
				if err == nil {
					err = verifyManifest(peer, tier)
				}
				if err != nil {
					usable[src.url] = false
					problem(fmt.Sprintf("%s: invalid manifest %d: %v", src.url, generation, err))
					continue
				}
				normalized, _ := json.Marshal(peer)
				if string(normalized) != string(canonical) {
					usable[src.url] = false
					problem(fmt.Sprintf("%s: conflicting %s generation %d", src.url, tier, generation))
				}
			}
		}
	}
	if len(hashes) == 0 {
		problem("no backed-up objects found")
	}
	var ordered []string
	for hash := range hashes {
		ordered = append(ordered, hash)
	}
	sort.Strings(ordered)
	local := store.Open(p.storeRoot)
	for _, hash := range ordered {
		check := backupCheck{Hash: hash, Copies: map[string]string{}}
		data, localErr := local.Get(hash)
		if localErr == nil {
			check.Copies["local"] = "verified"
		} else if errors.Is(localErr, os.ErrNotExist) {
			check.Copies["local"] = "missing"
		} else {
			check.Copies["local"] = "corrupt"
		}
		for _, src := range r.sources {
			target, err := r.target(src)
			if err != nil {
				check.Copies[src.url] = "unreachable"
				continue
			}
			has, err := target.Has(hash)
			if err != nil {
				check.Copies[src.url] = "unreachable"
				usable[src.url] = false
				continue
			}
			if !has {
				check.Copies[src.url] = "missing"
				usable[src.url] = false
				continue
			}
			copy, err := target.Get(hash)
			if err != nil {
				check.Copies[src.url] = "unreadable"
				usable[src.url] = false
				continue
			}
			if err := store.Verify(hash, copy); err != nil {
				check.Copies[src.url] = "corrupt"
				usable[src.url] = false
				continue
			}
			check.Copies[src.url] = "verified"
			if localErr != nil && data == nil {
				data = copy
			}
		}
		if repair && localErr != nil && data != nil {
			if _, err := local.Put(data); err != nil {
				problem(err.Error())
			} else {
				check.Copies["local"] = "repaired"
				report.Repaired++
			}
		}
		for _, source := range sources {
			state := check.Copies[source]
			if state != "verified" && state != "repaired" {
				report.Healthy = false
			}
		}
		report.Checks = append(report.Checks, check)
	}
	for _, ok := range usable {
		if ok && len(hashes) > 0 {
			report.UsableReplicas++
		}
	}
	sort.Strings(report.Problems)
	return report
}
func backupHealthSummary(p paths) string {
	data, err := os.ReadFile(filepath.Join(p.storeRoot, "backup-health.json"))
	if os.IsNotExist(err) {
		return "no verification recorded (run verify-backups --record)"
	}
	if err != nil {
		return err.Error()
	}
	var report backupReport
	if err := json.Unmarshal(data, &report); err != nil {
		return "invalid verification record"
	}
	return fmt.Sprintf("checked at %s: healthy=%t, usable replicas=%d, repaired=%d, last successful=%s (recorded state)", report.CheckedAt.Format(time.RFC3339), report.Healthy, report.UsableReplicas, report.Repaired, report.LastSuccessfulAt.Format(time.RFC3339))
}
