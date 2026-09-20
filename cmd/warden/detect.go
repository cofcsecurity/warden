package main

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"warden/internal/detect"
)

// procRoot is a var so a build-time -ldflags override isn't needed just to
// point this at a fake /proc in a test — nothing else in cmd/warden reads
// it.
var procRoot = "/proc"

func detectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "detect",
		Short: "Scan for running services and config files this box is likely defending",
		Long: `Read-only. Checks the box's running processes and on-disk config paths
against a list of services common on CCDC-style images (web, database,
mail, DNS, file transfer, DHCP, SSH) and reports what it finds, alongside
whether each one is already in this build's watch list.

This never changes anything — it's meant to answer "what should
cmd/warden/config.go's watch list actually cover" before a competition,
not to reconfigure Warden automatically. See docs/PLAN.md Phase 1.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDetect()
		},
	}
}

func runDetect() error {
	findings, err := detect.Scan(procRoot)
	if err != nil {
		return fmt.Errorf("detect: %w", err)
	}

	watched := map[string]bool{}
	for _, p := range configTierPaths {
		watched[p] = true
	}

	sort.Slice(findings, func(i, j int) bool {
		// Detected services first, then alphabetical within each group —
		// what needs a decision belongs at the top.
		if findings[i].Detected() != findings[j].Detected() {
			return findings[i].Detected()
		}
		return findings[i].Service.Name < findings[j].Service.Name
	})

	detectedCount := 0
	unwatchedCount := 0

	for _, f := range findings {
		if !f.Detected() {
			continue
		}
		detectedCount++

		status := "running"
		if len(f.PIDs) == 0 {
			status = "configured, not running"
		}
		fmt.Printf("%-16s %s\n", f.Service.Name, status)

		for _, cfg := range f.ConfigsPresent {
			marker := "  watched"
			if !watched[cfg] {
				marker = "  NOT in watch list"
				unwatchedCount++
			}
			fmt.Printf("  %-40s %s\n", cfg, marker)
		}
		if len(f.ConfigsPresent) == 0 {
			fmt.Printf("  (running, but no known config path found on disk — check %s's actual config location)\n", f.Service.Name)
		}
	}

	if detectedCount == 0 {
		fmt.Println("nothing from the known-services list was detected on this box.")
		return nil
	}

	if unwatchedCount > 0 {
		fmt.Printf("\n%d config path(s) above aren't in cmd/warden/config.go's configTierPaths yet — add the ones that matter for this competition's scoring before relying on watch/snapshot to cover them.\n", unwatchedCount)
	}

	return nil
}
