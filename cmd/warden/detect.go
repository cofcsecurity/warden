package main

import (
	"fmt"
	"os"
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
		Short: "Report what's currently protected, plus anything found but not yet covered",
		Long: `Read-only, two parts:

1. Every watched path (configTierPaths/dataTierPaths) that actually
   exists on THIS box right now — what's really being protected here,
   as opposed to the full lists in cmd/warden/config.go, most of which
   won't apply to any single box.
2. A scan of running processes and known config paths against services
   common on CCDC-style images (web, database, mail, DNS, file
   transfer, DHCP, SSH), reporting anything found that isn't in part 1
   yet. Unknown running process names are also listed for review.

This never changes anything — it's meant to answer "what should
the host profile actually cover" before a competition,
and to give anyone checking in on the box a plain answer to "what is
Warden actually protecting right now." See docs/PLAN.md Phase 1.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDetect()
		},
	}
}

// protectedPath is one watched path that's confirmed present on this box.
type protectedPath struct {
	Path  string
	Tier  string // "config" or "data"
	Class string // "auto-restore" or "confirm-first"
}

// currentlyProtected reports every entry in configTierPaths/dataTierPaths
// that actually exists on disk right now — a path listed in config.go but
// absent from this particular box isn't protecting anything here, so it's
// left out.
func currentlyProtected() []protectedPath {
	var out []protectedPath
	add := func(paths []string, tier string) {
		for _, p := range paths {
			if _, err := os.Stat(p); err != nil {
				continue
			}
			class := "auto-restore"
			if confirmFirstPaths[p] {
				class = "confirm-first"
			}
			out = append(out, protectedPath{Path: p, Tier: tier, Class: class})
		}
	}
	add(configTierPaths, "config")
	add(dataTierPaths, "data")
	return out
}

func runDetect() error {
	protected := currentlyProtected()
	fmt.Println("==> Currently protected on this box")
	if len(protected) == 0 {
		fmt.Println("  nothing — configTierPaths/dataTierPaths don't match anything present here yet.")
	} else {
		for _, pp := range protected {
			fmt.Printf("  %-40s %-6s %s\n", pp.Path, pp.Tier, pp.Class)
		}
	}

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

	fmt.Println("\n==> Scan: services and unknown processes vs. what's watched")
	for _, f := range findings {
		if !f.Detected() {
			continue
		}
		detectedCount++

		if f.Unknown {
			fmt.Printf("%s  unknown process (PIDs %v); inspect its config and add scored files to /etc/warden/profile.json\n", f.Service.Name, f.PIDs)
			continue
		}
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
		fmt.Printf("\n%d config path(s) above aren't in the config tier yet — add to /etc/warden/profile.json the ones that matter for this competition's scoring before relying on watch/snapshot to cover them.\n", unwatchedCount)
	}

	return nil
}
