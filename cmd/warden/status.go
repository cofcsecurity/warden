package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"warden/internal/audit"
	"warden/internal/manifest"
	"warden/internal/store"
)

// statusCmd is the read-only report, locally and over the team key. Its
// --json form is the contract seer reads (`seer warden status`); add
// fields freely, but do not rename or remove them.
func statusCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Report armed state, backups, peers, and the last pass of each timer",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := loadPaths()
			if err != nil {
				return err
			}
			report, err := collectStatus(p)
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			fmt.Fprintln(cmd.OutOrStdout(), report.text())
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the report as JSON")
	return cmd
}

type componentStatus struct {
	Time   time.Time      `json:"time"`
	Action string         `json:"action"`
	Fields map[string]any `json:"fields,omitempty"`
}

type tierStatus struct {
	Generation     int       `json:"generation"`
	CreatedAt      time.Time `json:"created_at,omitzero"`
	Files          int       `json:"files"`
	MissingObjects int       `json:"missing_objects"`
	Error          string    `json:"error,omitempty"`
}

type statusReport struct {
	Host           string                     `json:"host"`
	Name           string                     `json:"name"`
	Installed      bool                       `json:"installed"`
	Armed          bool                       `json:"armed"`
	ArmedAt        string                     `json:"armed_at,omitempty"`
	AllowFrom      string                     `json:"allow_from,omitempty"`
	BreakGlass     string                     `json:"break_glass_user,omitempty"`
	Ban            string                     `json:"ban"`
	Lock           string                     `json:"lock"`
	Peers          []string                   `json:"peers"`
	Tiers          map[string]tierStatus      `json:"tiers"`
	Components     map[string]componentStatus `json:"components"`
	PendingReloads int                        `json:"pending_reloads"`
	Quarantined    int                        `json:"quarantined"`
	BackupHealth   string                     `json:"backup_health"`
}

// statusComponents are the periodic jobs whose last run status reports. A
// stale time on any of them means its triggers stopped firing.
var statusComponents = []string{"watch", "sentinel", "snapshot", "scan", "replicate"}

func collectStatus(p paths) (statusReport, error) {
	host, _ := os.Hostname()
	name, _ := binaryName()
	r := statusReport{
		Host:       host,
		Name:       name,
		Installed:  cfg.TeamKey != "",
		AllowFrom:  cfg.AllowFrom,
		BreakGlass: cfg.BreakGlassUser,
		Ban:        cfg.Ban,
		Lock:       cfg.Lock,
		Peers:      []string{},
		Tiers:      map[string]tierStatus{},
		Components: map[string]componentStatus{},
	}
	for _, peer := range cfg.Peers {
		r.Peers = append(r.Peers, peer.URL)
	}

	armed, err := isArmed(p)
	if err != nil {
		return r, err
	}
	r.Armed = armed
	if armed {
		if data, err := os.ReadFile(p.armedMarkerPath); err == nil {
			r.ArmedAt = strings.TrimSpace(string(data))
		}
	}

	local := store.Open(p.storeRoot)
	for _, tier := range []snapshotTier{tierConfig, tierData} {
		m, err := manifest.New(p.manifestPathForTier(tier))
		if err != nil {
			r.Tiers[string(tier)] = tierStatus{Error: err.Error()}
			continue
		}
		ts := tierStatus{Generation: m.Generation, CreatedAt: m.CreatedAt, Files: len(m.Records)}
		for _, rec := range m.Records {
			if !local.Has(rec.Hash) {
				ts.MissingObjects++
			}
		}
		r.Tiers[string(tier)] = ts
	}

	entries, err := audit.Read(p.auditLogPath)
	if err != nil {
		return r, err
	}
	for _, e := range entries {
		if e.Action == "pass" {
			r.Components[e.Component] = componentStatus{Time: e.Time, Action: e.Action, Fields: e.Fields}
		}
	}

	if q, err := loadReloadQueue(p); err == nil {
		r.PendingReloads = len(q.Units)
	}
	if entries, err := os.ReadDir(p.quarantineDir); err == nil {
		r.Quarantined = len(entries)
	}
	r.BackupHealth = backupHealthSummary(p)
	return r, nil
}

func (r statusReport) text() string {
	var b strings.Builder
	if r.Armed {
		fmt.Fprintf(&b, "armed: yes since %s (auto-restore is on)\n", r.ArmedAt)
	} else {
		fmt.Fprintf(&b, "armed: NO (drift is only flagged; run 'arm' once hardening is done and scoring works)\n")
	}
	if !r.Installed {
		fmt.Fprintf(&b, "installed: no runtime config found (run 'install')\n")
	}
	allow := r.AllowFrom
	if allow == "" {
		allow = "not set"
	}
	fmt.Fprintf(&b, "team access from: %s\n", allow)
	if r.BreakGlass != "" {
		fmt.Fprintf(&b, "break-glass account: %s\n", r.BreakGlass)
	}
	fmt.Fprintf(&b, "responses: ban=%s lock=%s\n", r.Ban, r.Lock)
	if len(r.Peers) == 0 {
		fmt.Fprintf(&b, "peers: none (backups exist on this box only; see 'pair')\n")
	} else {
		fmt.Fprintf(&b, "peers: %s\n", strings.Join(r.Peers, ", "))
	}
	for _, tier := range []snapshotTier{tierConfig, tierData} {
		ts := r.Tiers[string(tier)]
		switch {
		case ts.Error != "":
			fmt.Fprintf(&b, "%s snapshot: invalid: %s\n", tier, ts.Error)
		case ts.Generation == 0:
			fmt.Fprintf(&b, "%s snapshot: none\n", tier)
		default:
			fmt.Fprintf(&b, "%s snapshot: generation %d, %d file(s), taken %s, missing objects %d\n", tier, ts.Generation, ts.Files, ts.CreatedAt.Format(time.RFC3339), ts.MissingObjects)
		}
	}
	for _, c := range statusComponents {
		e, ok := r.Components[c]
		if !ok {
			fmt.Fprintf(&b, "last %s: none recorded\n", c)
			continue
		}
		fmt.Fprintf(&b, "last %s: %s %v\n", c, e.Time.Format(time.RFC3339), e.Fields)
	}
	fmt.Fprintf(&b, "pending reloads: %d\n", r.PendingReloads)
	if r.Quarantined > 0 {
		fmt.Fprintf(&b, "quarantined files: %d (see %s)\n", r.Quarantined, "the state directory's quarantine/")
	}
	fmt.Fprintf(&b, "backup health: %s", r.BackupHealth)
	return b.String()
}
