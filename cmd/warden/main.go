// Warden provides resilient, audited persistence and automatic
// backup/restore for a host under active attack in a CCDC-style
// competition. See docs/DESIGN.md for the full design.
package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"warden/internal/fsutil"

	"github.com/spf13/cobra"
)

// Build-time configuration, set via -ldflags -X main.<field>=<value>.
// These stay empty in a dev build; a real deploy build supplies all of
// them.
var (
	buildTeamPubKey string
	buildTeamFromIP string
	buildTOTPSecret string

	// buildReplicateTargets encodes one or more replication peers, e.g. for
	// a mesh across several defended boxes rather than a single backup
	// destination — see docs/DEPLOYMENT.md's "Replication topology"
	// section. Format: "<url>||<hostkey>;;<url>||<hostkey>...", where
	// <hostkey> is empty for a file:// target. Parsed by
	// parseReplicateTargets in cmd/warden/replicate.go.
	buildReplicateTargets string

	// buildReplicateKey is a base64-encoded PEM private key, generated only
	// for replication (see docs/DESIGN.md's replicate section) — never a
	// personal or team login key. One key authenticates to every
	// configured ssh:// target; they're all team-controlled boxes.
	buildReplicateKey string

	// buildAutobanEnabled gates watch's auto-ban reaction (see react.go)
	// behind an explicit opt-in, the same way REPLICATE_TARGETS gates
	// replication — off (empty) unless a build deliberately sets it,
	// since firewalling an IP is a more assertive defensive posture than
	// the rest of Warden. Any non-empty value turns it on; attribution
	// still always runs and always logs/flags regardless of this flag —
	// only the actual ban is gated.
	buildAutobanEnabled string

	// buildAutolockEnabled gates scan.go's account-lock reaction, the
	// same way buildAutobanEnabled gates the IP-ban one — separately,
	// since locking a local account is a materially different risk (it
	// can hit a legitimate teammate's own competition-issued account on
	// a false positive, where IP-autoban structurally can't hit the
	// team's own IP). Off (empty) unless a build deliberately sets it.
	buildAutolockEnabled string

	// buildSafeAccounts is a comma-separated list of local account names
	// scan.go's auto-lock and the manual lock-account command both
	// refuse to touch, on top of the always-hardcoded root/opmenu
	// exclusion — the team's own operating account(s) on this box, and
	// the scoring engine's account if it uses one. There's no way to
	// infer either automatically (unlike TEAM_FROM_IP for IP-autoban):
	// this extends the same manual, team-configured safety
	// responsibility docs/DEPLOYMENT.md step 0 already asks for around
	// configTierPaths/ConfirmFirst, to the account-lock surface.
	buildSafeAccounts string
)

func main() {
	var logLevel = new(slog.LevelVar)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	var verbose bool

	root := &cobra.Command{
		Use:   "warden",
		Short: "Warden provides resilient persistence and backup/restore for a defended host",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if verbose {
				logLevel.Set(slog.LevelDebug)
			}
			if cmd.Name() == "receive" {
				return nil
			}
			return loadHostProfile(hostProfilePath)
		},
	}
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose logging")

	root.AddCommand(manifestKeygenCmd())
	root.AddCommand(profileCmd())
	root.AddCommand(receiverCmd())
	root.AddCommand(verifyBackupsCmd())
	root.AddCommand(snapshotCmd())
	root.AddCommand(replicateCmd())
	root.AddCommand(retrieveCmd())
	root.AddCommand(watchCmd())
	root.AddCommand(restoreCmd())
	root.AddCommand(sentinelCheckCmd())
	root.AddCommand(opmenuCmd())
	root.AddCommand(debugConfigCmd())
	root.AddCommand(armCmd())
	root.AddCommand(disarmCmd())
	root.AddCommand(detectCmd())
	root.AddCommand(banCmd())
	root.AddCommand(unbanCmd())
	root.AddCommand(acceptCmd())
	root.AddCommand(alertsCmd())
	root.AddCommand(rotateSecretCmd())
	root.AddCommand(uninstallCmd())
	root.AddCommand(scanCmd())
	root.AddCommand(fleetCmd())
	root.AddCommand(statusCmd())
	root.AddCommand(lockAccountCmd())
	root.AddCommand(unlockAccountCmd())

	// Serialize mutations across timer, manual, and response commands.
	for _, cmd := range root.Commands() {
		switch cmd.Name() {
		case "snapshot", "accept", "arm", "disarm", "retrieve", "restore", "watch", "replicate", "scan", "sentinel-check", "ban", "unban", "lock-account", "unlock-account", "verify-backups":
			run := cmd.RunE
			cmd.RunE = func(c *cobra.Command, args []string) error {
				if c.Name() == "verify-backups" {
					repair, _ := c.Flags().GetBool("repair")
					record, _ := c.Flags().GetBool("record")
					if !repair && !record {
						return run(c, args)
					}
				}
				if c.Name() == "restore" || c.Name() == "retrieve" {
					apply, _ := c.Flags().GetBool("apply")
					if !apply {
						return run(c, args)
					}
				}
				p, err := loadPaths()
				if err != nil {
					return err
				}
				if err := os.MkdirAll(p.storeRoot, 0700); err != nil {
					return err
				}
				release, err := fsutil.Lock(filepath.Join(p.storeRoot, "operation.lock"))
				if err != nil {
					return err
				}
				defer release()
				return run(c, args)
			}
		}
	}
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
