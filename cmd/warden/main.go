// Warden keeps a defended host alive and recoverable: it holds the team's
// access open, puts watched files back, and keeps backups on peer boxes.
// See docs/DESIGN.md.
package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"warden/internal/fsutil"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

// lockTimeout is how long a command waits for another to finish.
const lockTimeout = 2 * time.Minute

// lockedCommands mutate shared state and take the operation lock, so a
// timer and a manual command never interleave.
var lockedCommands = map[string]bool{
	"snapshot": true, "accept": true, "arm": true, "disarm": true, "retrieve": true,
	"restore": true, "watch": true, "replicate": true, "scan": true, "sentinel-check": true,
	"ban": true, "unban": true, "lock-account": true, "unlock-account": true, "verify-backups": true,
}

func newRootCmd() *cobra.Command {
	var logLevel = new(slog.LevelVar)
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

	var verbose, quiet bool

	root := &cobra.Command{
		Use:           "warden",
		Short:         "Keep a defended host's access, files and backups alive",
		SilenceUsage:  true,
		SilenceErrors: false,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if verbose {
				logLevel.Set(slog.LevelDebug)
			}
			if quiet {
				if devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0); err == nil {
					os.Stdout = devnull
					cmd.SetOut(devnull)
				}
			}
			return prepareCommand(cmd.Name())
		},
	}
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose logging")
	root.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "print nothing but errors")

	for _, c := range []*cobra.Command{
		installCmd(),
		uninstallCmd(),
		configCmd(),
		rekeyCmd(),
		pairCmd(),
		profileCmd(),
		receiverCmd(),
		verifyBackupsCmd(),
		snapshotCmd(),
		replicateCmd(),
		retrieveCmd(),
		watchCmd(),
		restoreCmd(),
		sentinelCheckCmd(),
		opmenuCmd(),
		armCmd(),
		disarmCmd(),
		detectCmd(),
		banCmd(),
		unbanCmd(),
		acceptCmd(),
		accountEditCmd(),
		alertsCmd(),
		scanCmd(),
		statusCmd(),
		lockAccountCmd(),
		unlockAccountCmd(),
		masqCmd(),
	} {
		root.AddCommand(c)
	}

	for _, cmd := range root.Commands() {
		if !lockedCommands[cmd.Name()] {
			continue
		}
		run := cmd.RunE
		cmd.RunE = func(c *cobra.Command, args []string) error {
			if !needsLock(c) {
				return run(c, args)
			}
			p, err := loadPaths()
			if err != nil {
				return err
			}
			if err := os.MkdirAll(p.storeRoot, 0700); err != nil {
				return err
			}
			release, err := fsutil.LockWait(filepath.Join(p.storeRoot, "operation.lock"), lockTimeout)
			if err != nil {
				return err
			}
			defer release()
			return run(c, args)
		}
	}
	return root
}

// needsLock skips the lock for the read-only forms of commands that are
// otherwise mutating.
func needsLock(c *cobra.Command) bool {
	switch c.Name() {
	case "verify-backups":
		repair, _ := c.Flags().GetBool("repair")
		record, _ := c.Flags().GetBool("record")
		return repair || record
	case "restore", "retrieve":
		apply, _ := c.Flags().GetBool("apply")
		return apply
	}
	return true
}

// prepareCommand loads the runtime config and the host profile. Access and
// disarming must keep working when the profile is broken, so those
// commands skip it; opmenu loads it only inside the command it dispatches.
func prepareCommand(command string) error {
	p, err := loadPaths()
	if err != nil {
		return err
	}
	if err := loadRuntimeConfig(p); err != nil && !profileOptional(command) {
		return err
	}
	if profileOptional(command) {
		_ = loadHostProfile(profilePathFor(p))
		return nil
	}
	return loadHostProfile(profilePathFor(p))
}

// profilePathFor is a var so tests can point it at a fixture.
var profilePathFor = func(p paths) string { return p.profilePath }

func profileOptional(command string) bool {
	switch command {
	case "receive", "opmenu", "disarm", "status", "sentinel-check", "install", "uninstall", "config", "rekey", "pair", "help":
		return true
	}
	return false
}

// prepareCommandProfile is kept for tests that exercise profile handling
// directly against a given path.
func prepareCommandProfile(command, path string) error {
	if profileOptional(command) {
		return nil
	}
	return loadHostProfile(path)
}
