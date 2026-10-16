package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"warden/internal/replicate"
)

// receiverCmd is the forced command a paired source's key runs on this
// box (see `pair accept`). It serves exactly one protocol request into
// that source's own directory and nothing else: no shell, no delete.
func receiverCmd() *cobra.Command {
	var source string
	cmd := &cobra.Command{
		Use:    "receive",
		Short:  "Serve one backup request from a paired source (forced command only)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if original := os.Getenv("SSH_ORIGINAL_COMMAND"); original != "" && original != replicate.ReceiverCommand {
				return fmt.Errorf("unsupported SSH command")
			}
			if !validSourceName(source) {
				return fmt.Errorf("receive: invalid source %q", source)
			}
			p, err := loadPaths()
			if err != nil {
				return err
			}
			r, err := replicate.NewReceiver(filepath.Join(p.peerRoot, source), peerQuotaBytes())
			if err != nil {
				return err
			}
			defer r.Close()
			return r.Serve(c.InOrStdin(), c.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&source, "source", "", "the paired source box this key belongs to")
	return cmd
}
