package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"warden/internal/replicate"
)

func receiverCmd() *cobra.Command {
	var root, key, source string
	cmd := &cobra.Command{Use: "receive", Short: "Serve one restricted backup request", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		if original := os.Getenv("SSH_ORIGINAL_COMMAND"); original != "" && original != replicate.ReceiverCommand {
			return fmt.Errorf("unsupported SSH command")
		}
		if root == "" {
			return fmt.Errorf("receiver root is required")
		}
		var public ed25519.PublicKey
		if key != "" {
			data, err := base64.StdEncoding.DecodeString(key)
			if err != nil || len(data) != ed25519.PublicKeySize || source == "" {
				return fmt.Errorf("invalid receiver key or source")
			}
			public = data
		}
		r, err := replicate.NewReceiver(root, public, source)
		if err != nil {
			return err
		}
		defer r.Close()
		return r.Serve(c.InOrStdin(), c.OutOrStdout())
	}}
	cmd.Flags().StringVar(&root, "root", "", "Administrator-owned per-source backup root")
	cmd.Flags().StringVar(&key, "public-key", "", "Pinned base64 Ed25519 manifest public key")
	cmd.Flags().StringVar(&source, "source", "", "Expected manifest source identity")
	return cmd
}
