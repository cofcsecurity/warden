package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/spf13/cobra"
)

func manifestKeygenCmd() *cobra.Command {
	return &cobra.Command{Use: "manifest-keygen", Short: "Generate a per-source Ed25519 manifest key pair as JSON", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		return json.NewEncoder(c.OutOrStdout()).Encode(map[string]string{"private_key": base64.StdEncoding.EncodeToString(private), "public_key": base64.StdEncoding.EncodeToString(public)})
	}}
}
