package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// statusCmd is the same read-only report opmenu's `status` returns over
// SSH, available as a plain local command too. runStatus itself is
// unchanged and shared, so the two can't drift into saying different
// things about the same box.
//
// It existed only over opmenu for no better reason than that being where
// it was first needed — which left the most common question anyone has in
// a local shell ("is this box armed, and are its timers still running?")
// answerable only by spending a TOTP code from off-box, or by reading the
// audit log by hand.
func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report armed state, manifest generation, and the last pass of each timer",
		Long: `Read-only summary of this box: whether auto-restore is armed, whether a
static second factor is set, the current manifest generation and when it
was taken, and the last recorded run of watch, sentinel-check, scan and
replicate.

A stale timestamp on any of those is the signal worth acting on — it
means that component's timer has stopped firing, which looks exactly
like a quiet box until you look here. 'warden fleet' answers the same
question for the peers that replicate to this box.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := loadPaths()
			if err != nil {
				return err
			}
			out, err := runStatus(p)
			if err != nil {
				return err
			}
			fmt.Println(out)
			return nil
		},
	}
}
