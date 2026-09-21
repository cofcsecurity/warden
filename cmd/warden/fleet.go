package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"warden/internal/heartbeat"
)

func fleetCmd() *cobra.Command {
	var fromDir string

	cmd := &cobra.Command{
		Use:   "fleet",
		Short: "Show this box and every peer that reports to it, newest heartbeat first",
		Long: `One place to see whether the whole defended set is still healthy,
instead of opening a session per box and running 'status' on each.

Reads the heartbeats other boxes leave here every time they replicate
(see docs/DESIGN.md's heartbeat section) plus this box's own current
state. A box that has gone completely dark — powered off, cut off, or
with every timer killed — can't report that itself; what shows up here
is the absence of its heartbeat, which is the point.

Which boxes appear depends on the replication topology: every box that
replicates TO this one reports here. In the documented ring, that's
this box's two neighbors. If the team wants one box to see everything,
point every box's REPLICATE_TARGETS at it as well, and run this there.

Never acts on what it reads. A heartbeat is written by whatever account
receives replication, so anyone who can write in that directory can
forge one — this is a report for a human, not an input to anything
automatic.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := loadPaths()
			if err != nil {
				return err
			}
			return runFleet(os.Stdout, p, fromDir, time.Now())
		},
	}
	cmd.Flags().StringVar(&fromDir, "from", "", "directory holding peers' replication roots (default: the replication account's home, auto-detected)")
	return cmd
}

func runFleet(w io.Writer, p paths, fromDir string, now time.Time) error {
	self, err := collectHeartbeat(p, now)
	if err != nil {
		return err
	}

	fmt.Fprintln(w, "==> This box")
	printBeatLine(w, self, now, false)

	globs := inboundHeartbeatGlobs
	if fromDir != "" {
		globs = heartbeatGlobsUnder(fromDir)
	}

	beats, err := inboundHeartbeats(globs)
	if err != nil {
		return err
	}

	// A box's own beat can legitimately show up in its own receiving
	// directory (a two-box setup where each replicates to the other, or
	// a file:// target on shared media), and reporting this box twice —
	// once live, once from a copy that's up to 15 minutes old — would
	// read as two boxes disagreeing about one host.
	var peers []heartbeat.Beat
	for _, b := range beats {
		if b.Host != self.Host {
			peers = append(peers, b)
		}
	}

	fmt.Fprintln(w, "\n==> Peers reporting to this box")
	if len(peers) == 0 {
		fmt.Fprintln(w, "  none yet.")
		fmt.Fprintln(w, "  Peers appear here once they replicate TO this box at least once. If that's")
		fmt.Fprintln(w, "  expected already, check that their REPLICATE_TARGETS point here, that their")
		fmt.Fprintln(w, "  build includes heartbeats, and that their replication root is under a home")
		fmt.Fprintf(w, "  directory (searched: %s) — otherwise pass --from with the right directory.\n", strings.Join(globs, ", "))
		return nil
	}

	stale := 0
	for _, b := range peers {
		isStale := b.Stale(now, heartbeatStaleGrace)
		if isStale {
			stale++
		}
		printBeatLine(w, b, now, isStale)
	}

	if stale > 0 {
		fmt.Fprintf(w, "\n%d peer(s) above are overdue. That can be a reboot or a network blip — or a box\nthat's been taken down or had its timers killed. Check them before assuming the first.\n", stale)
	}
	return nil
}

// printBeatLine renders one box: its identity and age on the first line,
// what it was doing on the second. Two lines rather than one wide table
// row, since this is read in an 80-column SSH session as often as not.
func printBeatLine(w io.Writer, b heartbeat.Beat, now time.Time, stale bool) {
	host := b.Host
	if host == "" {
		host = "(unknown host)"
	}

	armed := "DISARMED"
	if b.Armed {
		armed = "armed"
	}

	age := "just now"
	if b.WrittenAt.IsZero() {
		age = "never reported"
	} else if d := b.Age(now); d > time.Second {
		age = d.Round(time.Second).String() + " ago"
	}

	marker := " "
	if stale {
		marker = "!"
		age += "  ** OVERDUE **"
	}

	fmt.Fprintf(w, "%s %-24s %-9s gen %-4d bans %-3d locks %-3d %s\n",
		marker, host, armed, b.Generation, b.ActiveBans, b.ActiveLocks, age)
	fmt.Fprintf(w, "    last: %s\n", summarizeLastPass(b, now))
}

// summarizeLastPass renders each periodic component's last run as an age,
// in a fixed order, with "never" for one that has no recorded pass at
// all — a component that has never run is a different problem from one
// that ran an hour ago, and both matter more than the exact timestamps.
func summarizeLastPass(b heartbeat.Beat, now time.Time) string {
	parts := make([]string, 0, len(heartbeatComponents))
	for _, component := range heartbeatComponents {
		at, ok := b.LastPass[component]
		switch {
		case !ok || at.IsZero():
			parts = append(parts, component+"=never")
		default:
			parts = append(parts, fmt.Sprintf("%s=%s", component, now.Sub(at).Round(time.Second)))
		}
	}
	return strings.Join(parts, "  ")
}
