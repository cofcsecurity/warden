// Package sentinel checks that persistence itself is still alive: the SSH
// key entry, and each of the two independent triggers (systemd timer, cron
// entry) that re-invoke it. It reads registration files directly rather
// than shelling out to systemctl/crontab, since either could be altered.
package sentinel

import (
	"fmt"

	"warden/internal/audit"
)

// Registration is one thing sentinel checks for and can re-create.
type Registration struct {
	Name     string
	Check    func() (present bool, err error)
	Recreate func() error
}

// Sentinel runs one check-and-respawn pass over a set of registrations.
type Sentinel struct {
	registrations []Registration
	log           *audit.Logger
}

// New builds a Sentinel over the given registrations (typically: the
// authorized_keys entry, the systemd timer unit, and the cron entry).
func New(registrations []Registration, log *audit.Logger) *Sentinel {
	return &Sentinel{registrations: registrations, log: log}
}

// Result reports what one Run pass found and fixed.
type Result struct {
	Recreated []string
	OK        []string
}

// Run checks every registration and re-creates whichever is missing.
func (s *Sentinel) Run() (*Result, error) {
	res := &Result{}

	for _, reg := range s.registrations {
		present, err := reg.Check()
		if err != nil {
			return res, fmt.Errorf("sentinel: check %s: %w", reg.Name, err)
		}
		if present {
			res.OK = append(res.OK, reg.Name)
			continue
		}

		if err := reg.Recreate(); err != nil {
			return res, fmt.Errorf("sentinel: recreate %s: %w", reg.Name, err)
		}
		res.Recreated = append(res.Recreated, reg.Name)
		s.logAction(reg.Name)
	}

	return res, nil
}

func (s *Sentinel) logAction(name string) {
	if s.log == nil {
		return
	}
	_ = s.log.Log("sentinel", "recreated", map[string]any{"registration": name})
}
