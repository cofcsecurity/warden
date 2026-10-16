// Package sentinel keeps Warden's own access and triggers alive. Each
// Registration is one invariant with a check and, usually, a repair. A
// pass checks every invariant and repairs what is broken; one failure
// never stops the rest, since red only has to win one link but we have
// to hold all of them.
package sentinel

import (
	"errors"
	"fmt"

	"warden/internal/audit"
)

// Registration is one thing sentinel checks and can usually re-create.
type Registration struct {
	Name  string
	Check func() (ok bool, err error)
	// Recreate repairs the invariant. Nil means flag only: the problem
	// is reported but not something Warden may change.
	Recreate func() error
	// Problems, when set, explains a failed check for the log.
	Problems func() []string
}

// Sentinel runs one check-and-repair pass over a set of registrations.
type Sentinel struct {
	registrations []Registration
	log           *audit.Logger
}

func New(registrations []Registration, log *audit.Logger) *Sentinel {
	return &Sentinel{registrations: registrations, log: log}
}

// Result reports what one Run pass found and did.
type Result struct {
	OK        []string
	Recreated []string
	Flagged   []string
}

// Run checks every registration, repairing what it can. Errors from
// individual registrations are joined and returned after every
// registration has had its turn.
func (s *Sentinel) Run() (*Result, error) {
	res := &Result{}
	var errs []error

	for _, reg := range s.registrations {
		ok, err := reg.Check()
		if err != nil {
			errs = append(errs, fmt.Errorf("sentinel: check %s: %w", reg.Name, err))
			s.logAction("check-failed", reg, err)
			continue
		}
		if ok {
			res.OK = append(res.OK, reg.Name)
			continue
		}
		if reg.Recreate == nil {
			res.Flagged = append(res.Flagged, reg.Name)
			s.logAction("flagged", reg, nil)
			continue
		}
		problems := describe(reg)
		if err := reg.Recreate(); err != nil {
			errs = append(errs, fmt.Errorf("sentinel: repair %s: %w", reg.Name, err))
			s.logFields("repair-failed", reg.Name, problems, err)
			continue
		}
		res.Recreated = append(res.Recreated, reg.Name)
		s.logFields("recreated", reg.Name, problems, nil)
	}

	return res, errors.Join(errs...)
}

func describe(reg Registration) []string {
	if reg.Problems == nil {
		return nil
	}
	return reg.Problems()
}

func (s *Sentinel) logAction(action string, reg Registration, err error) {
	s.logFields(action, reg.Name, describe(reg), err)
}

func (s *Sentinel) logFields(action, name string, problems []string, err error) {
	if s.log == nil {
		return
	}
	fields := map[string]any{"registration": name}
	if len(problems) > 0 {
		fields["problems"] = problems
	}
	if err != nil {
		fields["error"] = err.Error()
	}
	_ = s.log.Log("sentinel", action, fields)
}
