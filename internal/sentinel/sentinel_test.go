package sentinel

import (
	"errors"
	"testing"
)

func TestRunRecreatesMissingRegistrations(t *testing.T) {
	systemdPresent := true
	cronPresent := false
	cronRecreated := false

	regs := []Registration{
		{
			Name:     "systemd-timer",
			Check:    func() (bool, error) { return systemdPresent, nil },
			Recreate: func() error { t.Fatal("should not recreate an already-present registration"); return nil },
		},
		{
			Name:  "cron-entry",
			Check: func() (bool, error) { return cronPresent, nil },
			Recreate: func() error {
				cronRecreated = true
				cronPresent = true
				return nil
			},
		},
	}

	s := New(regs, nil)
	res, err := s.Run()
	if err != nil {
		t.Fatal(err)
	}

	if !cronRecreated {
		t.Errorf("expected cron-entry to be recreated")
	}
	if len(res.OK) != 1 || res.OK[0] != "systemd-timer" {
		t.Errorf("expected systemd-timer to be reported OK, got %+v", res.OK)
	}
	if len(res.Recreated) != 1 || res.Recreated[0] != "cron-entry" {
		t.Errorf("expected cron-entry to be reported recreated, got %+v", res.Recreated)
	}
}

func TestRunContinuesPastFailures(t *testing.T) {
	laterRepaired := false
	regs := []Registration{
		{Name: "broken-check", Check: func() (bool, error) { return false, errors.New("boom") }},
		{Name: "broken-repair", Check: func() (bool, error) { return false, nil }, Recreate: func() error { return errors.New("nope") }},
		{Name: "later", Check: func() (bool, error) { return false, nil }, Recreate: func() error { laterRepaired = true; return nil }},
	}
	res, err := New(regs, nil).Run()
	if err == nil {
		t.Fatal("expected the joined errors")
	}
	if !laterRepaired || len(res.Recreated) != 1 {
		t.Fatalf("a failure must not stop later repairs: %+v", res)
	}
}

func TestRunFlagsWithoutRepair(t *testing.T) {
	regs := []Registration{
		{Name: "flag-only", Check: func() (bool, error) { return false, nil }, Problems: func() []string { return []string{"x"} }},
	}
	res, err := New(regs, nil).Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Flagged) != 1 || res.Flagged[0] != "flag-only" {
		t.Fatalf("flagged = %+v", res.Flagged)
	}
}
