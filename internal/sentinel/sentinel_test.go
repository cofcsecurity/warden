package sentinel

import "testing"

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
