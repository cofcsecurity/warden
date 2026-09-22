package restore

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"warden/internal/manifest"
	"warden/internal/store"
)

type fakeController struct {
	active     bool
	calls      []string
	startCheck func()
}

func (c *fakeController) Active(string) (bool, error) { return c.active, nil }
func (c *fakeController) Stop(string) error           { c.calls = append(c.calls, "stop"); return nil }
func (c *fakeController) Start(string) error {
	c.calls = append(c.calls, "start")
	if c.startCheck != nil {
		c.startCheck()
	}
	return nil
}
func TestServiceTransactionValidatesAllFilesAndRollsBack(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprint(reject), func(t *testing.T) {
			dir := t.TempDir()
			st, err := store.New(dir)
			if err != nil {
				t.Fatal(err)
			}
			hash, err := st.Put([]byte("approved"))
			if err != nil {
				t.Fatal(err)
			}
			var entries []PlanEntry
			for _, name := range []string{"a", "b"} {
				p := filepath.Join(dir, name)
				if err := os.WriteFile(p, []byte("previous"), 0600); err != nil {
					t.Fatal(err)
				}
				entries = append(entries, PlanEntry{Path: p, TargetHash: hash, TargetMode: 0640, Changed: true})
			}
			ctrl := &fakeController{active: true}
			r := New(st, func(string) (string, bool) { return "example", true })
			r.Control = ctrl
			r.Validate = func(string) error {
				for _, e := range entries {
					got, _ := os.ReadFile(e.Path)
					if string(got) != "approved" {
						t.Fatal("validated partial restore")
					}
				}
				if reject {
					return fmt.Errorf("invalid config")
				}
				return nil
			}
			ctrl.startCheck = func() {
				want := "approved"
				if reject {
					want = "previous"
				}
				for _, e := range entries {
					got, _ := os.ReadFile(e.Path)
					if string(got) != want {
						t.Fatal("started service before complete publication or rollback")
					}
				}
			}
			results := r.Apply(entries)
			for _, res := range results {
				if (res.Err != nil) != reject {
					t.Fatalf("result=%+v", res)
				}
			}
			if fmt.Sprint(ctrl.calls) != "[stop start]" {
				t.Fatal(ctrl.calls)
			}
		})
	}
}
func TestModeOnlyRestorePreservesInactiveService(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "file")
	if err := os.WriteFile(p, []byte("same"), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Generate([]string{p}, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0777); err != nil {
		t.Fatal(err)
	}
	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Put([]byte("same"))
	entries, err := Plan(m, p)
	if err != nil {
		t.Fatal(err)
	}
	ctrl := &fakeController{}
	r := New(st, func(string) (string, bool) { return "example", true })
	r.Control = ctrl
	results := r.Apply(entries)
	if results[0].Err != nil {
		t.Fatal(results[0].Err)
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0600 || len(ctrl.calls) != 0 {
		t.Fatalf("mode=%v calls=%v", info.Mode(), ctrl.calls)
	}
}
