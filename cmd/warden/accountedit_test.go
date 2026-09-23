package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"warden/internal/accountedit"
	"warden/internal/accountlock"
	"warden/internal/anomaly"
	"warden/internal/manifest"
	"warden/internal/store"
)

func accountEditFixture(t *testing.T) (paths, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "etc")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	p := paths{storeRoot: filepath.Join(root, "store"), configManifestPath: filepath.Join(root, "config.json"), configManifestsDir: filepath.Join(root, "manifests"), accountLocksPath: filepath.Join(root, "locks.json"), auditLogPath: filepath.Join(root, "audit.jsonl"), anomalyDir: filepath.Join(root, "anomaly")}
	files := map[string]string{
		"passwd":  "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/bash\n",
		"shadow":  "root:$6$root:20000:0:99999:7:::\nalice:$6$old:20000:0:99999:7:::\nbob:$6$bob:20000:0:99999:7:::\n",
		"group":   "root:x:0:\nsudo:x:27:alice\n",
		"gshadow": "root:!::\nsudo:!::alice\n",
	}
	st, err := store.New(p.storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, name := range accountedit.Files {
		path := filepath.Join(dir, name)
		paths = append(paths, path)
		if err := os.WriteFile(path, []byte(files[name]), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Put([]byte(files[name])); err != nil {
			t.Fatal(err)
		}
	}
	m, err := manifest.Generate(paths, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Archive(p.configManifestsDir); err != nil {
		t.Fatal(err)
	}
	if err := m.SaveAs(p.configManifestPath); err != nil {
		t.Fatal(err)
	}
	return p, dir
}
func editFile(t *testing.T, path, old, next string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes.ReplaceAll(data, []byte(old), []byte(next)), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestAccountEditApprovesPasswordAndRetainsPriorArchive(t *testing.T) {
	p, dir := accountEditFixture(t)
	req, _ := accountedit.Parse([]string{"passwd", "alice"})
	err := performAccountEdit(p, dir, req, func() error {
		editFile(t, filepath.Join(dir, "shadow"), "alice:$6$old:20000", "alice:$6$new:20001")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.New(p.configManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	current, err := manifest.Generate([]string{filepath.Join(dir, "passwd"), filepath.Join(dir, "shadow"), filepath.Join(dir, "group"), filepath.Join(dir, "gshadow")}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if changes := manifest.Diff(m, current); len(changes) != 0 {
		t.Fatalf("legitimate change still triggers watch: %+v", changes)
	}
	old, err := manifest.LoadGeneration(p.configManifestsDir, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Diff(old, m)) != 1 || m.Generation != 2 {
		t.Fatal("prior archive lost or unexpected files accepted")
	}
	log, err := os.ReadFile(p.auditLogPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(log), "$6$") {
		t.Fatal("credential hash logged")
	}
}

func TestAccountEditGroupApprovalSurvivesUntilNextScan(t *testing.T) {
	p, dir := accountEditFixture(t)
	passwd, group := filepath.Join(dir, "passwd"), filepath.Join(dir, "group")
	if _, err := anomaly.CheckAccounts(p.anomalyDir, passwd, group); err != nil {
		t.Fatal(err)
	}
	req, _ := accountedit.Parse([]string{"gpasswd", "-a", "bob", "sudo"})
	if err := performAccountEdit(p, dir, req, func() error {
		for _, name := range []string{"group", "gshadow"} {
			editFile(t, filepath.Join(dir, name), ":alice\n", ":alice,bob\n")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	m, err := manifest.New(p.configManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	// An unrelated change arriving before scan must still produce a finding.
	editFile(t, passwd, "alice:x:1000", "alice:x:0")
	findings, err := anomaly.CheckAccountsWithGroupApprovals(p.anomalyDir, passwd, group, m.ApprovedGroups)
	if err != nil {
		t.Fatal(err)
	}
	local := 0
	for _, f := range findings {
		if f.Detail == group {
			t.Fatalf("approved group flagged: %+v", f)
		}
		if f.Culprit == "alice" {
			local++
		}
	}
	if local != 1 {
		t.Fatal("unrelated user change hidden")
	}
	editFile(t, group, "sudo:x:27", "sudo:x:0")
	findings, err = anomaly.CheckAccountsWithGroupApprovals(p.anomalyDir, passwd, group, m.ApprovedGroups)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Detail == group {
			found = true
		}
	}
	if !found {
		t.Fatal("later unapproved group change hidden")
	}
}

func TestAccountEditRejectsPreexistingDriftWithoutRunningUtility(t *testing.T) {
	p, dir := accountEditFixture(t)
	editFile(t, filepath.Join(dir, "group"), "sudo:x:27", "sudo:x:0")
	req, _ := accountedit.Parse([]string{"passwd", "alice"})
	called := false
	if err := performAccountEdit(p, dir, req, func() error { called = true; return nil }); err == nil || called {
		t.Fatal("utility ran with preexisting drift")
	}
}

func TestAccountEditFailuresNeverPublishApproval(t *testing.T) {
	for _, kind := range []string{"command", "unrelated", "mode", "symlink", "archive"} {
		t.Run(kind, func(t *testing.T) {
			p, dir := accountEditFixture(t)
			original, _ := os.ReadFile(p.configManifestPath)
			req, _ := accountedit.Parse([]string{"passwd", "alice"})
			err := performAccountEdit(p, dir, req, func() error {
				editFile(t, filepath.Join(dir, "shadow"), "alice:$6$old:20000", "alice:$6$new:20001")
				switch kind {
				case "command":
					return errors.New("interrupted")
				case "unrelated":
					editFile(t, filepath.Join(dir, "passwd"), "bob:x:1001", "bob:x:0")
				case "mode":
					if err := os.Chmod(filepath.Join(dir, "shadow"), 0644); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					path := filepath.Join(dir, "group")
					if err := os.Rename(path, path+".real"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(path+".real", path); err != nil {
						t.Fatal(err)
					}
				case "archive":
					if err := os.Mkdir(filepath.Join(p.configManifestsDir, "manifest-2.json"), 0700); err != nil {
						t.Fatal(err)
					}
				}
				return nil
			})
			if err == nil {
				t.Fatal("accepted unsafe/failed operation")
			}
			current, _ := os.ReadFile(p.configManifestPath)
			if !bytes.Equal(original, current) {
				t.Fatal("published partial approval")
			}
		})
	}
}

func TestAccountEditRefusesWardenLockedTarget(t *testing.T) {
	p, dir := accountEditFixture(t)
	if err := accountlock.NewStore(p.accountLocksPath).Save([]accountlock.Lock{{User: "alice"}}); err != nil {
		t.Fatal(err)
	}
	req, _ := accountedit.Parse([]string{"passwd", "alice"})
	called := false
	if err := performAccountEdit(p, dir, req, func() error { called = true; return nil }); err == nil || called {
		t.Fatal("modified Warden-locked account")
	}
}
