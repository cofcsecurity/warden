package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"warden/internal/accountlock"
	"warden/internal/audit"
	"warden/internal/manifest"
	"warden/internal/restore"
	"warden/internal/store"
	"warden/internal/watch"
)

func probeWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestRegressionPruneActiveGeneration(t *testing.T) {
	p, _, content := recoveryFixture(t)
	st, err := store.New(p.storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	activeHash, err := st.Put(content)
	if err != nil {
		t.Fatal(err)
	}
	otherHash, err := st.Put([]byte("newer"))
	if err != nil {
		t.Fatal(err)
	}
	active := &manifest.Manifest{Generation: 1, Records: []manifest.Record{{Path: "/example", Hash: activeHash}}}
	if err := active.SaveAs(p.configManifestPath); err != nil {
		t.Fatal(err)
	}
	if err := active.Archive(p.configManifestsDir); err != nil {
		t.Fatal(err)
	}
	for g := 2; g <= retainGenerations+1; g++ {
		m := &manifest.Manifest{Generation: g, Records: []manifest.Record{{Path: "/example", Hash: otherHash}}}
		if err := m.Archive(p.configManifestsDir); err != nil {
			t.Fatal(err)
		}
	}
	if err := pruneOldObjects(p, st); err != nil {
		t.Fatal(err)
	}
	if !st.Has(activeHash) {
		t.Fatal("pruning deleted the active baseline's object")
	}
}

func TestRegressionReplicationFailureStillSendsEvidence(t *testing.T) {
	p, _, _ := recoveryFixture(t)
	peer, url := recoveryPeer(t)
	st, err := store.New(p.storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	probeWrite(t, p.auditLogPath, []byte("evidence\n"))
	if _, err := pushToTarget(p, st, replicateTarget{url: url}, auditPushState{}, "probe.json", []byte("{}")); err == nil {
		t.Fatal("expected missing manifest error")
	}
	names, err := peer.AuditSegments()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		t.Error("backup error prevented audit delivery")
	}
	root := url[len("file://"):]
	if _, err := os.Stat(filepath.Join(root, "heartbeat", "probe.json")); err != nil {
		t.Errorf("backup error prevented heartbeat delivery: %v", err)
	}
}

func TestRegressionArchiveImmutable(t *testing.T) {
	dir := t.TempDir()
	m := &manifest.Manifest{Generation: 1, Records: []manifest.Record{{Path: "/original"}}}
	if err := m.Archive(dir); err != nil {
		t.Fatal(err)
	}
	m.Records[0].Path = "/replacement"
	if err := m.Archive(dir); err == nil {
		got, err := manifest.LoadGeneration(dir, 1)
		if err != nil {
			t.Fatal(err)
		}
		if got.Records[0].Path != "/original" {
			t.Fatal("archive silently replaced an existing generation")
		}
	}
}

func TestRegressionNullAuditState(t *testing.T) {
	p := auditTestPaths(t)
	probeWrite(t, p.auditPushStatePath, []byte("null"))
	probeWrite(t, p.auditLogPath, []byte("evidence\n"))
	state, err := loadAuditPushState(p.auditPushStatePath)
	if err != nil {
		t.Fatal(err)
	}
	r, _, _ := fsReplicator(t)
	defer func() {
		if v := recover(); v != nil {
			t.Errorf("valid JSON null crashes replication: %v", v)
		}
	}()
	if _, err := pushAuditLog(p, r, "file:///peer", state); err != nil {
		t.Fatal(err)
	}
}

func TestRegressionRestoreModeDrift(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	probeWrite(t, path, []byte("approved"))
	m, err := manifest.Generate([]string{path}, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	plan, err := restore.Plan(m, path)
	if err != nil {
		t.Fatal(err)
	}
	if !plan[0].Changed {
		t.Fatal("world-writable config is reported unchanged")
	}
}

func TestRegressionReloadSeesAllRepairs(t *testing.T) {
	p, _, content := recoveryFixture(t)
	st, err := store.New(p.storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Put(content); err != nil {
		t.Fatal(err)
	}
	a, b := filepath.Join(p.storeRoot, "a"), filepath.Join(p.storeRoot, "b")
	probeWrite(t, a, content)
	probeWrite(t, b, content)
	m, err := manifest.Generate([]string{a, b}, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SaveAs(p.configManifestPath); err != nil {
		t.Fatal(err)
	}
	probeWrite(t, a, []byte("changed"))
	probeWrite(t, b, []byte("changed"))
	oldMap, oldDirs := pathServices, systemdUnitSearchDirs
	t.Cleanup(func() { pathServices = oldMap; systemdUnitSearchDirs = oldDirs })
	pathServices = map[string][]string{a: {"probe"}, b: {"probe"}}
	systemdUnitSearchDirs = []string{p.storeRoot}
	probeWrite(t, filepath.Join(p.storeRoot, "probe.service"), nil)
	marker := filepath.Join(p.storeRoot, "reloaded")
	t.Setenv("PROBE_A", a)
	t.Setenv("PROBE_B", b)
	t.Setenv("PROBE_MARKER", marker)
	script := filepath.Join(p.storeRoot, "systemctl")
	probeWrite(t, script, []byte("#!/bin/sh\nif cmp -s \"$PROBE_A\" \"$PROBE_B\"; then echo good; else echo partial; fi >> \"$PROBE_MARKER\"\n"))
	if err := os.Chmod(script, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", p.storeRoot+":"+os.Getenv("PATH"))
	log, err := audit.New(p.auditLogPath)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	w := watch.New(p.configManifestPath, []string{a, b}, nil, true, st, log, reloadServiceFor(log))
	if _, err := w.Check(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "good\n" {
		t.Fatalf("service reload saw incomplete repairs and was not retried: %q", got)
	}
}

type probeAccounts struct{ locked bool }

func (s *probeAccounts) Lock(string) (string, error) { s.locked = true; return "/bin/sh", nil }
func (s *probeAccounts) Unlock(string, string) error { s.locked = false; return nil }
func (s *probeAccounts) KillSessions(string) error   { return nil }

func TestRegressionReapplyIndefiniteAccountLock(t *testing.T) {
	st := accountlock.NewStore(filepath.Join(t.TempDir(), "locks.json"))
	sys := &probeAccounts{}
	now := time.Now()
	if err := accountlock.Add(st, sys, "example", "test", 0, now); err != nil {
		t.Fatal(err)
	}
	sys.locked = false // Simulates restoring the account's original shell.
	active, _, err := accountlock.Reconcile(st, sys, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || !sys.locked {
		t.Fatalf("active=%v but actual lock=%t", active, sys.locked)
	}
}

func TestRegressionRestoreFailureServiceCleanup(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "actions")
	script := filepath.Join(dir, "systemctl")
	probeWrite(t, script, []byte("#!/bin/sh\necho \"$1\" >> \"$PROBE_MARKER\"\n"))
	if err := os.Chmod(script, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROBE_MARKER", marker)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := st.Put([]byte("approved"))
	if err != nil {
		t.Fatal(err)
	}
	r := restore.New(st, func(string) (string, bool) { return "probe", true })
	results := r.Apply([]restore.PlanEntry{{Path: filepath.Join(dir, "missing-parent", "config"), TargetHash: hash, TargetMode: 0600, Changed: true}})
	if results[0].Err == nil {
		t.Fatal("expected failed write")
	}
	got, err := os.ReadFile(marker)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if string(got) == "stop\n" {
		t.Fatal("service stopped before write failure and never recovered")
	}
}
