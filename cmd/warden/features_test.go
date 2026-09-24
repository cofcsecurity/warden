package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
	"warden/internal/attribution"
	"warden/internal/manifest"
	"warden/internal/store"
)

func TestVerifyBackupsReadOnlyAndRepair(t *testing.T) {
	p, hash, content := recoveryFixture(t)
	peer, url := recoveryPeer(t)
	buildReplicateTargets = url
	m := &manifest.Manifest{Generation: 1, Records: []manifest.Record{{Path: "/example", Hash: hash, Mode: 0600}}}
	if err := m.Archive(p.configManifestsDir); err != nil {
		t.Fatal(err)
	}
	if err := m.SaveAs(p.configManifestPath); err != nil {
		t.Fatal(err)
	}
	putRecoveryManifest(t, peer, tierConfig, m)
	if err := peer.Put(hash, content); err != nil {
		t.Fatal(err)
	}
	report := checkBackups(p, false)
	if report.Healthy || report.UsableReplicas != 1 || report.Checks[0].Copies["local"] != "missing" {
		t.Fatalf("report=%+v", report)
	}
	if store.Open(p.storeRoot).Has(hash) {
		t.Fatal("read-only verification cached content")
	}
	if _, err := os.Stat(filepath.Join(p.storeRoot, "backup-health.json")); !os.IsNotExist(err) {
		t.Fatal("read-only verification wrote health state")
	}
	report = checkBackups(p, true)
	if !report.Healthy || report.Repaired != 1 || !store.Open(p.storeRoot).Has(hash) {
		t.Fatalf("repair=%+v", report)
	}
	if err := os.WriteFile(filepath.Join(url[len("file://"):], "objects", hash[:2], hash), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	report = checkBackups(p, false)
	if report.Healthy || report.Checks[0].Copies[url] != "corrupt" {
		t.Fatalf("corrupt peer=%+v", report)
	}
}
func TestRetrieveRequiresExplicitRollback(t *testing.T) {
	p, hash, content := recoveryFixture(t)
	st := store.Open(p.storeRoot)
	if _, err := st.Put(content); err != nil {
		t.Fatal(err)
	}
	for _, g := range []int{1, 2} {
		m := &manifest.Manifest{Generation: g, Records: []manifest.Record{{Path: "/example", Hash: hash}}}
		if err := m.Archive(p.configManifestsDir); err != nil {
			t.Fatal(err)
		}
	}
	if err := retrieveWithRecovery(p, "", tierConfig, 1, true); err == nil {
		t.Fatal("silent rollback")
	}
	if err := retrieveWithRecovery(p, "", tierConfig, 1, true, true); err != nil {
		t.Fatal(err)
	}
	if next, err := allocateGeneration(p, tierConfig, 1); err != nil || next != 3 {
		t.Fatalf("reused generation: %d %v", next, err)
	}
}
func TestPendingReloadSurvivesFailureAndRetries(t *testing.T) {
	p, _, _ := recoveryFixture(t)
	oldMap, oldDirs := pathServices, systemdUnitSearchDirs
	defer func() { pathServices = oldMap; systemdUnitSearchDirs = oldDirs }()
	pathServices = map[string][]string{"/example": {"example"}}
	systemdUnitSearchDirs = []string{p.storeRoot}
	probeWrite(t, filepath.Join(p.storeRoot, "example.service"), nil)
	script := filepath.Join(p.storeRoot, "systemctl")
	probeWrite(t, script, []byte("#!/bin/sh\nexit 1\n"))
	os.Chmod(script, 0700)
	t.Setenv("PATH", p.storeRoot+":"+os.Getenv("PATH"))
	q, err := loadReloadQueue(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.add("/example"); err != nil {
		t.Fatal(err)
	}
	if len(q.flush()) == 0 {
		t.Fatal("expected reload failure")
	}
	q, err = loadReloadQueue(p)
	if err != nil || !q.Units["example"] {
		t.Fatal("lost pending reload")
	}
	probeWrite(t, script, []byte("#!/bin/sh\nexit 0\n"))
	os.Chmod(script, 0700)
	if errs := q.flush(); len(errs) != 0 {
		t.Fatal(errs)
	}
	q, err = loadReloadQueue(p)
	if err != nil || len(q.Units) != 0 {
		t.Fatal("successful reload remains queued")
	}
}
func TestProfileValidationReportsMissingAndNonRegularPaths(t *testing.T) {
	p, _, _ := recoveryFixture(t)
	oldConfig, oldData, oldProc, oldJournal, oldAuth := configTierPaths, dataTierPaths, procRoot, journalSessions, authLogPaths
	defer func() {
		configTierPaths = oldConfig
		dataTierPaths = oldData
		procRoot = oldProc
		journalSessions = oldJournal
		authLogPaths = oldAuth
	}()
	missing := filepath.Join(t.TempDir(), "missing")
	configTierPaths = []string{missing, p.storeRoot}
	dataTierPaths = []string{missing}
	procRoot = t.TempDir()
	authLogPaths = nil
	journalSessions = func(time.Time, time.Time) ([]attribution.Session, error) { return nil, nil }
	report := validateProfile(p)
	if len(report.Issues) < 4 || report.Attribution != "journald" {
		t.Fatalf("report=%+v", report)
	}
}

func TestPruneRejectsInvalidActiveManifest(t *testing.T) {
	for _, data := range []string{"null", "{broken"} {
		t.Run(data, func(t *testing.T) {
			p, hash, content := recoveryFixture(t)
			st := store.Open(p.storeRoot)
			if _, err := st.Put(content); err != nil {
				t.Fatal(err)
			}
			probeWrite(t, p.configManifestPath, []byte(data))
			if err := pruneOldObjects(p, st); err == nil {
				t.Fatal("pruned without a valid active manifest")
			}
			if !st.Has(hash) {
				t.Fatal("pruned after metadata failure")
			}
		})
	}
}

func TestVerifyBackupsChecksAndRepairsArchiveIndependentlyOfLive(t *testing.T) {
	p, hash, content := recoveryFixture(t)
	if _, err := store.Open(p.storeRoot).Put(content); err != nil {
		t.Fatal(err)
	}
	m := &manifest.Manifest{Generation: 1, Records: []manifest.Record{{Path: "/example", Hash: hash, Mode: 0600}}}
	if err := m.Archive(p.configManifestsDir); err != nil {
		t.Fatal(err)
	}
	if err := m.SaveAs(p.configManifestPath); err != nil {
		t.Fatal(err)
	}
	path := manifest.ArchivePath(p.configManifestsDir, 1)
	if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	report := checkBackups(p, false)
	if report.Healthy || len(report.Metadata) != 1 || report.Metadata[0].Copies["local-archive"] != "corrupt" || report.Metadata[0].Copies["local-live"] != "verified" {
		t.Fatalf("masked bad archive: %+v", report)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "broken" {
		t.Fatal("read-only check repaired archive")
	}
	report = checkBackups(p, true)
	if !report.Healthy || report.MetadataRepaired != 1 || len(report.QuarantinedArchives) != 1 {
		t.Fatalf("repair failed: %+v", report)
	}
	data, err := os.ReadFile(report.QuarantinedArchives[0])
	if err != nil || string(data) != "broken" {
		t.Fatal("lost quarantine")
	}
}

func TestVerifyBackupsDoesNotCountPeerWithUnreadableTier(t *testing.T) {
	p, hash, content := recoveryFixture(t)
	peer, url := recoveryPeer(t)
	buildReplicateTargets = url
	m := &manifest.Manifest{Generation: 1, Records: []manifest.Record{{Path: "/example", Hash: hash, Mode: 0600}}}
	if err := m.Archive(p.configManifestsDir); err != nil {
		t.Fatal(err)
	}
	if err := m.SaveAs(p.configManifestPath); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open(p.storeRoot).Put(content); err != nil {
		t.Fatal(err)
	}
	putRecoveryManifest(t, peer, tierConfig, m)
	if err := peer.Put(hash, content); err != nil {
		t.Fatal(err)
	}
	if err := peer.PutManifest("data", 1, []byte("broken")); err != nil {
		t.Fatal(err)
	}
	report := checkBackups(p, false)
	if report.Healthy || report.UsableReplicas != 0 {
		t.Fatalf("counted unreadable tier: %+v", report)
	}
	found := false
	for _, row := range report.Metadata {
		if row.Tier == tierData && row.Copies[url] == "corrupt" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing per-copy failure: %+v", report.Metadata)
	}
}

func TestVerificationDoesNotRepairValidConflictingArchive(t *testing.T) {
	p, hash, content := recoveryFixture(t)
	if _, err := store.Open(p.storeRoot).Put(content); err != nil {
		t.Fatal(err)
	}
	archived := &manifest.Manifest{Generation: 1, Records: []manifest.Record{{Path: "/archived", Hash: hash, Mode: 0600}}}
	live := &manifest.Manifest{Generation: 1, Records: []manifest.Record{{Path: "/live", Hash: hash, Mode: 0600}}}
	if err := archived.Archive(p.configManifestsDir); err != nil {
		t.Fatal(err)
	}
	if err := live.SaveAs(p.configManifestPath); err != nil {
		t.Fatal(err)
	}
	report := checkBackups(p, true)
	if report.Healthy || report.MetadataRepaired != 0 || report.Metadata[0].Copies["local-archive"] != "conflicting" {
		t.Fatalf("accepted conflict: %+v", report)
	}
	after, err := manifest.LoadGeneration(p.configManifestsDir, 1)
	if err != nil || after.Records[0].Path != "/archived" {
		t.Fatal("replaced valid conflict")
	}
}

func TestVerifyMissingLiveBaselineDoesNotAdoptArchive(t *testing.T) {
	p, hash, content := recoveryFixture(t)
	if _, err := store.Open(p.storeRoot).Put(content); err != nil {
		t.Fatal(err)
	}
	m := &manifest.Manifest{Generation: 1, Records: []manifest.Record{{Path: "/example", Hash: hash, Mode: 0600}}}
	if err := m.Archive(p.configManifestsDir); err != nil {
		t.Fatal(err)
	}
	report := checkBackups(p, true)
	if report.Healthy {
		t.Fatal("missing live baseline reported healthy")
	}
	if _, err := os.Stat(p.configManifestPath); !os.IsNotExist(err) {
		t.Fatal("verification adopted a baseline")
	}
	found := false
	for _, row := range report.Metadata {
		if row.Tier == tierConfig && row.Copies["local-live"] == "missing" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing live status: %+v", report.Metadata)
	}
}

func TestVerificationDoesNotBlockOnManifestFIFO(t *testing.T) {
	p, hash, content := recoveryFixture(t)
	if _, err := store.Open(p.storeRoot).Put(content); err != nil {
		t.Fatal(err)
	}
	m := &manifest.Manifest{Generation: 1, Records: []manifest.Record{{Path: "/example", Hash: hash, Mode: 0600}}}
	if err := m.Archive(p.configManifestsDir); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(p.configManifestPath, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan backupReport, 1)
	go func() { done <- checkBackups(p, false) }()
	select {
	case report := <-done:
		if report.Healthy {
			t.Fatal("FIFO reported healthy")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("verification blocked on manifest FIFO")
	}
}
