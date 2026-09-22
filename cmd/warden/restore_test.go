package main

import (
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"warden/internal/audit"
	"warden/internal/manifest"
	"warden/internal/restore"
	"warden/internal/store"
)

func TestRestoreLoadsBothTiersAndGenerations(t *testing.T) {
	dir := t.TempDir()
	p := paths{configManifestPath: filepath.Join(dir, "config.json"), dataManifestPath: filepath.Join(dir, "data.json"), configManifestsDir: filepath.Join(dir, "config"), dataManifestsDir: filepath.Join(dir, "data")}
	for _, tier := range []snapshotTier{tierConfig, tierData} {
		m := &manifest.Manifest{Generation: 7, Records: []manifest.Record{{Path: "/" + string(tier), Hash: strings.Repeat("a", 64)}}}
		if err := m.SaveAs(p.manifestPathForTier(tier)); err != nil {
			t.Fatal(err)
		}
		if err := m.Archive(p.manifestsDirForTier(tier)); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"", "7"} {
			got, err := loadSnapshotTier(p, id, tier)
			if err != nil || len(got.Records) != 1 || got.Records[0].Path != "/"+string(tier) {
				t.Fatalf("tier=%s id=%s got=%v err=%v", tier, id, got, err)
			}
		}
	}
	if _, err := loadSnapshotTier(p, "bad", tierData); err == nil {
		t.Fatal("invalid generation accepted")
	}
	cmd := restoreCmd()
	cmd.SetArgs([]string{"/file", "--tier", "bad"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("invalid CLI tier accepted")
	}
}

func TestDataTierRestoreAppliesArchivedFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "data-file")
	p := paths{storeRoot: dir, dataManifestPath: filepath.Join(dir, "data.json"), dataManifestsDir: filepath.Join(dir, "data-history"), auditLogPath: filepath.Join(dir, "audit.log")}
	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := st.Put([]byte("known good"))
	if err != nil {
		t.Fatal(err)
	}
	m := &manifest.Manifest{Generation: 3, Records: []manifest.Record{{Path: target, Hash: hash, Mode: 0600}}}
	if err := m.Archive(p.dataManifestsDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("drift"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadSnapshotTier(p, "3", tierData)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := restore.Plan(loaded, target)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(target)
	if string(before) != "drift" {
		t.Fatal("planning changed file")
	}
	log, err := audit.New(p.auditLogPath)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	if _, err := applyPlan(p, plan, log); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(target)
	if err != nil || string(after) != "known good" {
		t.Fatalf("data=%q err=%v", after, err)
	}
}

func TestResponseDurationDefaults(t *testing.T) {
	for _, cmd := range []*cobra.Command{banCmd(), lockAccountCmd()} {
		duration, err := cmd.Flags().GetDuration("duration")
		if err != nil || duration != 0 {
			t.Fatalf("%s duration=%s err=%v", cmd.Name(), duration, err)
		}
	}
}
