package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"warden/internal/audit"
	"warden/internal/manifest"
	"warden/internal/replicate"
	"warden/internal/store"
	"warden/internal/watch"
)

func recoveryFixture(t *testing.T) (paths, string, []byte) {
	t.Helper()
	dir := t.TempDir()
	p := paths{storeRoot: dir, configManifestPath: filepath.Join(dir, "config.json"), configManifestsDir: filepath.Join(dir, "config"), dataManifestPath: filepath.Join(dir, "data.json"), dataManifestsDir: filepath.Join(dir, "data"), auditLogPath: filepath.Join(dir, "audit.log")}
	content := []byte("approved data")
	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := st.Put(content)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "objects", hash[:2], hash)); err != nil {
		t.Fatal(err)
	}
	old := buildReplicateTargets
	t.Cleanup(func() { buildReplicateTargets = old })
	buildReplicateTargets = ""
	return p, hash, content
}
func recoveryPeer(t *testing.T) (*replicate.FSTarget, string) {
	t.Helper()
	root := t.TempDir()
	target, err := replicate.NewFSTarget(root)
	if err != nil {
		t.Fatal(err)
	}
	return target, "file://" + root
}
func putRecoveryManifest(t *testing.T, target replicate.Target, tier snapshotTier, m *manifest.Manifest) {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.PutManifest(string(tier), m.Generation, data); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverySkipsMissingAndCorruptPeersAndCaches(t *testing.T) {
	p, hash, content := recoveryFixture(t)
	bad, badURL := recoveryPeer(t)
	good, goodURL := recoveryPeer(t)
	if err := bad.Put(hash, []byte("corrupt")); err != nil {
		t.Fatal(err)
	}
	if err := good.Put(hash, content); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "not-mounted")
	buildReplicateTargets = "file://" + missing + ";;" + badURL + ";;" + goodURL
	log, err := audit.New(p.auditLogPath)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	r := newBackupRecovery(p, log)
	defer r.Close()
	st, err := r.store()
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(hash)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("got=%q err=%v", got, err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("missing replica created: %v", err)
	}
	// The cached object must work after every replica goes away.
	st.SetRecovery(func(string) ([]byte, error) { t.Fatal("local cache was bypassed"); return nil, nil })
	got, err = st.Get(hash)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("cache=%q err=%v", got, err)
	}
	entries, err := audit.Read(p.auditLogPath)
	if err != nil || len(entries) != 1 || entries[0].Fields["source"] != goodURL {
		t.Fatalf("audit=%v err=%v", entries, err)
	}
}

func TestRecoverySelectsNewestManifestAndHonorsExactGeneration(t *testing.T) {
	p, hash, _ := recoveryFixture(t)
	m := &manifest.Manifest{Generation: 1, Records: []manifest.Record{{Path: "/srv/example", Hash: hash, Class: manifest.ConfirmFirst}}}
	if err := m.Archive(p.dataManifestsDir); err != nil {
		t.Fatal(err)
	}
	peer, url := recoveryPeer(t)
	m.Generation = 2
	putRecoveryManifest(t, peer, tierData, m)
	buildReplicateTargets = url
	r := newBackupRecovery(p, nil)
	defer r.Close()
	got, err := r.loadManifest(tierData, "")
	if err != nil || got.Generation != 2 {
		t.Fatalf("got=%v err=%v", got, err)
	}
	if _, err := r.loadManifest(tierData, "3"); err == nil {
		t.Fatal("fell back from explicitly requested generation")
	}
	if err := r.ensureManifest(tierData); err != nil {
		t.Fatal(err)
	}
	got, err = manifest.New(p.dataManifestPath)
	if err != nil || got.Generation != 2 {
		t.Fatalf("saved=%v err=%v", got, err)
	}
}

func TestAutomaticWatchRecoversDeletedBackupFromNeighbor(t *testing.T) {
	p, hash, content := recoveryFixture(t)
	targetPath := filepath.Join(t.TempDir(), "guarded.conf")
	m := &manifest.Manifest{Generation: 2, Records: []manifest.Record{{Path: targetPath, Hash: hash, Mode: 0600, Class: manifest.SafeAutoRestore}}}
	peer, url := recoveryPeer(t)
	putRecoveryManifest(t, peer, tierConfig, m)
	if err := peer.Put(hash, content); err != nil {
		t.Fatal(err)
	}
	buildReplicateTargets = url
	r := newBackupRecovery(p, nil)
	defer r.Close()
	if err := r.ensureManifest(tierConfig); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetPath, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	st, err := r.store()
	if err != nil {
		t.Fatal(err)
	}
	result, err := watch.New(p.configManifestPath, []string{targetPath}, nil, true, st, nil, nil).Check()
	if err != nil || len(result.AutoRestored) != 1 {
		t.Fatalf("result=%v err=%v", result, err)
	}
	got, err := os.ReadFile(targetPath)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("restored=%q err=%v", got, err)
	}
}

func TestRetrieveDryRunThenRecoverSplitBackup(t *testing.T) {
	p, hash, content := recoveryFixture(t)
	first, firstURL := recoveryPeer(t)
	second, secondURL := recoveryPeer(t)
	m := &manifest.Manifest{Generation: 7, Records: []manifest.Record{{Path: "/srv/example", Hash: hash, Class: manifest.ConfirmFirst}}}
	putRecoveryManifest(t, first, tierData, m)
	if err := second.Put(hash, content); err != nil {
		t.Fatal(err)
	}
	buildReplicateTargets = firstURL + ";;" + secondURL
	if err := retrieveWithRecovery(p, firstURL, tierData, 7, false); err != nil {
		t.Fatal(err)
	}
	st, err := store.New(p.storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	if st.Has(hash) {
		t.Fatal("dry run cached object")
	}
	if _, err := os.Stat(p.dataManifestPath); !os.IsNotExist(err) {
		t.Fatal("dry run adopted manifest")
	}
	if err := retrieveWithRecovery(p, firstURL, tierData, 7, true); err != nil {
		t.Fatal(err)
	}
	if !st.Has(hash) {
		t.Fatal("object not recovered from second peer")
	}
	// Deleted preferred manifest: the saved local archive must recover it.
	if err := os.Remove(p.dataManifestPath); err != nil {
		t.Fatal(err)
	}
	if err := retrieveWithRecovery(p, secondURL, tierData, 7, true); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryFailsWithoutUsableCopies(t *testing.T) {
	p, hash, _ := recoveryFixture(t)
	bad, url := recoveryPeer(t)
	if err := bad.Put(hash, []byte("wrong")); err != nil {
		t.Fatal(err)
	}
	buildReplicateTargets = url
	r := newBackupRecovery(p, nil)
	defer r.Close()
	st, err := r.store()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(hash); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("expected mismatch: %v", err)
	}
	if st.Has(hash) {
		t.Fatal("bad content cached")
	}
	if err := r.ensureManifest(tierConfig); err == nil {
		t.Fatal("invented a baseline")
	}
	if _, err := os.Stat(p.configManifestPath); !os.IsNotExist(err) {
		t.Fatal("failed recovery wrote a baseline")
	}
	for _, h := range []string{"", "x", "../../etc/shadow"} {
		if _, err := st.Get(h); err == nil {
			t.Fatalf("accepted hash %q", h)
		}
	}
}

func TestRecoveryPeerFailureFallsThroughAndClosesConnections(t *testing.T) {
	p, hash, content := recoveryFixture(t)
	peer, _ := recoveryPeer(t)
	if err := peer.Put(hash, content); err != nil {
		t.Fatal(err)
	}
	buildReplicateTargets = "ssh://missing/root||pinned-a;;ssh://healthy/root||pinned-b"
	old := openRecoveryTarget
	t.Cleanup(func() { openRecoveryTarget = old })
	closed := false
	openRecoveryTarget = func(url, key string) (replicate.Target, func() error, error) {
		if strings.Contains(url, "missing") {
			return nil, nil, os.ErrNotExist
		}
		if key != "pinned-b" {
			t.Fatalf("wrong host key: %s", key)
		}
		return peer, func() error { closed = true; return nil }, nil
	}
	r := newBackupRecovery(p, nil)
	st, err := r.store()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(hash); err != nil {
		t.Fatal(err)
	}
	r.Close()
	if !closed {
		t.Fatal("connection not closed")
	}
}

func TestRecoveryQuarantinesCorruptArchive(t *testing.T) {
	for _, retrieve := range []bool{false, true} {
		t.Run(fmt.Sprint(retrieve), func(t *testing.T) {
			p, hash, content := recoveryFixture(t)
			peer, url := recoveryPeer(t)
			buildReplicateTargets = url
			m := &manifest.Manifest{Generation: 1, Records: []manifest.Record{{Path: "/example", Hash: hash, Mode: 0600}}}
			putRecoveryManifest(t, peer, tierConfig, m)
			if err := peer.Put(hash, content); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(p.configManifestsDir, 0700); err != nil {
				t.Fatal(err)
			}
			broken := []byte("{broken archive")
			if err := os.WriteFile(manifest.ArchivePath(p.configManifestsDir, 1), broken, 0600); err != nil {
				t.Fatal(err)
			}
			if retrieve {
				if err := retrieveWithRecovery(p, url, tierConfig, 1, true); err != nil {
					t.Fatal(err)
				}
			} else {
				r := newBackupRecovery(p, nil)
				defer r.Close()
				if err := r.ensureManifest(tierConfig); err != nil {
					t.Fatal(err)
				}
			}
			recovered, err := manifest.New(p.configManifestPath)
			if err != nil || recovered.Generation != 1 {
				t.Fatalf("not recovered: %+v %v", recovered, err)
			}
			archived, err := manifest.LoadGeneration(p.configManifestsDir, 1)
			if err != nil || archived.Records[0].Hash != hash {
				t.Fatalf("archive not repaired: %v", err)
			}
			names, err := filepath.Glob(filepath.Join(p.configManifestsDir, "corrupt-manifest-1-*.json"))
			if err != nil || len(names) != 1 {
				t.Fatalf("missing quarantined archive: %v %v", names, err)
			}
			retained, err := os.ReadFile(names[0])
			if err != nil || !bytes.Equal(retained, broken) {
				t.Fatal("corrupt bytes lost")
			}
		})
	}
}

func TestArchiveRepairRefusesValidConflictAndSymlink(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		t.Run(fmt.Sprint(symlink), func(t *testing.T) {
			p, hash, _ := recoveryFixture(t)
			old := &manifest.Manifest{Generation: 1, Records: []manifest.Record{{Path: "/old", Hash: hash, Mode: 0600}}}
			if err := old.Archive(p.configManifestsDir); err != nil {
				t.Fatal(err)
			}
			path := manifest.ArchivePath(p.configManifestsDir, 1)
			before, _ := os.ReadFile(path)
			if symlink {
				if err := os.Rename(path, path+".target"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".target", path); err != nil {
					t.Fatal(err)
				}
			}
			next := &manifest.Manifest{Generation: 1, Records: []manifest.Record{{Path: "/new", Hash: hash, Mode: 0600}}}
			r := newBackupRecovery(p, nil)
			defer r.Close()
			if err := r.archiveRecovered(tierConfig, next); err == nil {
				t.Fatal("overwrote conflict or followed symlink")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) || len(r.quarantined) != 0 {
				t.Fatal("modified protected archive")
			}
		})
	}
}
