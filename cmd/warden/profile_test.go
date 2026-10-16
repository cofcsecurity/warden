package main

import (
	"os"
	"path/filepath"
	"testing"

	"warden/internal/detect"
	"warden/internal/manifest"
)

func restoreProfileState(t *testing.T) {
	t.Helper()
	c, d, confirm, services, known := configTierPaths, dataTierPaths, confirmFirstPaths, pathServices, detect.KnownServices
	t.Cleanup(func() {
		configTierPaths, dataTierPaths, confirmFirstPaths, pathServices, detect.KnownServices = c, d, confirm, services, known
	})
}

func TestHostProfileExtendsDefaults(t *testing.T) {
	restoreProfileState(t)
	file := filepath.Join(t.TempDir(), "profile.json")
	content := `{"exclude":["/etc/hostname"],"paths":[{"path":"/etc/scored.conf","tier":"config","class":"confirm-first","services":["scored"]},{"path":"/srv/scored/**","tier":"data","class":"confirm-first"},{"path":"/etc/passwd","tier":"config","class":"confirm-first"}],"services":[{"Name":"Scored","ProcessNames":["scored"],"ConfigPaths":["/etc/scored.conf"]}]}`
	if err := os.WriteFile(file, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadHostProfile(file); err != nil {
		t.Fatal(err)
	}
	if configTierPaths[0] != "/etc/scored.conf" || !coveredBy(configTierPaths, "/etc/sudoers.d/x") {
		t.Fatalf("profile entries must come first and defaults must stay: %v", configTierPaths)
	}
	if coveredBy(configTierPaths, "/etc/hostname") {
		t.Fatal("excluded default still watched")
	}
	if classifyPath("/etc/scored.conf") != manifest.ConfirmFirst || classifyPath("/etc/passwd") != manifest.ConfirmFirst {
		t.Fatal("profile classification not applied")
	}
	if pathServices["/etc/scored.conf"][0] != "scored" || !coveredBy(dataTierPaths, "/srv/scored/a/b") {
		t.Fatal("profile services or data tier not applied")
	}
	// Loading twice must not duplicate anything.
	n := len(configTierPaths)
	if err := loadHostProfile(file); err != nil {
		t.Fatal(err)
	}
	if len(configTierPaths) != n || len(detect.KnownServices) != len(defaultKnownServices)+1 {
		t.Fatal("reloading the profile duplicated entries")
	}
}

func TestHostProfileReplaceAndRejectsInvalid(t *testing.T) {
	restoreProfileState(t)
	file := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(file, []byte(`{"replace":true,"paths":[{"path":"/etc/only.conf","tier":"config","class":"auto-restore"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadHostProfile(file); err != nil {
		t.Fatal(err)
	}
	if len(configTierPaths) != 1 || len(dataTierPaths) != 0 || classifyPath("/etc/shadow") != manifest.SafeAutoRestore {
		t.Fatalf("replace must drop the defaults: %v %v", configTierPaths, dataTierPaths)
	}
	for _, bad := range []string{`{}`, `{"paths":[],"typo":true}`, `{"paths":[]} {}`, `{"paths":[{"path":"relative","class":"confirm-first"}]}`, `{"paths":[{"path":"/x","class":"unknown"}]}`, `{"paths":[{"path":"/a/**/b","class":"auto-restore"}]}`} {
		if err := os.WriteFile(file, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if err := loadHostProfile(file); err == nil {
			t.Fatalf("accepted %s", bad)
		}
		if len(configTierPaths) != 1 || configTierPaths[0] != "/etc/only.conf" {
			t.Fatal("invalid profile changed state")
		}
	}
}
