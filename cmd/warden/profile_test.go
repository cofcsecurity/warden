package main

import (
	"os"
	"path/filepath"
	"testing"
	"warden/internal/detect"
	"warden/internal/manifest"
)

func TestHostProfileReplacesDefaultsAndRejectsInvalid(t *testing.T) {
	cfg, data, watch, confirm, services, known := configTierPaths, dataTierPaths, watchedPaths, confirmFirstPaths, pathServices, detect.KnownServices
	t.Cleanup(func() {
		configTierPaths, dataTierPaths, watchedPaths, confirmFirstPaths, pathServices, detect.KnownServices = cfg, data, watch, confirm, services, known
	})
	file := filepath.Join(t.TempDir(), "profile.json")
	content := `{"paths":[{"path":"/etc/scored.conf","tier":"config","class":"confirm-first","services":["scored"]},{"path":"/srv/scored.data","tier":"data","class":"confirm-first"}],"services":[{"Name":"Scored","ProcessNames":["scored"],"ConfigPaths":["/etc/scored.conf"]}]}`
	if err := os.WriteFile(file, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadHostProfile(file); err != nil {
		t.Fatal(err)
	}
	if len(configTierPaths) != 1 || len(dataTierPaths) != 1 || watchedPaths[0] != "/etc/scored.conf" || classifyPath(watchedPaths[0]) != manifest.ConfirmFirst || pathServices[watchedPaths[0]][0] != "scored" || len(detect.KnownServices) != len(known)+1 {
		t.Fatal("profile not applied")
	}
	for _, bad := range []string{`{}`, `{"paths":[],"typo":true}`, `{"paths":[]} {}`, `{"paths":[{"path":"relative","class":"confirm-first"}]}`, `{"paths":[{"path":"/x","class":"unknown"}]}`} {
		if err := os.WriteFile(file, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if err := loadHostProfile(file); err == nil {
			t.Fatalf("accepted %s", bad)
		}
		if len(configTierPaths) != 1 || configTierPaths[0] != "/etc/scored.conf" {
			t.Fatal("invalid profile changed state")
		}
	}
}
