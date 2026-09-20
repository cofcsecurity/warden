package detect

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// fakeProc builds a minimal fake /proc: one directory per pid, each with a
// comm file, plus a couple of non-pid entries that Scan must skip.
func fakeProc(t *testing.T, comms map[int]string) string {
	t.Helper()
	root := t.TempDir()

	for pid, comm := range comms {
		dir := filepath.Join(root, strconv.Itoa(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Real /proc has plenty of non-numeric entries; Scan must ignore them
	// rather than erroring out.
	for _, name := range []string{"self", "net", "meminfo"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	return root
}

func TestScanServicesDetectsRunningProcess(t *testing.T) {
	procRoot := fakeProc(t, map[int]string{1234: "nginx", 5: "systemd"})

	services := []Service{
		{Name: "nginx", ProcessNames: []string{"nginx"}, ConfigPaths: nil},
		{Name: "Apache", ProcessNames: []string{"apache2", "httpd"}, ConfigPaths: nil},
	}

	findings, err := scanServices(procRoot, services)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	nginx := findings[0]
	if !nginx.Detected() {
		t.Fatalf("expected nginx to be detected")
	}
	if len(nginx.PIDs) != 1 || nginx.PIDs[0] != 1234 {
		t.Fatalf("expected nginx pid [1234], got %v", nginx.PIDs)
	}

	apache := findings[1]
	if apache.Detected() {
		t.Fatalf("expected apache not to be detected, got %+v", apache)
	}
}

func TestScanServicesDetectsConfigWithoutProcess(t *testing.T) {
	procRoot := fakeProc(t, map[int]string{1: "systemd"})

	dir := t.TempDir()
	confPath := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(confPath, []byte("server {}"), 0o644); err != nil {
		t.Fatal(err)
	}

	services := []Service{
		{Name: "nginx", ProcessNames: []string{"nginx"}, ConfigPaths: []string{confPath}},
	}

	findings, err := scanServices(procRoot, services)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if len(f.PIDs) != 0 {
		t.Fatalf("expected no pids, got %v", f.PIDs)
	}
	if !f.Detected() {
		t.Fatalf("expected the service to be detected via its config file alone")
	}
	if len(f.ConfigsPresent) != 1 || f.ConfigsPresent[0] != confPath {
		t.Fatalf("expected ConfigsPresent to contain %s, got %v", confPath, f.ConfigsPresent)
	}
}

func TestScanServicesNeitherRunningNorConfigured(t *testing.T) {
	procRoot := fakeProc(t, map[int]string{1: "systemd"})

	services := []Service{
		{Name: "vsftpd", ProcessNames: []string{"vsftpd"}, ConfigPaths: []string{"/nonexistent/vsftpd.conf"}},
	}

	findings, err := scanServices(procRoot, services)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Detected() {
		t.Fatalf("expected vsftpd not to be detected, got %+v", findings[0])
	}
}

func TestKnownServicesProcessNamesFitCommLimit(t *testing.T) {
	// The kernel truncates /proc/<pid>/comm to 15 bytes; a longer entry
	// here would never actually match a real process.
	for _, svc := range KnownServices {
		for _, name := range svc.ProcessNames {
			if len(name) > 15 {
				t.Errorf("%s: process name %q is longer than comm's 15-byte limit", svc.Name, name)
			}
		}
	}
}
