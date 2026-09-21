package anomaly

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// writeFakeProcNetTCP writes a minimal /proc/net/tcp-format file with one
// header line and one data line per (port, uid) pair, all in LISTEN
// state — real column layout, just the fields this package actually
// reads populated meaningfully.
func writeFakeProcNetTCP(t *testing.T, procRoot, file string, entries [][2]int) {
	t.Helper()
	dir := filepath.Join(procRoot, "net")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	for _, e := range entries {
		port, uid := e[0], e[1]
		content += fmt.Sprintf("   0: 00000000:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000 %5d        0 12345 1 0000000000000000 100 0 0 10 0\n", port, uid)
	}
	if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCheckListeningPortsFirstRunBootstrapsSilently(t *testing.T) {
	baseDir := t.TempDir()
	procRoot := t.TempDir()
	writeFakeProcNetTCP(t, procRoot, "tcp", [][2]int{{22, 0}})

	findings, err := CheckListeningPorts(baseDir, procRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings on first run, got %+v", findings)
	}
}

func TestCheckListeningPortsFlagsNewPort(t *testing.T) {
	baseDir := t.TempDir()
	procRoot := t.TempDir()
	writeFakeProcNetTCP(t, procRoot, "tcp", [][2]int{{22, 0}})

	if _, err := CheckListeningPorts(baseDir, procRoot); err != nil {
		t.Fatal(err)
	}

	// Port 4444 (a classic reverse-shell listener port) shows up, owned
	// by uid 0.
	writeFakeProcNetTCP(t, procRoot, "tcp", [][2]int{{22, 0}, {4444, 0}})

	findings, err := CheckListeningPorts(baseDir, procRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly one finding, got %+v", findings)
	}
	if findings[0].Check != "listening-ports" {
		t.Fatalf("unexpected check name: %+v", findings[0])
	}
}

func TestParseProcNetTCPOnlyReportsListenState(t *testing.T) {
	procRoot := t.TempDir()
	dir := filepath.Join(procRoot, "net")
	os.MkdirAll(dir, 0o755)
	// One LISTEN (0A) and one ESTABLISHED (01) entry on different ports.
	content := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 0 0 0 0\n" +
		"   1: 00000000:1F90 0A0A0A0A:1234 01 00000000:00000000 00:00000000 00000000     0        0 2 1 0 0 0 0 0\n"
	os.WriteFile(filepath.Join(dir, "tcp"), []byte(content), 0o644)

	socks, err := parseProcNetTCP(filepath.Join(dir, "tcp"), "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if len(socks) != 1 || socks[0].port != 0x16 {
		t.Fatalf("expected only the LISTEN-state port 0x16 (22), got %+v", socks)
	}
}
