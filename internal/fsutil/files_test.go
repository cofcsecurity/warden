package fsutil

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRejectFIFOAndSerializeWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(path); err == nil {
		t.Fatal("read FIFO")
	}
	if err := WriteFile(path, []byte("x"), 0600); err == nil {
		t.Fatal("replaced unsupported file")
	}
	lock := filepath.Join(t.TempDir(), "lock")
	release, err := Lock(lock)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := Lock(lock); err == nil {
		other()
		t.Fatal("concurrent writer acquired lock")
	}
	release()
	release, err = Lock(lock)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if _, err := os.Stat(lock); err != nil {
		t.Fatal("lock file was unlinked")
	}
}

func TestWritePreservesSpecialPermissionsOrRefusesPublication(t *testing.T) {
	path := filepath.Join(t.TempDir(), "program")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	mode := os.FileMode(0750) | os.ModeSetuid | os.ModeSetgid | os.ModeSticky
	err := WriteFile(path, []byte("replacement"), mode)
	info, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatal(statErr)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if err == nil {
		if info.Mode() != mode || string(data) != "replacement" {
			t.Fatalf("published wrong state: %v %q", info.Mode(), data)
		}
	} else {
		if string(data) != "original" || info.Mode().Perm() != 0600 {
			t.Fatal("failed mode check changed the destination")
		}
	}
}
