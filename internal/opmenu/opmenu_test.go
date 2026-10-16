package opmenu

import (
	"errors"
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	req := Parse("  restore /etc/nginx/nginx.conf --apply ", "198.51.100.7 51234 22")
	if !reflect.DeepEqual(req.Args, []string{"restore", "/etc/nginx/nginx.conf", "--apply"}) {
		t.Fatalf("args = %q", req.Args)
	}
	if req.SourceIP != "198.51.100.7" {
		t.Fatalf("source ip = %q", req.SourceIP)
	}
	if req.Shell() {
		t.Fatal("a command is not a shell request")
	}
}

func TestEmptyAndShellRequestShell(t *testing.T) {
	for _, raw := range []string{"", "   ", "shell", "shell extra"} {
		if !Parse(raw, "").Shell() {
			t.Fatalf("%q should request a shell", raw)
		}
	}
}

func TestHandleRunsAllowedCommandWithoutAnyCode(t *testing.T) {
	var got []string
	var logged string
	h := &Handler{
		Run:     func(args []string) error { got = args; return nil },
		Allowed: func(name string) bool { return name == "arm" },
		Log:     func(action string, _ map[string]any) { logged = action },
	}
	if err := h.Handle(Parse("arm --yes", "")); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"arm", "--yes"}) {
		t.Fatalf("ran %q", got)
	}
	if logged != "ran" {
		t.Fatalf("logged %q", logged)
	}
}

func TestHandleRejectsUnknownCommand(t *testing.T) {
	ran := false
	h := &Handler{
		Run:     func([]string) error { ran = true; return nil },
		Allowed: func(name string) bool { return name == "status" },
	}
	if err := h.Handle(Parse("rm -rf /", "")); err == nil {
		t.Fatal("expected rejection")
	}
	if ran {
		t.Fatal("rejected command must not run")
	}
}

func TestHandlePropagatesCommandError(t *testing.T) {
	want := errors.New("boom")
	h := &Handler{Run: func([]string) error { return want }}
	if err := h.Handle(Parse("status", "")); !errors.Is(err, want) {
		t.Fatalf("err = %v", err)
	}
}

func TestShellWithoutPathFails(t *testing.T) {
	h := &Handler{}
	if err := h.Handle(Parse("shell", "")); err == nil {
		t.Fatal("expected error without a shell path")
	}
}
