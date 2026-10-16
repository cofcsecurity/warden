// Package opmenu is what the team key's forced SSH command runs. It reads
// $SSH_ORIGINAL_COMMAND and either runs one warden subcommand or opens a
// root shell. There is no second factor: holding the team key, from the
// team network, is the whole check.
package opmenu

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// Request is one parsed invocation.
type Request struct {
	// Args is the requested warden command line, without the binary name.
	// Empty means an interactive shell.
	Args     []string
	SourceIP string
}

// Shell reports whether the request asks for a shell rather than a command.
func (r Request) Shell() bool {
	return len(r.Args) == 0 || r.Args[0] == "shell"
}

// Parse splits raw (from $SSH_ORIGINAL_COMMAND) on whitespace. Quoting is
// not interpreted; no warden argument needs embedded spaces except a public
// key, which commands that take one join from their remaining arguments.
func Parse(raw, sshClient string) Request {
	req := Request{Args: strings.Fields(raw)}
	if fields := strings.Fields(sshClient); len(fields) > 0 {
		req.SourceIP = fields[0] // SSH_CLIENT is "<ip> <port> <port>"
	}
	return req
}

// Handler runs requests. Run executes one warden command line in-process;
// Allowed reports whether a command name may be run this way.
type Handler struct {
	Run       func(args []string) error
	Allowed   func(name string) bool
	ShellPath string
	Log       func(action string, fields map[string]any)
}

// Handle dispatches req.
func (h *Handler) Handle(req Request) error {
	if req.Shell() {
		h.log("shell", req, nil)
		return h.execShell()
	}
	name := req.Args[0]
	if h.Allowed != nil && !h.Allowed(name) {
		err := fmt.Errorf("opmenu: %q is not a warden command (try 'help', or 'shell')", name)
		h.log("rejected", req, err)
		return err
	}
	err := h.Run(req.Args)
	h.log("ran", req, err)
	return err
}

func (h *Handler) execShell() error {
	if h.ShellPath == "" {
		return fmt.Errorf("opmenu: no shell path configured")
	}
	// -l gives the operator a normal root login environment rather than
	// the stripped one sudo leaves behind.
	env := append(os.Environ(), "HOME=/root", "USER=root", "LOGNAME=root")
	return syscall.Exec(h.ShellPath, []string{h.ShellPath, "-l"}, env)
}

func (h *Handler) log(action string, req Request, err error) {
	if h.Log == nil {
		return
	}
	fields := map[string]any{"source_ip": req.SourceIP}
	if len(req.Args) > 0 {
		fields["command"] = req.Args[0]
	}
	if err != nil {
		fields["error"] = err.Error()
	}
	h.Log(action, fields)
}
