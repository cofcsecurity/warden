package accountedit

import (
	"bytes"
	"maps"
	"strings"
	"testing"
)

func fixture() map[string][]byte {
	return map[string][]byte{
		"passwd":  []byte("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/bash\n"),
		"shadow":  []byte("root:$6$root:20000:0:99999:7:::\nalice:$6$old:20000:0:99999:7:::\nbob:$6$bob:20000:0:99999:7:::\n"),
		"group":   []byte("root:x:0:\nsudo:x:27:alice\n"),
		"gshadow": []byte("root:!::\nsudo:!::alice\n"),
	}
}

func TestParseRejectsExtraArgumentsAndFlags(t *testing.T) {
	for _, args := range [][]string{
		{"passwd", "alice", "secret"}, {"passwd", "--stdin"}, {"passwd", "-R", "/tmp"},
		{"gpasswd", "-Q", "/tmp", "sudo"}, {"gpasswd", "-a", "-evil", "sudo"},
		{"sh", "alice"}, {"passwd", "alice\nroot"}, {"passwd", "../root"},
	} {
		if _, err := Parse(args); err == nil {
			t.Errorf("accepted %q", args)
		}
	}
}

func TestPasswordChangeKeepsOtherAccountLockOutOfBaseline(t *testing.T) {
	base := fixture()
	before := maps.Clone(base)
	before["shadow"] = bytes.ReplaceAll(before["shadow"], []byte("bob:$6$bob"), []byte("bob:!$6$bob"))
	before["passwd"] = bytes.ReplaceAll(before["passwd"], []byte("/home/bob:/bin/bash"), []byte("/home/bob:/sbin/nologin"))
	after := maps.Clone(before)
	after["shadow"] = bytes.ReplaceAll(after["shadow"], []byte("alice:$6$old:20000"), []byte("alice:$6$new:20001"))
	r, _ := Parse([]string{"passwd", "alice"})
	got, err := r.Apply(base, before, after)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got["shadow"]), "bob:!") || !bytes.Equal(got["passwd"], base["passwd"]) {
		t.Fatal("committed another account's temporary lock")
	}
	if !strings.Contains(string(got["shadow"]), "alice:$6$new:20001") {
		t.Fatal("password not accepted")
	}
}

func TestRefusesUnrelatedAndPrivilegeChanges(t *testing.T) {
	cases := []struct{ file, old, next string }{
		{"passwd", "alice:x:1000", "alice:x:0"},
		{"passwd", "/home/alice:/bin/bash", "/home/alice:/sbin/nologin"},
		{"shadow", "bob:$6$bob", "bob:$6$evil"},
		{"shadow", "alice:$6$old:20000:0:99999", "alice:$6$new:20001:0:1"},
		{"shadow", "bob:$6$bob:20000:0:99999:7:::\n", ""},
		{"group", "sudo:x:27:alice", "sudo:x:27:alice,bob"},
		{"gshadow", "sudo:!::alice", "sudo:!:bob:alice"},
	}
	for _, c := range cases {
		t.Run(c.file+c.next, func(t *testing.T) {
			base := fixture()
			after := maps.Clone(base)
			after[c.file] = bytes.ReplaceAll(base[c.file], []byte(c.old), []byte(c.next))
			r, _ := Parse([]string{"passwd", "alice"})
			if _, err := r.Apply(base, base, after); err == nil {
				t.Fatal("accepted unrelated change")
			}
		})
	}
}

func TestGroupMembershipExactScope(t *testing.T) {
	for _, op := range []string{"-a", "-d"} {
		base := fixture()
		after := maps.Clone(base)
		member, next := "bob", "alice,bob"
		if op == "-d" {
			member, next = "alice", ""
		}
		for _, name := range []string{"group", "gshadow"} {
			after[name] = bytes.ReplaceAll(base[name], []byte(":alice\n"), []byte(":"+next+"\n"))
		}
		r, _ := Parse([]string{"gpasswd", op, member, "sudo"})
		if _, err := r.Apply(base, base, after); err != nil {
			t.Fatal(err)
		}
		after["group"] = bytes.ReplaceAll(after["group"], []byte("sudo:x:27:"), []byte("sudo:x:0:"))
		if _, err := r.Apply(base, base, after); err == nil {
			t.Fatal("accepted changed GID")
		}
	}
}

func TestRejectsMalformedOrMissingTargets(t *testing.T) {
	for _, target := range []string{"nonlocal", "alice"} {
		base := fixture()
		if target == "alice" {
			base["shadow"] = append(base["shadow"], []byte("alice:$6$evil:20000:0:99999:7:::\n")...)
		}
		r, _ := Parse([]string{"passwd", target})
		if err := r.ValidateBefore(base); err == nil {
			t.Fatal("accepted missing or duplicate user")
		}
	}
}

func TestGroupPasswordDoesNotApproveAdministrators(t *testing.T) {
	base := fixture()
	after := maps.Clone(base)
	after["gshadow"] = bytes.ReplaceAll(base["gshadow"], []byte("sudo:!::alice"), []byte("sudo:$6$new::alice"))
	r, _ := Parse([]string{"gpasswd", "sudo"})
	if _, err := r.Apply(base, base, after); err != nil {
		t.Fatal(err)
	}
	after["gshadow"] = bytes.ReplaceAll(after["gshadow"], []byte("::alice"), []byte(":bob:alice"))
	if _, err := r.Apply(base, base, after); err == nil {
		t.Fatal("approved administrator change")
	}
}

func TestGroupChangeMustReachBothDatabases(t *testing.T) {
	base := fixture()
	after := maps.Clone(base)
	after["group"] = bytes.ReplaceAll(base["group"], []byte(":alice\n"), []byte(":alice,bob\n"))
	r, _ := Parse([]string{"gpasswd", "-a", "bob", "sudo"})
	if _, err := r.Apply(base, base, after); err == nil {
		t.Fatal("accepted inconsistent group and gshadow")
	}
}

func TestPasswordChangeCannotBecomePasswordless(t *testing.T) {
	base := fixture()
	after := maps.Clone(base)
	after["shadow"] = bytes.ReplaceAll(base["shadow"], []byte("alice:$6$old:"), []byte("alice::"))
	r, _ := Parse([]string{"passwd", "alice"})
	if _, err := r.Apply(base, base, after); err == nil {
		t.Fatal("accepted password deletion")
	}
}

func TestBatchMembershipReplacement(t *testing.T) {
	for _, list := range []string{"bob,alice", "bob", ""} {
		t.Run("members="+list, func(t *testing.T) {
			base := fixture()
			after := maps.Clone(base)
			for _, file := range []string{"group", "gshadow"} {
				after[file] = bytes.ReplaceAll(base[file], []byte(":alice\n"), []byte(":"+list+"\n"))
			}
			r, err := Parse([]string{"gpasswd", "-M", list, "sudo"})
			if err != nil {
				t.Fatal(err)
			}
			if got := r.Args(); len(got) != 3 || got[0] != "-M" || got[1] != list || got[2] != "sudo" {
				t.Fatalf("incorrect native arguments: %q", got)
			}
			if _, err := r.Apply(base, base, after); err != nil {
				t.Fatal(err)
			}
			// A mismatch in either database must be rejected, even when clearing the list.
			after["gshadow"] = bytes.ReplaceAll(base["gshadow"], []byte(":alice\n"), []byte(":root\n"))
			if _, err := r.Apply(base, base, after); err == nil {
				t.Fatal("accepted mismatched gshadow batch")
			}
		})
	}
}

func TestBatchRejectsMalformedAndNonlocalMembers(t *testing.T) {
	for _, list := range []string{"alice,alice", "alice,", ",alice", "alice,,bob", "alice, bob", "alice,-R", "alice\nroot"} {
		if _, err := Parse([]string{"gpasswd", "-M", list, "sudo"}); err == nil {
			t.Fatalf("accepted %q", list)
		}
	}
	for _, op := range []string{"-a", "-d"} {
		for _, list := range []string{"alice,bob", ""} {
			if _, err := Parse([]string{"gpasswd", op, list, "sudo"}); err == nil {
				t.Fatalf("accepted invalid native arguments %s %q", op, list)
			}
		}
	}
	r, err := Parse([]string{"gpasswd", "--members", "alice,unknown", "sudo"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Args()[0] != "-M" {
		t.Fatal("long alias not normalized")
	}
	if err := r.ValidateBefore(fixture()); err == nil {
		t.Fatal("accepted nonlocal member")
	}
}

func TestBatchCannotApproveOtherGroupFields(t *testing.T) {
	for _, c := range []struct{ file, old, next string }{
		{"group", "sudo:x:27:", "sudo:x:0:"},
		{"group", "root:x:0:", "root:x:0:bob"},
		{"gshadow", "sudo:!::", "sudo:!:bob:"},
		{"gshadow", "sudo:!::", "sudo:$6$evil::"},
	} {
		base := fixture()
		after := maps.Clone(base)
		for _, file := range []string{"group", "gshadow"} {
			after[file] = bytes.ReplaceAll(base[file], []byte(":alice\n"), []byte(":bob\n"))
		}
		after[c.file] = bytes.ReplaceAll(after[c.file], []byte(c.old), []byte(c.next))
		r, _ := Parse([]string{"gpasswd", "-M", "bob", "sudo"})
		if _, err := r.Apply(base, base, after); err == nil {
			t.Fatalf("accepted unrelated %s mutation", c.file)
		}
	}
}
