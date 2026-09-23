// Package accountedit validates the exact account-file changes authorized by an operator.
package accountedit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var Files = []string{"passwd", "shadow", "group", "gshadow"}
var namePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]*\$?$`)

type Request struct {
	Tool      string
	Target    string
	Member    string
	Operation string
}

// Parse deliberately excludes arbitrary flags, alternate roots and password arguments.
func Parse(args []string) (Request, error) {
	var r Request
	if len(args) == 2 && (args[0] == "passwd" || args[0] == "gpasswd") {
		r = Request{Tool: args[0], Target: args[1], Operation: "password"}
	} else if len(args) == 4 && args[0] == "gpasswd" && (args[1] == "-a" || args[1] == "-d") {
		r = Request{Tool: "gpasswd", Target: args[3], Member: args[2], Operation: args[1]}
	} else {
		return r, fmt.Errorf("use passwd USER, gpasswd GROUP, or gpasswd -a/-d USER GROUP")
	}
	if !namePattern.MatchString(r.Target) || r.Member != "" && !namePattern.MatchString(r.Member) {
		return Request{}, fmt.Errorf("invalid local account or group name")
	}
	return r, nil
}

func (r Request) Args() []string {
	if r.Member != "" {
		return []string{r.Operation, r.Member, r.Target}
	}
	return []string{r.Target}
}

func records(data []byte, count int) (map[string][]string, error) {
	out := map[string][]string{}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("missing final newline")
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) != count || !namePattern.MatchString(f[0]) {
			return nil, fmt.Errorf("unsupported account record")
		}
		if _, ok := out[f[0]]; ok {
			return nil, fmt.Errorf("duplicate account record")
		}
		out[f[0]] = f
	}
	return out, nil
}

func fields(file string) int {
	switch file {
	case "passwd":
		return 7
	case "shadow":
		return 9
	default:
		return 4
	}
}

func (r Request) ValidateBefore(data map[string][]byte) error {
	parsed := map[string]map[string][]string{}
	for _, file := range Files {
		m, err := records(data[file], fields(file))
		if err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		parsed[file] = m
	}
	if r.Tool == "passwd" {
		if parsed["passwd"][r.Target] == nil || parsed["shadow"][r.Target] == nil {
			return fmt.Errorf("target must be an existing local shadow account")
		}
		if parsed["passwd"][r.Target][1] != "x" {
			return fmt.Errorf("target does not use a shadow password")
		}
	} else {
		if parsed["group"][r.Target] == nil || parsed["gshadow"][r.Target] == nil {
			return fmt.Errorf("target must be an existing local shadow group")
		}
		if parsed["group"][r.Target][1] != "x" {
			return fmt.Errorf("target does not use a shadow group password")
		}
		if r.Member != "" && parsed["passwd"][r.Member] == nil {
			return fmt.Errorf("member must be an existing local account")
		}
	}
	return nil
}

// Apply checks all four files, including comments, ordering and unrelated records.
// It merges only validated field changes into the original (not lock-overlaid) baseline.
func (r Request) Apply(base, before, after map[string][]byte) (map[string][]byte, error) {
	if err := r.ValidateBefore(before); err != nil {
		return nil, err
	}
	if err := r.ValidateBefore(after); err != nil {
		return nil, err
	}
	if r.Member != "" {
		for _, file := range []string{"group", "gshadow"} {
			old, _ := records(before[file], fields(file))
			next, _ := records(after[file], fields(file))
			if !sameMembers(next[r.Target][3], changedMembers(old[r.Target][3], r.Member, r.Operation == "-a")) {
				return nil, fmt.Errorf("requested membership change missing from %s", file)
			}
		}
	}
	out := map[string][]byte{}
	for _, file := range Files {
		out[file] = bytes.Clone(base[file])
		if bytes.Equal(before[file], after[file]) {
			continue
		}
		old, err := records(before[file], fields(file))
		if err != nil {
			return nil, err
		}
		next, err := records(after[file], fields(file))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		approved, err := records(base[file], fields(file))
		if err != nil {
			return nil, err
		}
		a, b, original := old[r.Target], next[r.Target], approved[r.Target]
		if a == nil || b == nil || original == nil {
			return nil, fmt.Errorf("unexpected account record change in %s", file)
		}
		allowed := map[int]bool{}
		switch {
		case r.Tool == "passwd" && file == "shadow":
			allowed[1], allowed[2] = true, true
			if a[1] != b[1] && (b[1] == "" || strings.ContainsAny(b[1], "! *\t\r")) {
				return nil, fmt.Errorf("unexpected password field in shadow")
			}
			if a[2] != b[2] {
				if _, err := strconv.ParseUint(b[2], 10, 64); err != nil {
					return nil, fmt.Errorf("invalid password change date")
				}
			}
		case r.Tool == "gpasswd" && r.Operation == "password" && file == "gshadow":
			allowed[1] = true
			if a[1] != b[1] && (b[1] == "" || strings.ContainsAny(b[1], "! *\t\r")) {
				return nil, fmt.Errorf("unexpected group password field")
			}
		case r.Tool == "gpasswd" && r.Member != "" && (file == "group" || file == "gshadow"):
			allowed[3] = true
			if !sameMembers(b[3], changedMembers(a[3], r.Member, r.Operation == "-a")) {
				return nil, fmt.Errorf("unexpected membership change in %s", file)
			}
		}
		merged := slices.Clone(original)
		for i := range a {
			if a[i] == b[i] {
				continue
			}
			if !allowed[i] || original[i] != a[i] {
				return nil, fmt.Errorf("unexpected field change in %s", file)
			}
			merged[i] = b[i]
		}
		// Replacing just the authorized record must reproduce the entire after file.
		expected := replace(before[file], a, b)
		if !bytes.Equal(expected, after[file]) {
			return nil, fmt.Errorf("unrelated change in %s", file)
		}
		out[file] = replace(base[file], original, merged)
	}
	return out, nil
}

func replace(data []byte, old, next []string) []byte {
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if line == strings.Join(old, ":") {
			lines[i] = strings.Join(next, ":")
			break
		}
	}
	return []byte(strings.Join(lines, "\n"))
}
func changedMembers(value, member string, add bool) string {
	var members []string
	for _, v := range strings.Split(value, ",") {
		if v != "" && v != member {
			members = append(members, v)
		}
	}
	if add {
		members = append(members, member)
	}
	return strings.Join(members, ",")
}
func sameMembers(a, b string) bool {
	aa, bb := strings.Split(a, ","), strings.Split(b, ",")
	slices.Sort(aa)
	slices.Sort(bb)
	return slices.Equal(aa, bb)
}

// GroupHash binds approval to the entire target record, including its GID.
func (r Request) GroupHash(data []byte) (string, error) {
	m, err := records(data, 4)
	if err != nil {
		return "", err
	}
	f := m[r.Target]
	if f == nil {
		return "", fmt.Errorf("missing group")
	}
	sum := sha256.Sum256([]byte(strings.Join(f, ":")))
	return hex.EncodeToString(sum[:]), nil
}
