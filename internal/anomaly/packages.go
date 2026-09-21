package anomaly

import (
	"os/exec"
	"path/filepath"
	"strings"
)

// listInstalledPackages auto-detects dpkg vs rpm and returns every
// installed package's name — a var so tests can fake it without a real
// package manager. Neither tool reliably records *who* ran an install
// (dpkg's log has no user field; sudo's own logging would, but that's a
// separate signal this doesn't correlate), so CheckPackages never
// attributes a Culprit for these findings, unlike every other check in
// this package.
var listInstalledPackages = func() ([]string, error) {
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		out, err := exec.Command("dpkg-query", "-W", "-f", "${Package}\n").Output()
		if err != nil {
			return nil, err
		}
		return nonEmptyLines(out), nil
	}
	if _, err := exec.LookPath("rpm"); err == nil {
		out, err := exec.Command("rpm", "-qa", "--queryformat", "%{NAME}\n").Output()
		if err != nil {
			return nil, err
		}
		return nonEmptyLines(out), nil
	}
	return nil, nil
}

func nonEmptyLines(data []byte) []string {
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// CheckPackages flags any installed package that wasn't present as of the
// last run. No package manager found on this box (or `listInstalledPackages`
// erroring) just means this signal isn't available — reported as zero
// findings, not an error, so it never breaks the rest of `scan`.
func CheckPackages(baselineDir string) ([]Finding, error) {
	names, err := listInstalledPackages()
	if err != nil || len(names) == 0 {
		return nil, nil
	}

	baselinePath := filepath.Join(baselineDir, "packages.json")
	bootstrap := firstRun(baselinePath)
	old, err := loadBaseline(baselinePath)
	if err != nil {
		return nil, err
	}

	next := baseline{}
	var findings []Finding
	for _, name := range names {
		next[name] = "1"
		if bootstrap {
			continue
		}
		if _, existed := old[name]; existed {
			continue
		}
		findings = append(findings, Finding{
			Check:       "packages",
			Description: "new package installed: " + name,
			Detail:      "package managers don't reliably record who ran the install — no culprit attributed",
		})
	}

	if err := saveBaseline(baselinePath, next); err != nil {
		return nil, err
	}
	return findings, nil
}
