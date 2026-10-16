package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"warden/internal/detect"
)

// The optional host profile lives in the state directory and extends the
// built-in defaults: its entries are checked first, so an entry here can
// reclassify a default path. "replace": true drops the defaults entirely,
// and "exclude" removes default entries by exact pattern.
type hostProfile struct {
	Replace          bool                `json:"replace,omitempty"`
	Exclude          []string            `json:"exclude,omitempty"`
	Paths            []profilePath       `json:"paths"`
	Services         []detect.Service    `json:"services,omitempty"`
	Validators       map[string][]string `json:"validators,omitempty"`
	IgnoredProcesses []string            `json:"ignored_processes,omitempty"`
}
type profilePath struct {
	Path     string   `json:"path"`
	Tier     string   `json:"tier"`
	Class    string   `json:"class"`
	Services []string `json:"services,omitempty"`
}

// The defaults, captured once so loading a profile is repeatable.
var (
	defaultConfigTierPaths   = append([]string(nil), configTierPaths...)
	defaultDataTierPaths     = append([]string(nil), dataTierPaths...)
	defaultConfirmFirstPaths = copyBoolMap(confirmFirstPaths)
	defaultPathServices      = copyServiceMap(pathServices)
	defaultKnownServices     = append([]detect.Service(nil), detect.KnownServices...)
)

func copyBoolMap(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func copyServiceMap(m map[string][]string) map[string][]string {
	out := make(map[string][]string, len(m))
	for k, v := range m {
		out[k] = append([]string(nil), v...)
	}
	return out
}

func loadHostProfile(path string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var profile hostProfile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&profile); err != nil {
		return fmt.Errorf("host profile: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("host profile: expected one JSON object")
	}
	if profile.Paths == nil {
		return fmt.Errorf("host profile: paths is required (use [] for none)")
	}

	var configs, dataPaths []string
	confirm := map[string]bool{}
	services := map[string][]string{}
	seen := map[string]bool{}
	for _, p := range profile.Paths {
		if !validProfileEntry(p.Path) || seen[p.Path] {
			return fmt.Errorf("host profile: invalid or duplicate absolute path %q", p.Path)
		}
		seen[p.Path] = true
		tier, err := parseTier(p.Tier)
		if err != nil {
			return err
		}
		if p.Class != "confirm-first" && p.Class != "auto-restore" {
			return fmt.Errorf("host profile: path %s needs class confirm-first or auto-restore", p.Path)
		}
		for _, unit := range p.Services {
			if unit == "" || strings.ContainsAny(unit, "/\\\x00\n\r\t ") || strings.HasPrefix(unit, "-") {
				return fmt.Errorf("host profile: invalid service %q", unit)
			}
		}
		if tier == tierData {
			dataPaths = append(dataPaths, p.Path)
		} else {
			configs = append(configs, p.Path)
		}
		confirm[p.Path] = p.Class == "confirm-first"
		if len(p.Services) > 0 {
			services[p.Path] = p.Services
		}
	}
	for _, e := range profile.Exclude {
		if !validProfileEntry(e) {
			return fmt.Errorf("host profile: invalid exclude %q", e)
		}
	}
	for unit, args := range profile.Validators {
		if unit == "" || len(args) == 0 || !filepath.IsAbs(args[0]) {
			return fmt.Errorf("host profile: validator requires unit and absolute executable")
		}
	}
	ignored := map[string]bool{}
	for _, name := range profile.IgnoredProcesses {
		if name == "" {
			return fmt.Errorf("host profile: ignored process name cannot be empty")
		}
		ignored[name] = true
	}

	// Valid: apply, starting from the defaults unless replacing them.
	excluded := map[string]bool{}
	for _, e := range profile.Exclude {
		excluded[e] = true
	}
	baseConfig, baseData := defaultConfigTierPaths, defaultDataTierPaths
	baseConfirm, baseServices := defaultConfirmFirstPaths, defaultPathServices
	if profile.Replace {
		baseConfig, baseData, baseConfirm, baseServices = nil, nil, map[string]bool{}, map[string][]string{}
	}
	for _, e := range baseConfig {
		if !excluded[e] && !seen[e] {
			configs = append(configs, e)
		}
	}
	for _, e := range baseData {
		if !excluded[e] && !seen[e] {
			dataPaths = append(dataPaths, e)
		}
	}
	for k, v := range baseConfirm {
		if _, set := confirm[k]; !set {
			confirm[k] = v
		}
	}
	for k, v := range baseServices {
		if _, set := services[k]; !set {
			services[k] = v
		}
	}

	ignoredProcesses = ignored
	serviceValidators = profile.Validators
	configTierPaths, dataTierPaths = configs, dataPaths
	confirmFirstPaths, pathServices = confirm, services
	detect.KnownServices = append(append([]detect.Service(nil), defaultKnownServices...), profile.Services...)
	return nil
}

// validProfileEntry accepts an absolute, clean path, optionally a glob or
// a trailing "/**" tree.
func validProfileEntry(entry string) bool {
	root := strings.TrimSuffix(entry, "/**")
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || strings.Contains(root, "**") {
		return false
	}
	if _, err := filepath.Match(root, root); err != nil {
		return false
	}
	return true
}
