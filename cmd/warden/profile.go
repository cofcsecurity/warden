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

// An optional host profile replaces all default paths and service mappings.
// The fixed location also applies to unattended timer/cron invocations.
const hostProfilePath = "/etc/warden/profile.json"

type hostProfile struct {
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
		return fmt.Errorf("host profile: paths is required (use [] for no watched files)")
	}
	var configs, dataPaths []string
	confirm := map[string]bool{}
	services := map[string][]string{}
	seen := map[string]bool{}
	for _, p := range profile.Paths {
		if !filepath.IsAbs(p.Path) || filepath.Clean(p.Path) != p.Path || seen[p.Path] {
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
		services[p.Path] = p.Services
	}
	for unit, args := range profile.Validators {
		if unit == "" || len(args) == 0 || !filepath.IsAbs(args[0]) {
			return fmt.Errorf("host profile: validator requires unit and absolute executable")
		}
	}
	ignoredProcesses = map[string]bool{}
	for _, name := range profile.IgnoredProcesses {
		if name == "" {
			return fmt.Errorf("host profile: ignored process name cannot be empty")
		}
		ignoredProcesses[name] = true
	}
	serviceValidators = profile.Validators
	configTierPaths, watchedPaths, dataTierPaths = configs, configs, dataPaths
	confirmFirstPaths, pathServices = confirm, services
	detect.KnownServices = append(detect.KnownServices, profile.Services...)
	return nil
}
