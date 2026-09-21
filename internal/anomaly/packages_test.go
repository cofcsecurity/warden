package anomaly

import (
	"testing"
)

func TestCheckPackagesFirstRunBootstrapsSilently(t *testing.T) {
	baseDir := t.TempDir()
	listInstalledPackages = func() ([]string, error) {
		return []string{"openssh-server", "curl"}, nil
	}

	findings, err := CheckPackages(baseDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings on first run, got %+v", findings)
	}
}

func TestCheckPackagesFlagsNewPackageWithNoCulprit(t *testing.T) {
	baseDir := t.TempDir()
	listInstalledPackages = func() ([]string, error) {
		return []string{"openssh-server", "curl"}, nil
	}
	if _, err := CheckPackages(baseDir); err != nil {
		t.Fatal(err)
	}

	listInstalledPackages = func() ([]string, error) {
		return []string{"openssh-server", "curl", "netcat-traditional"}, nil
	}

	findings, err := CheckPackages(baseDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly one finding, got %+v", findings)
	}
	if findings[0].Culprit != "" {
		t.Fatalf("expected no culprit for a package finding, got %+v", findings[0])
	}
}

func TestCheckPackagesNoManagerAvailableIsNotAnError(t *testing.T) {
	baseDir := t.TempDir()
	listInstalledPackages = func() ([]string, error) {
		return nil, nil
	}

	findings, err := CheckPackages(baseDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings when no package manager is available, got %+v", findings)
	}
}
