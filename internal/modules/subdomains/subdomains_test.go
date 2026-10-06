package subdomains

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sukku/internal/store"
)

type mockRunner struct {
	output string
	err    error
}

func (m *mockRunner) RunSubfinder(ctx context.Context, domain, rawPath string) error {
	if m.err != nil {
		return m.err
	}

	return os.WriteFile(rawPath, []byte(m.output), 0644)
}

func testConfig(t *testing.T, output string) (Config, *store.AssetStore) {
	t.Helper()

	dir := t.TempDir()

	return Config{
		Domain:         "example.com",
		SubfinderRaw:   filepath.Join(dir, "raw", "subfinder.raw"),
		SubdomainsFile: filepath.Join(dir, "subdomains.txt"),
		Runner: &mockRunner{
			output: output,
		},
	}, store.NewAssetStore()
}

func TestRun_DiscoversDomains(t *testing.T) {
	output := strings.Join([]string{
		"api.example.com",
		"www.example.com",
		"admin.example.com",
	}, "\n") + "\n"

	cfg, assets := testConfig(t, output)

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	domains := assets.Domains()

	if len(domains) != 3 {
		t.Fatalf("expected 3 domains, got %d", len(domains))
	}

	want := []string{
		"admin.example.com",
		"api.example.com",
		"www.example.com",
	}

	for i, domain := range domains {
		if domain.Name != want[i] {
			t.Errorf("domain[%d] = %q, want %q", i, domain.Name, want[i])
		}
	}
}

func TestRun_NormalizesDomains(t *testing.T) {
	output := "  API.Example.COM.  \n"

	cfg, assets := testConfig(t, output)

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	domains := assets.Domains()

	if len(domains) != 1 {
		t.Fatalf("expected 1 domain, got %d", len(domains))
	}

	if domains[0].Name != "api.example.com" {
		t.Errorf("domain = %q, want %q", domains[0].Name, "api.example.com")
	}
}

func TestRun_DeduplicatesDomains(t *testing.T) {
	output := strings.Join([]string{
		"api.example.com",
		"api.example.com",
		"API.EXAMPLE.COM.",
	}, "\n") + "\n"

	cfg, assets := testConfig(t, output)

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if got := len(assets.Domains()); got != 1 {
		t.Fatalf("expected 1 deduplicated domain, got %d", got)
	}
}

func TestRun_InvalidDomainDoesNotAbort(t *testing.T) {
	output := strings.Join([]string{
		"valid.example.com",
		"not a domain",
		"another.example.com",
	}, "\n") + "\n"

	cfg, assets := testConfig(t, output)

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if got := len(assets.Domains()); got != 2 {
		t.Fatalf("expected 2 valid domains, got %d", got)
	}
}

func TestRun_RawOutputExact(t *testing.T) {
	output := "api.example.com\nwww.example.com\n"

	cfg, assets := testConfig(t, output)

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	raw, err := os.ReadFile(cfg.SubfinderRaw)
	if err != nil {
		t.Fatalf("failed to read raw output: %v", err)
	}

	if string(raw) != output {
		t.Fatalf("raw output changed:\nwant: %q\ngot:  %q", output, string(raw))
	}
}

func TestRun_EmptyOutput(t *testing.T) {
	cfg, assets := testConfig(t, "")

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if got := len(assets.Domains()); got != 0 {
		t.Fatalf("expected no domains, got %d", got)
	}
}

func TestRun_ScannerError(t *testing.T) {
	dir := t.TempDir()

	cfg := Config{
		Domain:         "example.com",
		SubfinderRaw:   filepath.Join(dir, "raw", "subfinder.raw"),
		SubdomainsFile: filepath.Join(dir, "subdomains.txt"),
		Runner: &mockRunner{
			output: strings.Repeat("X", 70*1024) + "\n",
		},
	}

	assets := store.NewAssetStore()

	err := Run(context.Background(), cfg, assets)

	if err == nil {
		t.Fatal("expected scanner error")
	}

	if !strings.Contains(err.Error(), "failed to scan raw subfinder output") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_RunnerError(t *testing.T) {
	cfg, assets := testConfig(t, "")

	cfg.Runner = &mockRunner{
		err: errors.New("mock subfinder failure"),
	}

	err := Run(context.Background(), cfg, assets)

	if err == nil {
		t.Fatal("expected Run() error")
	}

	if !strings.Contains(err.Error(), "failed to execute subfinder") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_LegacyOutput(t *testing.T) {
	output := "api.example.com\nwww.example.com\n"

	cfg, assets := testConfig(t, output)

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	legacy, err := os.ReadFile(cfg.SubdomainsFile)
	if err != nil {
		t.Fatalf("failed to read legacy output: %v", err)
	}

	want := "api.example.com\nwww.example.com\n"

	if string(legacy) != want {
		t.Fatalf("legacy output = %q, want %q", string(legacy), want)
	}
}

func TestRun_LegacyOutputWriteError(t *testing.T) {
	output := "api.example.com\n"

	cfg, assets := testConfig(t, output)

	cfg.SubdomainsFile = filepath.Join(
		t.TempDir(),
		"missing",
		"subdomains.txt",
	)

	err := Run(context.Background(), cfg, assets)

	if err == nil {
		t.Fatal("expected legacy output write error")
	}

	if !strings.Contains(err.Error(), "failed to create legacy subdomains output") {
		t.Fatalf("unexpected error: %v", err)
	}
}
