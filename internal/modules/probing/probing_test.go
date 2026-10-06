package probing

import (
	"context"
	"errors"
	"net/url"
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

func (m *mockRunner) RunHTTPX(ctx context.Context, inputPath, rawPath string) error {
	if m.err != nil {
		return m.err
	}

	return os.WriteFile(rawPath, []byte(m.output), 0644)
}

func testConfig(t *testing.T, output string) (Config, *store.AssetStore) {
	t.Helper()

	dir := t.TempDir()

	return Config{
		SubdomainsFile: filepath.Join(dir, "subdomains.txt"),
		HTTPXRaw:       filepath.Join(dir, "raw", "httpx.raw"),
		LiveFile:       filepath.Join(dir, "live.txt"),
		Runner: &mockRunner{
			output: output,
		},
	}, store.NewAssetStore()
}

// Test 1 - endpoint discovery
func TestRun_DiscoversEndpoints(t *testing.T) {
	output := strings.Join([]string{
		"https://example.com/",
		"https://example.com/login",
		"https://example.com/api/users",
	}, "\n") + "\n"

	cfg, assets := testConfig(t, output)

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	eps := assets.WebEndpoints()
	if len(eps) != 3 {
		t.Fatalf("expected 3 endpoints, got %d", len(eps))
	}

	wantPaths := map[string]bool{"/login": false, "/api/users": false}

	for _, ep := range eps {
		u, err := url.Parse(ep.URL)
		if err != nil {
			t.Fatalf("stored URL %q does not parse: %v", ep.URL, err)
		}

		if ep.Host != "example.com" {
			t.Errorf("Host = %q, want example.com", ep.Host)
		}
		if u.Scheme != "https" {
			t.Errorf("scheme = %q, want https", u.Scheme)
		}
		if u.Port() != "" {
			t.Errorf("port = %q, want default (empty)", u.Port())
		}
		if u.RawQuery != "" {
			t.Errorf("RawQuery = %q, want empty", u.RawQuery)
		}
		if _, ok := wantPaths[u.Path]; ok {
			wantPaths[u.Path] = true
		} else if u.Path != "" && u.Path != "/" {
			t.Errorf("unexpected path %q", u.Path)
		}
	}

	for p, seen := range wantPaths {
		if !seen {
			t.Errorf("path %q not found in stored endpoints", p)
		}
	}
}

// Test 2 - query preservation
func TestRun_PreservesQuery(t *testing.T) {
	output := "https://example.com/app?debug=true&version=123\n"

	cfg, assets := testConfig(t, output)

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	eps := assets.WebEndpoints()
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(eps))
	}

	u, err := url.Parse(eps[0].URL)
	if err != nil {
		t.Fatalf("stored URL does not parse: %v", err)
	}

	if u.RawQuery != "debug=true&version=123" {
		t.Errorf("RawQuery = %q, want %q", u.RawQuery, "debug=true&version=123")
	}

	if !strings.Contains(eps[0].URL, "?debug=true&version=123") {
		t.Errorf("stored URL lost query: %q", eps[0].URL)
	}
}

// Test 3 - HTTP and HTTPS
func TestRun_HTTPAndHTTPS(t *testing.T) {
	output := "http://example.com/\nhttps://example.com/\n"

	cfg, assets := testConfig(t, output)

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	eps := assets.WebEndpoints()
	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(eps))
	}

	schemes := map[string]bool{}

	for _, ep := range eps {
		u, err := url.Parse(ep.URL)
		if err != nil {
			t.Fatalf("stored URL %q does not parse: %v", ep.URL, err)
		}
		schemes[u.Scheme] = true
	}

	if !schemes["http"] || !schemes["https"] {
		t.Fatalf("expected both http and https endpoints, got %v", schemes)
	}
}

// Test 4 - raw output byte-for-byte
func TestRun_RawOutputExact(t *testing.T) {
	output := "https://example.com/\nhttp://api.example.com/v1?x=1\n"

	cfg, assets := testConfig(t, output)

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	raw, err := os.ReadFile(cfg.HTTPXRaw)
	if err != nil {
		t.Fatalf("failed to read raw output: %v", err)
	}

	if string(raw) != output {
		t.Fatalf("raw output changed:\nwant: %q\ngot:  %q", output, string(raw))
	}
}

// Test 5 - legacy live.txt
func TestRun_LegacyOutput(t *testing.T) {
	output := "https://example.com/login\nhttps://example.com/api/users\n"

	cfg, assets := testConfig(t, output)

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	legacy, err := os.ReadFile(cfg.LiveFile)
	if err != nil {
		t.Fatalf("failed to read live.txt: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(legacy)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines in live.txt, got %d: %q", len(lines), string(legacy))
	}

	got := string(legacy)
	for _, want := range []string{"https://example.com/login", "https://example.com/api/users"} {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("live.txt missing %q: %q", want, got)
		}
	}
}

// Test 6 - deduplication
func TestRun_DeduplicatesEndpoints(t *testing.T) {
	output := "https://example.com/\nhttps://example.com/\n"

	cfg, assets := testConfig(t, output)

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if got := len(assets.WebEndpoints()); got != 1 {
		t.Fatalf("expected 1 deduplicated endpoint, got %d", got)
	}

	legacy, err := os.ReadFile(cfg.LiveFile)
	if err != nil {
		t.Fatalf("failed to read live.txt: %v", err)
	}

	if got := len(strings.Split(strings.TrimSpace(string(legacy)), "\n")); got != 1 {
		t.Fatalf("expected 1 line in live.txt, got %d", got)
	}
}

// Test 7 - invalid URL does not abort the run
func TestRun_InvalidURLDoesNotAbort(t *testing.T) {
	output := strings.Join([]string{
		"https://valid.example.com/",
		"://invalid",
		"not a url",
		"ftp://files.example.com/",
		"https://another.example.com/",
	}, "\n") + "\n"

	cfg, assets := testConfig(t, output)

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if got := len(assets.WebEndpoints()); got != 2 {
		t.Fatalf("expected 2 valid endpoints, got %d", got)
	}
}

// Test 8 - empty output
func TestRun_EmptyOutput(t *testing.T) {
	cfg, assets := testConfig(t, "")

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if got := len(assets.WebEndpoints()); got != 0 {
		t.Fatalf("expected no endpoints, got %d", got)
	}

	if _, err := os.Stat(cfg.HTTPXRaw); err != nil {
		t.Errorf("raw file should exist: %v", err)
	}

	legacy, err := os.ReadFile(cfg.LiveFile)
	if err != nil {
		t.Fatalf("live.txt should exist: %v", err)
	}

	if len(legacy) != 0 {
		t.Errorf("live.txt should be empty, got %q", string(legacy))
	}
}

// Test 9 - scanner error
func TestRun_ScannerError(t *testing.T) {
	cfg, assets := testConfig(t, strings.Repeat("X", 70*1024)+"\n")

	err := Run(context.Background(), cfg, assets)

	if err == nil {
		t.Fatal("expected scanner error")
	}

	if !strings.Contains(err.Error(), "failed to scan raw httpx output") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Test 10 - runner error
func TestRun_RunnerError(t *testing.T) {
	cfg, assets := testConfig(t, "")

	cfg.Runner = &mockRunner{
		err: errors.New("mock httpx failure"),
	}

	err := Run(context.Background(), cfg, assets)

	if err == nil {
		t.Fatal("expected Run() error")
	}

	if !strings.Contains(err.Error(), "failed to execute httpx") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Test 11 - legacy output write failure
func TestRun_LegacyOutputWriteError(t *testing.T) {
	cfg, assets := testConfig(t, "https://example.com/\n")

	cfg.LiveFile = filepath.Join(t.TempDir(), "missing", "live.txt")

	err := Run(context.Background(), cfg, assets)

	if err == nil {
		t.Fatal("expected legacy output write error")
	}

	if !strings.Contains(err.Error(), "failed to create legacy live output") {
		t.Fatalf("unexpected error: %v", err)
	}
}
