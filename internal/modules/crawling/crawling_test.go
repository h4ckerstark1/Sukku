package crawling

import (
	"context"
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

func (m *mockRunner) RunKatana(ctx context.Context, livePath, rawPath string) error {
	if m.err != nil {
		return m.err
	}

	return os.WriteFile(rawPath, []byte(m.output), 0644)
}

func newTestConfig(t *testing.T, output string) (Config, string, string) {
	t.Helper()

	dir := t.TempDir()

	liveFile := filepath.Join(dir, "live.txt")
	rawFile := filepath.Join(dir, "raw", "katana.raw")
	jsFile := filepath.Join(dir, "jsfiles.txt")

	if err := os.WriteFile(liveFile, []byte("https://example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	return Config{
		LiveFile:    liveFile,
		KatanaRaw:   rawFile,
		JSFilesFile: jsFile,
		Runner:      &mockRunner{output: output},
	}, rawFile, jsFile
}

func TestCrawling_Run_URLDiscoveryAndJSDetection(t *testing.T) {
	output := strings.Join([]string{
		"https://example.com/",
		"https://example.com/login",
		"https://example.com/api/users",
		"https://example.com/app.js",
		"https://example.com/static/main.min.js?v=123",
		"https://example.com/javascript",
		"https://example.com/js",
	}, "\n") + "\n"

	cfg, rawPath, jsPath := newTestConfig(t, output)
	assetStore := store.NewAssetStore()

	if err := Run(context.Background(), cfg, assetStore); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	endpoints := assetStore.WebEndpoints()
	if len(endpoints) != 7 {
		t.Fatalf("expected 7 endpoints, got %d", len(endpoints))
	}

	jsFiles := assetStore.JSFiles()
	if len(jsFiles) != 2 {
		t.Fatalf("expected 2 JS files, got %d", len(jsFiles))
	}

	if jsFiles[0].URL != "https://example.com/app.js" {
		t.Fatalf("unexpected first JS URL: %s", jsFiles[0].URL)
	}

	if jsFiles[1].URL != "https://example.com/static/main.min.js?v=123" {
		t.Fatalf("unexpected second JS URL: %s", jsFiles[1].URL)
	}

	if jsFiles[0].Host != "example.com" || jsFiles[1].Host != "example.com" {
		t.Fatalf("unexpected JS host values")
	}

	raw, err := os.ReadFile(rawPath)
	if err != nil {
		t.Fatalf("failed to read raw output: %v", err)
	}

	if string(raw) != output {
		t.Fatalf("raw output changed\nwant:\n%q\ngot:\n%q", output, string(raw))
	}

	legacy, err := os.ReadFile(jsPath)
	if err != nil {
		t.Fatalf("failed to read legacy output: %v", err)
	}

	wantLegacy := "https://example.com/app.js\nhttps://example.com/static/main.min.js?v=123\n"
	if string(legacy) != wantLegacy {
		t.Fatalf("unexpected jsfiles.txt\nwant:\n%q\ngot:\n%q", wantLegacy, string(legacy))
	}
}

func TestCrawling_Run_QueryPreservation(t *testing.T) {
	output := "https://example.com/app.js?v=123&debug=true\n"

	cfg, _, _ := newTestConfig(t, output)
	assetStore := store.NewAssetStore()

	if err := Run(context.Background(), cfg, assetStore); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	endpoints := assetStore.WebEndpoints()
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}

	if endpoints[0].URL != output[:len(output)-1] {
		t.Fatalf("query was not preserved: %s", endpoints[0].URL)
	}

	jsFiles := assetStore.JSFiles()
	if len(jsFiles) != 1 {
		t.Fatalf("expected 1 JS file, got %d", len(jsFiles))
	}

	if jsFiles[0].URL != output[:len(output)-1] {
		t.Fatalf("JS query was not preserved: %s", jsFiles[0].URL)
	}
}

func TestCrawling_Run_DeduplicatesJSURLs(t *testing.T) {
	output := strings.Join([]string{
		"https://example.com/app.js",
		"https://example.com/app.js",
		"HTTPS://EXAMPLE.COM/app.js",
	}, "\n") + "\n"

	cfg, _, _ := newTestConfig(t, output)
	assetStore := store.NewAssetStore()

	if err := Run(context.Background(), cfg, assetStore); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	jsFiles := assetStore.JSFiles()
	if len(jsFiles) != 1 {
		t.Fatalf("expected 1 deduplicated JS file, got %d", len(jsFiles))
	}
}

func TestCrawling_Run_InvalidURLDoesNotAbort(t *testing.T) {
	output := strings.Join([]string{
		"https://example.com/",
		"://invalid-url",
		"https://example.com/app.js",
	}, "\n") + "\n"

	cfg, _, _ := newTestConfig(t, output)
	assetStore := store.NewAssetStore()

	if err := Run(context.Background(), cfg, assetStore); err != nil {
		t.Fatalf("Run() should continue after invalid URL: %v", err)
	}

	if len(assetStore.WebEndpoints()) != 2 {
		t.Fatalf("expected 2 valid endpoints, got %d", len(assetStore.WebEndpoints()))
	}

	if len(assetStore.JSFiles()) != 1 {
		t.Fatalf("expected 1 JS file, got %d", len(assetStore.JSFiles()))
	}
}

func TestCrawling_Run_ScannerError(t *testing.T) {
	dir := t.TempDir()

	liveFile := filepath.Join(dir, "live.txt")
	rawFile := filepath.Join(dir, "raw", "katana.raw")
	jsFile := filepath.Join(dir, "jsfiles.txt")

	if err := os.WriteFile(liveFile, []byte("https://example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	oversized := strings.Repeat("X", 70*1024) + "\n"

	cfg := Config{
		LiveFile:    liveFile,
		KatanaRaw:   rawFile,
		JSFilesFile: jsFile,
		Runner:      &mockRunner{output: oversized},
	}

	err := Run(context.Background(), cfg, store.NewAssetStore())
	if err == nil {
		t.Fatal("expected scanner error, got nil")
	}

	if !strings.Contains(err.Error(), "failed to scan raw katana output") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCrawling_Run_RunnerError(t *testing.T) {
	dir := t.TempDir()

	cfg := Config{
		LiveFile:    filepath.Join(dir, "live.txt"),
		KatanaRaw:   filepath.Join(dir, "raw", "katana.raw"),
		JSFilesFile: filepath.Join(dir, "jsfiles.txt"),
		Runner: &mockRunner{
			err: os.ErrPermission,
		},
	}

	err := Run(context.Background(), cfg, store.NewAssetStore())
	if err == nil {
		t.Fatal("expected runner error, got nil")
	}

	if !strings.Contains(err.Error(), "failed to execute katana crawler") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCrawling_Run_EmptyOutput(t *testing.T) {
	cfg, rawPath, jsPath := newTestConfig(t, "")
	assetStore := store.NewAssetStore()

	if err := Run(context.Background(), cfg, assetStore); err != nil {
		t.Fatalf("empty output should not fail: %v", err)
	}

	if len(assetStore.WebEndpoints()) != 0 {
		t.Fatalf("expected no endpoints")
	}

	if len(assetStore.JSFiles()) != 0 {
		t.Fatalf("expected no JS files")
	}

	raw, err := os.ReadFile(rawPath)
	if err != nil {
		t.Fatalf("failed to read raw file: %v", err)
	}

	if len(raw) != 0 {
		t.Fatalf("expected empty raw file")
	}

	legacy, err := os.ReadFile(jsPath)
	if err != nil {
		t.Fatalf("failed to read legacy file: %v", err)
	}

	if len(legacy) != 0 {
		t.Fatalf("expected empty jsfiles.txt")
	}
}

func TestIsJSPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/app.js", true},
		{"/static/main.min.js", true},
		{"/app.js/", false},
		{"/javascript", false},
		{"/js", false},
		{"/page.html", false},
		{"/api/users", false},
	}

	for _, tt := range tests {
		if got := isJSPath(tt.path); got != tt.want {
			t.Errorf("isJSPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
