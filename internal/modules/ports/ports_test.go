package ports

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"sukku/internal/models"
	"sukku/internal/store"
)

const sampleOutput = `Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-10-04 13:58 UTC
Nmap scan report for example.com (93.184.216.34)
Host is up (0.012s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT    STATE    SERVICE
21/tcp  closed   ftp
22/tcp  filtered ssh
80/tcp  open     http
443/tcp open     https

Nmap done: 1 IP address (1 host up) scanned in 4.21 seconds
`

type mockRunner struct {
	output  string
	err     error
	called  bool
	targets []string
}

func (m *mockRunner) RunPortscan(ctx context.Context, targets []string, rawPath string) error {
	m.called = true
	m.targets = targets

	if m.err != nil {
		return m.err
	}

	return os.WriteFile(rawPath, []byte(m.output), 0644)
}

func testConfig(t *testing.T, output string) (Config, *store.AssetStore, *mockRunner) {
	t.Helper()

	dir := t.TempDir()
	runner := &mockRunner{output: output}

	assets := store.NewAssetStore()
	if err := assets.AddWebEndpoint(models.WebEndpoint{URL: "https://example.com/", Host: "example.com"}); err != nil {
		t.Fatalf("failed to seed endpoint: %v", err)
	}

	return Config{
		PortscanRaw: filepath.Join(dir, "raw", "portscan.raw"),
		PortsFile:   filepath.Join(dir, "ports.txt"),
		Runner:      runner,
	}, assets, runner
}

// servicesByKey returns "host:port" -> service for easy lookups.
func servicesByKey(svcs []models.Service) map[string]models.Service {
	res := make(map[string]models.Service)
	for _, s := range svcs {
		res[s.Host+":"+itoa(s.Port)] = s
	}
	return res
}

func itoa(n int) string {
	return strings.TrimSpace(strings.Replace(string(rune('0'+0)), "0", "", 1) + fmtInt(n))
}

func fmtInt(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

// Test 1 - service discovery
func TestRun_DiscoversServices(t *testing.T) {
	cfg, assets, _ := testConfig(t, sampleOutput)

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	svcs := assets.Services()
	if len(svcs) != 2 {
		t.Fatalf("expected 2 open services, got %d: %+v", len(svcs), svcs)
	}

	got := servicesByKey(svcs)

	cases := map[string]string{
		"example.com:80":  "http",
		"example.com:443": "https",
	}

	for key, wantName := range cases {
		svc, ok := got[key]
		if !ok {
			t.Fatalf("service %s not found: %+v", key, svcs)
		}
		if svc.Protocol != "tcp" {
			t.Errorf("%s protocol = %q, want tcp", key, svc.Protocol)
		}
		if svc.ServiceName != wantName {
			t.Errorf("%s service name = %q, want %q", key, svc.ServiceName, wantName)
		}
	}
}

// Test 2 - multiple hosts and services
func TestRun_MultipleServices(t *testing.T) {
	output := `Nmap scan report for api.example.com (198.51.100.7)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy

Nmap scan report for www.example.com (198.51.100.8)
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for 192.0.2.10
PORT    STATE SERVICE
443/tcp open  https
`

	cfg, assets, _ := testConfig(t, output)

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	svcs := assets.Services()
	if len(svcs) != 4 {
		t.Fatalf("expected 4 services, got %d: %+v", len(svcs), svcs)
	}

	got := servicesByKey(svcs)

	want := map[string]string{
		"api.example.com:22":   "ssh",
		"api.example.com:8080": "http-proxy",
		"www.example.com:80":   "http",
		"192.0.2.10:443":       "https",
	}

	for key, name := range want {
		svc, ok := got[key]
		if !ok {
			t.Fatalf("service %s not found: %+v", key, svcs)
		}
		if svc.ServiceName != name {
			t.Errorf("%s service name = %q, want %q", key, svc.ServiceName, name)
		}
	}
}

// Test 3 - deduplication
func TestRun_DeduplicatesServices(t *testing.T) {
	cfg, assets, _ := testConfig(t, sampleOutput+sampleOutput)

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if got := len(assets.Services()); got != 2 {
		t.Fatalf("expected 2 deduplicated services, got %d", got)
	}
}

// Test 4 - raw output byte-for-byte
func TestRun_RawOutputExact(t *testing.T) {
	cfg, assets, _ := testConfig(t, sampleOutput)

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	raw, err := os.ReadFile(cfg.PortscanRaw)
	if err != nil {
		t.Fatalf("failed to read raw output: %v", err)
	}

	if string(raw) != sampleOutput {
		t.Fatalf("raw output changed:\nwant: %q\ngot:  %q", sampleOutput, string(raw))
	}
}

// Test 5 - legacy ports.txt
func TestRun_LegacyOutput(t *testing.T) {
	cfg, assets, _ := testConfig(t, sampleOutput)

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	legacy, err := os.ReadFile(cfg.PortsFile)
	if err != nil {
		t.Fatalf("failed to read ports.txt: %v", err)
	}

	if string(legacy) != sampleOutput {
		t.Fatalf("ports.txt = %q, want %q", string(legacy), sampleOutput)
	}
}

// Test 6 - malformed records do not abort the run
func TestRun_MalformedRecordDoesNotAbort(t *testing.T) {
	output := `22/tcp open ssh
Nmap scan report for example.com (93.184.216.34)
Host is up.
PORT      STATE SERVICE
99999/tcp open  http
80/tcp
443/tcp   open  https
`

	cfg, assets, _ := testConfig(t, output)

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	svcs := assets.Services()
	if len(svcs) != 1 {
		t.Fatalf("expected 1 valid service, got %d: %+v", len(svcs), svcs)
	}

	if svcs[0].Host != "example.com" || svcs[0].Port != 443 || svcs[0].ServiceName != "https" {
		t.Errorf("unexpected service: %+v", svcs[0])
	}
}

// Test 7 - empty output
func TestRun_EmptyOutput(t *testing.T) {
	cfg, assets, _ := testConfig(t, "")

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if got := len(assets.Services()); got != 0 {
		t.Fatalf("expected no services, got %d", got)
	}

	if _, err := os.Stat(cfg.PortscanRaw); err != nil {
		t.Errorf("raw file should exist: %v", err)
	}

	if _, err := os.Stat(cfg.PortsFile); err != nil {
		t.Errorf("ports.txt should exist: %v", err)
	}
}

// Test 8 - scanner error
func TestRun_ScannerError(t *testing.T) {
	cfg, assets, _ := testConfig(t, strings.Repeat("X", 70*1024)+"\n")

	err := Run(context.Background(), cfg, assets)

	if err == nil {
		t.Fatal("expected scanner error")
	}

	if !strings.Contains(err.Error(), "failed to scan raw portscan output") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Test 9 - runner error
func TestRun_RunnerError(t *testing.T) {
	cfg, assets, _ := testConfig(t, "")

	cfg.Runner = &mockRunner{err: errors.New("mock nmap failure")}

	err := Run(context.Background(), cfg, assets)

	if err == nil {
		t.Fatal("expected Run() error")
	}

	if !strings.Contains(err.Error(), "failed to execute nmap") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Test 10 - legacy output write failure
func TestRun_LegacyOutputWriteError(t *testing.T) {
	cfg, assets, _ := testConfig(t, sampleOutput)

	cfg.PortsFile = filepath.Join(t.TempDir(), "missing", "ports.txt")

	err := Run(context.Background(), cfg, assets)

	if err == nil {
		t.Fatal("expected legacy output write error")
	}

	if !strings.Contains(err.Error(), "failed to create legacy ports output") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Extra - targets come from stored web endpoints (unique, sorted)
func TestRun_TargetsFromWebEndpoints(t *testing.T) {
	cfg, assets, runner := testConfig(t, "")

	for _, u := range []string{
		"https://b.example.com/x",
		"http://a.example.com:8080/",
		"https://a.example.com/",
	} {
		if err := assets.AddWebEndpoint(models.WebEndpoint{URL: u}); err != nil {
			t.Fatalf("failed to add endpoint %s: %v", u, err)
		}
	}

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	want := []string{"a.example.com", "b.example.com", "example.com"}
	if !reflect.DeepEqual(runner.targets, want) {
		t.Fatalf("targets = %v, want %v", runner.targets, want)
	}
}

// Extra - no endpoints means nmap is not run
func TestRun_NoTargetsSkipsNmap(t *testing.T) {
	cfg, _, runner := testConfig(t, sampleOutput)

	assets := store.NewAssetStore()

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if runner.called {
		t.Error("runner should not be called without targets")
	}

	if _, err := os.Stat(cfg.PortscanRaw); err != nil {
		t.Errorf("raw file should exist: %v", err)
	}

	if _, err := os.Stat(cfg.PortsFile); err != nil {
		t.Errorf("ports.txt should exist: %v", err)
	}
}

// Extra - nmap's "unknown" service is not stored as a name
func TestRun_UnknownServiceLeftEmpty(t *testing.T) {
	output := `Nmap scan report for example.com (93.184.216.34)
PORT     STATE SERVICE
9999/tcp open  unknown
`

	cfg, assets, _ := testConfig(t, output)

	if err := Run(context.Background(), cfg, assets); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	svcs := assets.Services()
	if len(svcs) != 1 || svcs[0].Port != 9999 || svcs[0].ServiceName != "" {
		t.Fatalf("unexpected services: %+v", svcs)
	}
}
