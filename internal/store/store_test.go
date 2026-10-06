package store

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"sukku/internal/models"
)

func TestStore_NewAssetStore(t *testing.T) {
	st := NewAssetStore()
	if st == nil {
		t.Fatal("expected non-nil AssetStore")
	}
	if len(st.Domains()) != 0 || len(st.Hosts()) != 0 || len(st.Services()) != 0 ||
		len(st.WebEndpoints()) != 0 || len(st.JSFiles()) != 0 || len(st.Parameters()) != 0 ||
		len(st.Findings()) != 0 || len(st.IntelligenceSignals()) != 0 || len(st.Correlations()) != 0 {
		t.Errorf("expected empty collections on initialized AssetStore")
	}
}

func TestStore_AddDomain(t *testing.T) {
	st := NewAssetStore()
	fixedTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Valid Domain & Preserved FirstSeen
	err := st.AddDomain(models.Domain{Name: "  EXAMPLE.COM. ", FirstSeen: fixedTime})
	if err != nil {
		t.Fatalf("unexpected error adding domain: %v", err)
	}
	doms := st.Domains()
	if len(doms) != 1 || doms[0].Name != "example.com" {
		t.Fatalf("domain not normalized correctly: %+v", doms)
	}
	if !doms[0].FirstSeen.Equal(fixedTime) {
		t.Errorf("supplied FirstSeen not preserved: got %v, want %v", doms[0].FirstSeen, fixedTime)
	}

	// Duplicate Domain deduplication
	err = st.AddDomain(models.Domain{Name: "example.com"})
	if err != nil || len(st.Domains()) != 1 {
		t.Errorf("duplicate domain created extra record or returned error: %v", err)
	}

	// Invalid Domain
	if err := st.AddDomain(models.Domain{Name: "invalid domain"}); !errors.Is(err, ErrInvalidDomain) {
		t.Errorf("expected ErrInvalidDomain, got: %v", err)
	}
}

func TestStore_AddHost(t *testing.T) {
	st := NewAssetStore()

	// IPv4
	err := st.AddHost(models.Host{IP: " 192.0.2.1 ", AssociatedDomains: []string{"b.com"}})
	if err != nil {
		t.Fatalf("unexpected error adding IPv4: %v", err)
	}
	hosts := st.Hosts()
	if len(hosts) != 1 || hosts[0].IP != "192.0.2.1" {
		t.Fatalf("host IPv4 not normalized: %+v", hosts)
	}
	if hosts[0].FirstSeen.IsZero() {
		t.Errorf("zero FirstSeen was not initialized")
	}

	// IPv6
	err = st.AddHost(models.Host{IP: "2001:0db8::1"})
	if err != nil || len(st.Hosts()) != 2 {
		t.Fatalf("unexpected error adding IPv6: %v", err)
	}

	// Duplicate Host & Merged AssociatedDomains
	err = st.AddHost(models.Host{IP: "192.0.2.1", AssociatedDomains: []string{"a.com", "b.com"}})
	if err != nil {
		t.Fatalf("unexpected error updating host: %v", err)
	}
	hosts = st.Hosts()
	var targetHost models.Host
	for _, h := range hosts {
		if h.IP == "192.0.2.1" {
			targetHost = h
			break
		}
	}
	expectedDomains := []string{"a.com", "b.com"}
	if !reflect.DeepEqual(targetHost.AssociatedDomains, expectedDomains) {
		t.Errorf("associated domains not merged/sorted: got %v, want %v", targetHost.AssociatedDomains, expectedDomains)
	}

	// Invalid Host IP
	if err := st.AddHost(models.Host{IP: "999.999.999.999"}); !errors.Is(err, ErrInvalidHost) {
		t.Errorf("expected ErrInvalidHost, got: %v", err)
	}
}

func TestStore_AddService(t *testing.T) {
	st := NewAssetStore()

	// Valid Service
	err := st.AddService(models.Service{Host: "EXAMPLE.COM", Port: 443, Protocol: "TCP", ServiceName: "https"})
	if err != nil {
		t.Fatalf("unexpected error adding service: %v", err)
	}
	svcs := st.Services()
	if len(svcs) != 1 || svcs[0].Host != "example.com" || svcs[0].Protocol != "tcp" {
		t.Fatalf("service host/protocol not normalized: %+v", svcs)
	}

	// Duplicate Service
	err = st.AddService(models.Service{Host: "example.com", Port: 443, Protocol: "tcp"})
	if err != nil || len(st.Services()) != 1 {
		t.Errorf("duplicate service not deduplicated: %v", err)
	}

	// Invalid Port
	if err := st.AddService(models.Service{Host: "example.com", Port: 0}); !errors.Is(err, ErrInvalidService) {
		t.Errorf("expected ErrInvalidService for port 0, got: %v", err)
	}
	if err := st.AddService(models.Service{Host: "example.com", Port: 70000}); !errors.Is(err, ErrInvalidService) {
		t.Errorf("expected ErrInvalidService for port 70000, got: %v", err)
	}

	// Invalid Host
	if err := st.AddService(models.Service{Host: "invalid host", Port: 80}); !errors.Is(err, ErrInvalidService) {
		t.Errorf("expected ErrInvalidService for invalid host, got: %v", err)
	}
}

func TestStore_AddWebEndpoint(t *testing.T) {
	st := NewAssetStore()

	// Valid Endpoint
	err := st.AddWebEndpoint(models.WebEndpoint{URL: "https://EXAMPLE.COM:443/api/v1#frag"})
	if err != nil {
		t.Fatalf("unexpected error adding endpoint: %v", err)
	}
	eps := st.WebEndpoints()
	if len(eps) != 1 || eps[0].URL != "https://example.com/api/v1" {
		t.Fatalf("endpoint URL not normalized: %+v", eps)
	}

	// Duplicate Endpoint
	err = st.AddWebEndpoint(models.WebEndpoint{URL: "https://example.com/api/v1"})
	if err != nil || len(st.WebEndpoints()) != 1 {
		t.Errorf("duplicate endpoint not deduplicated: %v", err)
	}

	// Invalid Endpoint
	if err := st.AddWebEndpoint(models.WebEndpoint{URL: "://invalid"}); !errors.Is(err, ErrInvalidEndpoint) {
		t.Errorf("expected ErrInvalidEndpoint, got: %v", err)
	}
}

func TestStore_AddJSFile(t *testing.T) {
	st := NewAssetStore()

	// Valid JSFile
	err := st.AddJSFile(models.JSFile{URL: "HTTPS://EXAMPLE.COM/static/app.js"})
	if err != nil {
		t.Fatalf("unexpected error adding JSFile: %v", err)
	}
	files := st.JSFiles()
	if len(files) != 1 || files[0].URL != "https://example.com/static/app.js" {
		t.Fatalf("JSFile URL not normalized: %+v", files)
	}

	// Duplicate JSFile
	err = st.AddJSFile(models.JSFile{URL: "https://example.com/static/app.js"})
	if err != nil || len(st.JSFiles()) != 1 {
		t.Errorf("duplicate JSFile not deduplicated: %v", err)
	}

	// Invalid JSFile
	if err := st.AddJSFile(models.JSFile{URL: ""}); !errors.Is(err, ErrInvalidJSFile) {
		t.Errorf("expected ErrInvalidJSFile, got: %v", err)
	}
}

func TestStore_AddParameter(t *testing.T) {
	st := NewAssetStore()

	// Valid Parameter
	err := st.AddParameter(models.Parameter{URL: "https://example.com/search", Name: " q ", Location: "QUERY"})
	if err != nil {
		t.Fatalf("unexpected error adding parameter: %v", err)
	}
	params := st.Parameters()
	if len(params) != 1 || params[0].Name != "q" || params[0].Location != "query" {
		t.Fatalf("parameter name/location not normalized: %+v", params)
	}

	// Duplicate Parameter
	err = st.AddParameter(models.Parameter{URL: "https://example.com/search", Name: "q", Location: "query"})
	if err != nil || len(st.Parameters()) != 1 {
		t.Errorf("duplicate parameter not deduplicated: %v", err)
	}

	// Invalid Parameter
	if err := st.AddParameter(models.Parameter{URL: "https://example.com/search", Name: ""}); !errors.Is(err, ErrInvalidParameter) {
		t.Errorf("expected ErrInvalidParameter for empty name, got: %v", err)
	}
	if err := st.AddParameter(models.Parameter{URL: "://invalid", Name: "q"}); !errors.Is(err, ErrInvalidParameter) {
		t.Errorf("expected ErrInvalidParameter for invalid URL, got: %v", err)
	}
}

func TestStore_AddFinding(t *testing.T) {
	st := NewAssetStore()

	// Valid Finding
	err := st.AddFinding(models.Finding{
		Target:     "https://EXAMPLE.COM/api",
		TemplateID: "cve-2026-0001",
		Protocol:   "HTTP",
		Location:   "https://EXAMPLE.COM/api#frag",
	})
	if err != nil {
		t.Fatalf("unexpected error adding finding: %v", err)
	}
	findings := st.Findings()
	if len(findings) != 1 || findings[0].Target != "https://example.com/api" || findings[0].Protocol != "http" || findings[0].Location != "https://example.com/api" {
		t.Fatalf("finding target/protocol/location not normalized: %+v", findings)
	}

	// Duplicate Finding
	err = st.AddFinding(models.Finding{
		Target:     "https://example.com/api",
		TemplateID: "cve-2026-0001",
		Protocol:   "http",
		Location:   "https://example.com/api",
	})
	if err != nil || len(st.Findings()) != 1 {
		t.Errorf("duplicate finding not deduplicated: %v", err)
	}

	// Invalid Finding
	if err := st.AddFinding(models.Finding{Target: "", TemplateID: "cve-1"}); !errors.Is(err, ErrInvalidFinding) {
		t.Errorf("expected ErrInvalidFinding for empty target, got: %v", err)
	}
	if err := st.AddFinding(models.Finding{Target: "example.com", TemplateID: ""}); !errors.Is(err, ErrInvalidFinding) {
		t.Errorf("expected ErrInvalidFinding for empty templateID, got: %v", err)
	}
}

func TestStore_AddIntelligenceSignal(t *testing.T) {
	st := NewAssetStore()

	// Valid Signal
	err := st.AddIntelligenceSignal(models.IntelligenceSignal{
		Type:     "js_secret_pattern",
		Target:   "https://example.com/app.js",
		Evidence: []string{"aws_key"},
	})
	if err != nil {
		t.Fatalf("unexpected error adding signal: %v", err)
	}
	sigs := st.IntelligenceSignals()
	if len(sigs) != 1 || sigs[0].Source != "js" {
		t.Fatalf("signal not recorded or default source not applied: %+v", sigs)
	}

	// Duplicate Signal
	err = st.AddIntelligenceSignal(models.IntelligenceSignal{
		Type:     "js_secret_pattern",
		Target:   "https://example.com/app.js",
		Evidence: []string{"aws_key"},
	})
	if err != nil || len(st.IntelligenceSignals()) != 1 {
		t.Errorf("duplicate signal not deduplicated: %v", err)
	}

	// Invalid Signal
	if err := st.AddIntelligenceSignal(models.IntelligenceSignal{Type: "", Target: "target"}); !errors.Is(err, ErrInvalidSignal) {
		t.Errorf("expected ErrInvalidSignal for empty type, got: %v", err)
	}
}

func TestStore_AddCorrelation(t *testing.T) {
	st := NewAssetStore()

	// Valid Correlation
	err := st.AddCorrelation(models.Correlation{GroupID: "group-1", Assets: []string{"a", "b"}})
	if err != nil {
		t.Fatalf("unexpected error adding correlation: %v", err)
	}
	corrs := st.Correlations()
	if len(corrs) != 1 || corrs[0].GroupID != "group-1" {
		t.Fatalf("correlation not stored: %+v", corrs)
	}

	// Duplicate Correlation GroupID
	err = st.AddCorrelation(models.Correlation{GroupID: "group-1", Assets: []string{"c"}})
	if err != nil || len(st.Correlations()) != 1 {
		t.Errorf("duplicate correlation group not deduplicated: %v", err)
	}

	// Invalid Correlation
	if err := st.AddCorrelation(models.Correlation{GroupID: "   "}); !errors.Is(err, ErrInvalidCorr) {
		t.Errorf("expected ErrInvalidCorr for empty GroupID, got: %v", err)
	}
}

func TestStore_DeterministicGetters(t *testing.T) {
	st := NewAssetStore()

	_ = st.AddDomain(models.Domain{Name: "zeta.com"})
	_ = st.AddDomain(models.Domain{Name: "alpha.com"})
	_ = st.AddDomain(models.Domain{Name: "beta.com"})

	first := st.Domains()
	second := st.Domains()

	if !reflect.DeepEqual(first, second) {
		t.Fatalf("repeated getter calls not deterministic across invocations")
	}

	if first[0].Name != "alpha.com" || first[1].Name != "beta.com" || first[2].Name != "zeta.com" {
		t.Errorf("getter results not sorted alphabetically: %+v", first)
	}
}
