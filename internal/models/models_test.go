package models

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestModels_Instantiation(t *testing.T) {
	now := time.Now().UTC()

	d := Domain{Name: "example.com", FirstSeen: now}
	if d.Name != "example.com" || d.FirstSeen != now {
		t.Errorf("Domain instantiation failed: %+v", d)
	}

	h := Host{IP: "192.0.2.1", AssociatedDomains: []string{"example.com"}, FirstSeen: now}
	if h.IP != "192.0.2.1" || len(h.AssociatedDomains) != 1 {
		t.Errorf("Host instantiation failed: %+v", h)
	}

	s := Service{Host: "192.0.2.1", Port: 443, Protocol: "tcp", ServiceName: "https", FirstSeen: now}
	if s.Host != "192.0.2.1" || s.Port != 443 || s.Protocol != "tcp" || s.ServiceName != "https" {
		t.Errorf("Service instantiation failed: %+v", s)
	}

	ep := WebEndpoint{URL: "https://example.com/api", Host: "example.com", StatusCode: 200, FirstSeen: now}
	if ep.URL != "https://example.com/api" || ep.Host != "example.com" || ep.StatusCode != 200 {
		t.Errorf("WebEndpoint instantiation failed: %+v", ep)
	}

	js := JSFile{URL: "https://example.com/app.js", Host: "example.com", FirstSeen: now}
	if js.URL != "https://example.com/app.js" || js.Host != "example.com" {
		t.Errorf("JSFile instantiation failed: %+v", js)
	}

	p := Parameter{URL: "https://example.com/api", Name: "id", Location: "query", FirstSeen: now}
	if p.URL != "https://example.com/api" || p.Name != "id" || p.Location != "query" {
		t.Errorf("Parameter instantiation failed: %+v", p)
	}

	f := Finding{Target: "https://example.com/api", TemplateID: "cve-1", Protocol: "http", Location: "/api", Severity: "high", DetectedAt: now}
	if f.Target != "https://example.com/api" || f.Severity != "high" || f.Protocol != "http" {
		t.Errorf("Finding instantiation failed: %+v", f)
	}

	sig := IntelligenceSignal{Type: "js_api_path", Target: "https://example.com/app.js", Evidence: []string{"/api"}, Source: "js", Confidence: 0.95, DetectedAt: now}
	if sig.Type != "js_api_path" || sig.Confidence != 0.95 {
		t.Errorf("IntelligenceSignal instantiation failed: %+v", sig)
	}

	c := Correlation{GroupID: "corr-1", Assets: []string{"endpoint:1"}, Findings: []string{"finding:1"}, Evidence: []string{"ev1"}}
	if c.GroupID != "corr-1" || len(c.Assets) != 1 {
		t.Errorf("Correlation instantiation failed: %+v", c)
	}

	rt := ResearchTarget{ID: "target-1", Target: "https://example.com/api", Priority: 75, Reasons: []string{"high severity"}}
	if rt.ID != "target-1" || rt.Priority != 75 {
		t.Errorf("ResearchTarget instantiation failed: %+v", rt)
	}
}

func TestModels_JSONRoundtrip(t *testing.T) {
	rtOrig := ResearchTarget{
		ID:       "target-100",
		Target:   "https://example.com/api/users",
		Priority: 45,
		Reasons:  []string{"api-like endpoint", "parameters discovered: 1"},
		Evidence: []string{"parameter:userId"},
		Signals: []IntelligenceSignal{
			{
				Type:       "js_api_path",
				Target:     "https://example.com/app.js",
				Evidence:   []string{"/api/users"},
				Source:     "js",
				Confidence: 0.90,
			},
		},
	}

	data, err := json.Marshal(rtOrig)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var rtParsed ResearchTarget
	if err := json.Unmarshal(data, &rtParsed); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if rtParsed.ID != rtOrig.ID || rtParsed.Target != rtOrig.Target || rtParsed.Priority != rtOrig.Priority {
		t.Errorf("JSON roundtrip lost core fields: got %+v, want %+v", rtParsed, rtOrig)
	}
	if len(rtParsed.Signals) != 1 || rtParsed.Signals[0].Type != "js_api_path" {
		t.Errorf("JSON roundtrip lost nested signal fields")
	}
}

func TestModels_OmitEmptyBehavior(t *testing.T) {
	c := Correlation{
		GroupID: "corr-empty-slices",
	}

	data, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	jsonStr := string(data)
	if strings.Contains(jsonStr, "assets") || strings.Contains(jsonStr, "findings") || strings.Contains(jsonStr, "evidence") {
		t.Errorf("omitempty not respected on Correlation nil slices: %s", jsonStr)
	}
}
