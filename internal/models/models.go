package models

import "time"

// Domain represents a discovered domain or subdomain.
type Domain struct {
	Name      string    `json:"name"`
	FirstSeen time.Time `json:"first_seen,omitempty"`
}

// Host represents an IP address and its associated metadata.
type Host struct {
	IP                string    `json:"ip"`
	AssociatedDomains []string  `json:"associated_domains,omitempty"`
	FirstSeen         time.Time `json:"first_seen,omitempty"`
}

// Service represents an exposed network port and service.
type Service struct {
	Host        string    `json:"host"`
	Port        int       `json:"port"`
	Protocol    string    `json:"protocol"`
	ServiceName string    `json:"service_name,omitempty"`
	FirstSeen   time.Time `json:"first_seen,omitempty"`
}

// WebEndpoint represents a discovered web URL endpoint.
type WebEndpoint struct {
	URL        string    `json:"url"`
	Host       string    `json:"host,omitempty"`
	StatusCode int       `json:"status_code,omitempty"`
	FirstSeen  time.Time `json:"first_seen,omitempty"`
}

// JSFile represents a discovered JavaScript file asset.
type JSFile struct {
	URL       string    `json:"url"`
	Host      string    `json:"host,omitempty"`
	FirstSeen time.Time `json:"first_seen,omitempty"`
}

// Parameter represents an input parameter discovered on an endpoint.
type Parameter struct {
	URL       string    `json:"url"`
	Name      string    `json:"name"`
	Location  string    `json:"location"`
	FirstSeen time.Time `json:"first_seen,omitempty"`
}

// Finding represents a vulnerability or static analysis finding.
type Finding struct {
	Target     string    `json:"target"`
	TemplateID string    `json:"template_id"`
	Protocol   string    `json:"protocol"`
	Location   string    `json:"location"`
	Severity   string    `json:"severity"`
	Name       string    `json:"name,omitempty"`
	DetectedAt time.Time `json:"detected_at,omitempty"`
}

// IntelligenceSignal represents a passive signal extracted from assets.
type IntelligenceSignal struct {
	Type       string    `json:"type"`
	Target     string    `json:"target"`
	Evidence   []string  `json:"evidence,omitempty"`
	Source     string    `json:"source"`
	Confidence float64   `json:"confidence"`
	DetectedAt time.Time `json:"detected_at,omitempty"`
}

// Correlation represents an undirected cluster of related assets and findings.
type Correlation struct {
	GroupID  string   `json:"group_id"`
	Assets   []string `json:"assets,omitempty"`
	Findings []string `json:"findings,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
}

// ResearchTarget represents a ranked asset target for manual investigation.
type ResearchTarget struct {
	ID       string               `json:"id"`
	Target   string               `json:"target"`
	Signals  []IntelligenceSignal `json:"signals,omitempty"`
	Evidence []string             `json:"evidence,omitempty"`
	Priority int                  `json:"priority"`
	Reasons  []string             `json:"reasons,omitempty"`
}
