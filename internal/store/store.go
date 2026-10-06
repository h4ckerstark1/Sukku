package store

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"sukku/internal/models"
	"sukku/internal/normalize"
)

var (
	ErrInvalidDomain    = errors.New("invalid or empty domain name")
	ErrInvalidHost      = errors.New("invalid or empty host ip")
	ErrInvalidService   = errors.New("invalid service host or port")
	ErrInvalidEndpoint  = errors.New("invalid or empty endpoint url")
	ErrInvalidJSFile    = errors.New("invalid or empty js file url")
	ErrInvalidParameter = errors.New("invalid parameter url or name")
	ErrInvalidFinding   = errors.New("invalid finding target or template id")
	ErrInvalidSignal    = errors.New("invalid signal type or target")
	ErrInvalidCorr      = errors.New("invalid correlation group id")
)

// AssetStore provides in-memory deduplication, storage, and retrieval of reconnaissance entities.
type AssetStore struct {
	domains    map[string]models.Domain
	hosts      map[string]models.Host
	services   map[string]models.Service
	endpoints  map[string]models.WebEndpoint
	jsFiles    map[string]models.JSFile
	parameters map[string]models.Parameter
	findings   map[string]models.Finding
	signals    map[string]models.IntelligenceSignal
	corrs      map[string]models.Correlation
}

// NewAssetStore initializes an empty in-memory AssetStore.
func NewAssetStore() *AssetStore {
	return &AssetStore{
		domains:    make(map[string]models.Domain),
		hosts:      make(map[string]models.Host),
		services:   make(map[string]models.Service),
		endpoints:  make(map[string]models.WebEndpoint),
		jsFiles:    make(map[string]models.JSFile),
		parameters: make(map[string]models.Parameter),
		findings:   make(map[string]models.Finding),
		signals:    make(map[string]models.IntelligenceSignal),
		corrs:      make(map[string]models.Correlation),
	}
}

// AddDomain normalizes and stores a Domain.
func (s *AssetStore) AddDomain(d models.Domain) error {
	norm, err := normalize.Domain(d.Name)
	if err != nil || norm == "" {
		return ErrInvalidDomain
	}
	d.Name = norm
	if _, exists := s.domains[norm]; !exists {
		if d.FirstSeen.IsZero() {
			d.FirstSeen = time.Now().UTC()
		}
		s.domains[norm] = d
	}
	return nil
}

// AddHost normalizes and stores a Host IP.
func (s *AssetStore) AddHost(h models.Host) error {
	norm, err := normalize.IP(h.IP)
	if err != nil || norm == "" {
		return ErrInvalidHost
	}
	h.IP = norm
	if existing, exists := s.hosts[norm]; exists {
		domMap := make(map[string]struct{})
		for _, dom := range existing.AssociatedDomains {
			domMap[dom] = struct{}{}
		}
		for _, dom := range h.AssociatedDomains {
			if ndom, err := normalize.Domain(dom); err == nil && ndom != "" {
				domMap[ndom] = struct{}{}
			}
		}
		var merged []string
		for dom := range domMap {
			merged = append(merged, dom)
		}
		sort.Strings(merged)
		existing.AssociatedDomains = merged
		s.hosts[norm] = existing
	} else {
		if h.FirstSeen.IsZero() {
			h.FirstSeen = time.Now().UTC()
		}
		var cleanDomains []string
		for _, dom := range h.AssociatedDomains {
			if ndom, err := normalize.Domain(dom); err == nil && ndom != "" {
				cleanDomains = append(cleanDomains, ndom)
			}
		}
		sort.Strings(cleanDomains)
		h.AssociatedDomains = cleanDomains
		s.hosts[norm] = h
	}
	return nil
}

// AddService normalizes and stores an exposed network Service.
func (s *AssetStore) AddService(svc models.Service) error {
	host := strings.TrimSpace(svc.Host)
	if nip, err := normalize.IP(host); err == nil {
		host = nip
	} else if ndom, err := normalize.Domain(host); err == nil {
		host = ndom
	} else {
		return ErrInvalidService
	}

	if svc.Port < 1 || svc.Port > 65535 {
		return ErrInvalidService
	}

	proto := strings.ToLower(strings.TrimSpace(svc.Protocol))
	if proto == "" {
		proto = "tcp"
	}

	key := fmt.Sprintf("%s:%d/%s", host, svc.Port, proto)
	if _, exists := s.services[key]; !exists {
		svc.Host = host
		svc.Protocol = proto
		if svc.FirstSeen.IsZero() {
			svc.FirstSeen = time.Now().UTC()
		}
		s.services[key] = svc
	}
	return nil
}

// AddWebEndpoint normalizes and stores a WebEndpoint.
func (s *AssetStore) AddWebEndpoint(ep models.WebEndpoint) error {
	norm, err := normalize.URL(ep.URL)
	if err != nil || norm == "" {
		return ErrInvalidEndpoint
	}
	ep.URL = norm
	if _, exists := s.endpoints[norm]; !exists {
		if ep.FirstSeen.IsZero() {
			ep.FirstSeen = time.Now().UTC()
		}
		s.endpoints[norm] = ep
	}
	return nil
}

// AddJSFile normalizes and stores a JSFile asset.
func (s *AssetStore) AddJSFile(j models.JSFile) error {
	norm, err := normalize.URL(j.URL)
	if err != nil || norm == "" {
		return ErrInvalidJSFile
	}
	j.URL = norm
	if _, exists := s.jsFiles[norm]; !exists {
		if j.FirstSeen.IsZero() {
			j.FirstSeen = time.Now().UTC()
		}
		s.jsFiles[norm] = j
	}
	return nil
}

// AddParameter stores a parameter associated with a normalized URL.
func (s *AssetStore) AddParameter(p models.Parameter) error {
	norm, err := normalize.URL(p.URL)
	if err != nil || norm == "" {
		return ErrInvalidParameter
	}
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return ErrInvalidParameter
	}
	loc := strings.ToLower(strings.TrimSpace(p.Location))
	if loc == "" {
		loc = "query"
	}

	key := fmt.Sprintf("%s:%s:%s", loc, norm, name)
	if _, exists := s.parameters[key]; !exists {
		p.URL = norm
		p.Name = name
		p.Location = loc
		if p.FirstSeen.IsZero() {
			p.FirstSeen = time.Now().UTC()
		}
		s.parameters[key] = p
	}
	return nil
}

// AddFinding stores a vulnerability finding.
func (s *AssetStore) AddFinding(f models.Finding) error {
	target := strings.TrimSpace(f.Target)
	if norm, err := normalize.URL(target); err == nil && norm != "" {
		target = norm
	} else if nip, err := normalize.IP(target); err == nil && nip != "" {
		target = nip
	} else if ndom, err := normalize.Domain(target); err == nil && ndom != "" {
		target = ndom
	}
	if target == "" || strings.TrimSpace(f.TemplateID) == "" {
		return ErrInvalidFinding
	}

	proto := strings.ToLower(strings.TrimSpace(f.Protocol))
	if proto == "" {
		proto = "unknown"
	}
	loc := strings.TrimSpace(f.Location)
	if nloc, err := normalize.URL(loc); err == nil && nloc != "" {
		loc = nloc
	}

	key := fmt.Sprintf("%s::%s::%s::%s", target, strings.TrimSpace(f.TemplateID), proto, loc)
	if _, exists := s.findings[key]; !exists {
		f.Target = target
		f.Protocol = proto
		f.Location = loc
		if f.DetectedAt.IsZero() {
			f.DetectedAt = time.Now().UTC()
		}
		s.findings[key] = f
	}
	return nil
}

// AddIntelligenceSignal stores an intelligence signal.
func (s *AssetStore) AddIntelligenceSignal(sig models.IntelligenceSignal) error {
	sigType := strings.TrimSpace(sig.Type)
	target := strings.TrimSpace(sig.Target)
	if sigType == "" || target == "" {
		return ErrInvalidSignal
	}

	ev := ""
	if len(sig.Evidence) > 0 {
		ev = strings.TrimSpace(sig.Evidence[0])
	}
	src := strings.TrimSpace(sig.Source)
	if src == "" {
		src = "js"
	}

	key := fmt.Sprintf("%s::%s::%s::%s", sigType, target, ev, src)
	if _, exists := s.signals[key]; !exists {
		sig.Type = sigType
		sig.Target = target
		sig.Source = src
		if sig.DetectedAt.IsZero() {
			sig.DetectedAt = time.Now().UTC()
		}
		s.signals[key] = sig
	}
	return nil
}

// AddCorrelation stores a correlation cluster.
func (s *AssetStore) AddCorrelation(c models.Correlation) error {
	gid := strings.TrimSpace(c.GroupID)
	if gid == "" {
		return ErrInvalidCorr
	}
	if _, exists := s.corrs[gid]; !exists {
		c.GroupID = gid
		s.corrs[gid] = c
	}
	return nil
}

// Domains returns all stored domains in deterministic sorted order.
func (s *AssetStore) Domains() []models.Domain {
	res := make([]models.Domain, 0, len(s.domains))
	keys := make([]string, 0, len(s.domains))
	for k := range s.domains {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		res = append(res, s.domains[k])
	}
	return res
}

// Hosts returns all stored hosts in deterministic sorted order.
func (s *AssetStore) Hosts() []models.Host {
	res := make([]models.Host, 0, len(s.hosts))
	keys := make([]string, 0, len(s.hosts))
	for k := range s.hosts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		res = append(res, s.hosts[k])
	}
	return res
}

// Services returns all stored services in deterministic sorted order.
func (s *AssetStore) Services() []models.Service {
	res := make([]models.Service, 0, len(s.services))
	keys := make([]string, 0, len(s.services))
	for k := range s.services {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		res = append(res, s.services[k])
	}
	return res
}

// WebEndpoints returns all stored web endpoints in deterministic sorted order.
func (s *AssetStore) WebEndpoints() []models.WebEndpoint {
	res := make([]models.WebEndpoint, 0, len(s.endpoints))
	keys := make([]string, 0, len(s.endpoints))
	for k := range s.endpoints {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		res = append(res, s.endpoints[k])
	}
	return res
}

// JSFiles returns all stored JS files in deterministic sorted order.
func (s *AssetStore) JSFiles() []models.JSFile {
	res := make([]models.JSFile, 0, len(s.jsFiles))
	keys := make([]string, 0, len(s.jsFiles))
	for k := range s.jsFiles {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		res = append(res, s.jsFiles[k])
	}
	return res
}

// Parameters returns all stored parameters in deterministic sorted order.
func (s *AssetStore) Parameters() []models.Parameter {
	res := make([]models.Parameter, 0, len(s.parameters))
	keys := make([]string, 0, len(s.parameters))
	for k := range s.parameters {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		res = append(res, s.parameters[k])
	}
	return res
}

// Findings returns all stored findings in deterministic sorted order.
func (s *AssetStore) Findings() []models.Finding {
	res := make([]models.Finding, 0, len(s.findings))
	keys := make([]string, 0, len(s.findings))
	for k := range s.findings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		res = append(res, s.findings[k])
	}
	return res
}

// IntelligenceSignals returns all stored signals in deterministic sorted order.
func (s *AssetStore) IntelligenceSignals() []models.IntelligenceSignal {
	res := make([]models.IntelligenceSignal, 0, len(s.signals))
	keys := make([]string, 0, len(s.signals))
	for k := range s.signals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		res = append(res, s.signals[k])
	}
	return res
}

// Correlations returns all stored correlations in deterministic sorted order.
func (s *AssetStore) Correlations() []models.Correlation {
	res := make([]models.Correlation, 0, len(s.corrs))
	keys := make([]string, 0, len(s.corrs))
	for k := range s.corrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		res = append(res, s.corrs[k])
	}
	return res
}
