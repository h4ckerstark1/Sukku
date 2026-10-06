package priority

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/url"
	"sort"
	"strings"

	"sukku/internal/models"
	"sukku/internal/normalize"
)

// Input encapsulates all reconnaissance inventory and intelligence data.
type Input struct {
	Domains      []models.Domain
	Hosts        []models.Host
	Services     []models.Service
	Endpoints    []models.WebEndpoint
	JSFiles      []models.JSFile
	Parameters   []models.Parameter
	Findings     []models.Finding
	Signals      []models.IntelligenceSignal
	Correlations []models.Correlation
}

type targetAccumulator struct {
	canonicalID string
	target      string
	endpoints   []models.WebEndpoint
	jsFiles     []models.JSFile
	parameters  []models.Parameter
	findings    []models.Finding
	signals     []models.IntelligenceSignal
	services    []models.Service
	corrAssets  map[string]struct{}
}

// Prioritize calculates passive research priority scores for discovered assets.
func Prioritize(input Input) []models.ResearchTarget {
	accumulators := make(map[string]*targetAccumulator)

	getOrCreate := func(canonicalID, rawTarget string) *targetAccumulator {
		if canonicalID == "" {
			return nil
		}
		if _, exists := accumulators[canonicalID]; !exists {
			accumulators[canonicalID] = &targetAccumulator{
				canonicalID: canonicalID,
				target:      rawTarget,
				corrAssets:  make(map[string]struct{}),
			}
		}
		return accumulators[canonicalID]
	}

	// 1. Ingest Endpoints
	for _, ep := range input.Endpoints {
		normURL, err := normalize.URL(ep.URL)
		if err != nil || normURL == "" {
			continue
		}
		id := "endpoint:" + normURL
		acc := getOrCreate(id, normURL)
		if acc != nil {
			acc.endpoints = append(acc.endpoints, ep)
		}
	}

	// 2. Ingest JSFiles
	for _, j := range input.JSFiles {
		normURL, err := normalize.URL(j.URL)
		if err != nil || normURL == "" {
			continue
		}
		id := "js:" + normURL
		acc := getOrCreate(id, normURL)
		if acc != nil {
			acc.jsFiles = append(acc.jsFiles, j)
		}
	}

	// 3. Ingest Parameters
	for _, p := range input.Parameters {
		normURL, err := normalize.URL(p.URL)
		if err != nil || normURL == "" {
			continue
		}
		name := strings.TrimSpace(p.Name)
		if name == "" {
			continue
		}
		loc := strings.ToLower(strings.TrimSpace(p.Location))
		if loc == "" {
			loc = "query"
		}
		epID := "endpoint:" + normURL
		if acc, exists := accumulators[epID]; exists {
			acc.parameters = append(acc.parameters, p)
			continue
		}
		paramID := fmt.Sprintf("parameter:%s:%s:%s", loc, normURL, name)
		acc := getOrCreate(paramID, normURL)
		if acc != nil {
			acc.parameters = append(acc.parameters, p)
		}
	}

	// 4. Ingest Findings
	for _, f := range input.Findings {
		normTarget, targetHost, targetPath := parseTargetHostPath(f.Target)
		if normTarget == "" {
			continue
		}

		matched := false
		for id, acc := range accumulators {
			if !strings.HasPrefix(id, "endpoint:") {
				continue
			}
			_, accHost, accPath := parseTargetHostPath(acc.target)
			if accHost != "" && accHost == targetHost && accPath == targetPath {
				acc.findings = append(acc.findings, f)
				matched = true
			}
		}
		if !matched {
			loc := normalizeFindingLocation(f.Location)
			proto := strings.ToLower(strings.TrimSpace(f.Protocol))
			if proto == "" {
				proto = "unknown"
			}
			fid := fmt.Sprintf("finding:%s:%s:%s:%s", normTarget, strings.TrimSpace(f.TemplateID), proto, loc)
			acc := getOrCreate(fid, normTarget)
			if acc != nil {
				acc.findings = append(acc.findings, f)
			}
		}
	}

	// 5. Ingest Signals
	for _, sig := range input.Signals {
		normTarget, sigHost, _ := parseTargetHostPath(sig.Target)
		if normTarget == "" {
			continue
		}

		matched := false
		for _, ev := range sig.Evidence {
			evTrim := strings.TrimSpace(ev)
			if strings.HasPrefix(evTrim, "/") {
				cleanEV := cleanPath(evTrim)
				for id, acc := range accumulators {
					if !strings.HasPrefix(id, "endpoint:") {
						continue
					}
					_, accHost, accPath := parseTargetHostPath(acc.target)
					if accHost != "" && accHost == sigHost && accPath == cleanEV {
						acc.signals = append(acc.signals, sig)
						matched = true
					}
				}
			}
		}

		jsID := "js:" + normTarget
		if acc, exists := accumulators[jsID]; exists {
			acc.signals = append(acc.signals, sig)
			matched = true
		}

		if !matched {
			ev := ""
			if len(sig.Evidence) > 0 {
				ev = strings.TrimSpace(sig.Evidence[0])
			}
			src := strings.TrimSpace(sig.Source)
			if src == "" {
				src = "js"
			}
			sigID := fmt.Sprintf("signal:%s:%s:%s:%s", strings.TrimSpace(sig.Type), normTarget, ev, src)
			acc := getOrCreate(sigID, normTarget)
			if acc != nil {
				acc.signals = append(acc.signals, sig)
			}
		}
	}

	// 6. Ingest Services
	for _, s := range input.Services {
		sHost := canonicalHostString(s.Host)
		if sHost == "" || s.Port < 1 || s.Port > 65535 {
			continue
		}
		proto := strings.ToLower(strings.TrimSpace(s.Protocol))
		if proto == "" {
			proto = "tcp"
		}

		matched := false
		for id, acc := range accumulators {
			if strings.HasPrefix(id, "endpoint:") || strings.HasPrefix(id, "js:") {
				_, accHost, _ := parseTargetHostPath(acc.target)
				if accHost == sHost {
					acc.services = append(acc.services, s)
					matched = true
				}
			}
		}
		if !matched {
			sid := fmt.Sprintf("service:%s:%d/%s", sHost, s.Port, proto)
			acc := getOrCreate(sid, sHost)
			if acc != nil {
				acc.services = append(acc.services, s)
			}
		}
	}

	// 7. Associate Correlation Groups & Propagate Evidence
	for _, corr := range input.Correlations {
		for _, a := range corr.Assets {
			if acc, exists := accumulators[a]; exists {
				for _, other := range corr.Assets {
					if other != a {
						acc.corrAssets[other] = struct{}{}
					}
				}
				for _, other := range corr.Assets {
					if strings.HasPrefix(other, "service:") {
						if otherAcc, oExists := accumulators[other]; oExists {
							acc.services = append(acc.services, otherAcc.services...)
						}
					}
					if strings.HasPrefix(other, "js:") {
						if otherAcc, oExists := accumulators[other]; oExists {
							acc.jsFiles = append(acc.jsFiles, otherAcc.jsFiles...)
							acc.signals = append(acc.signals, otherAcc.signals...)
						}
					}
				}
				for _, fID := range corr.Findings {
					if fAcc, fExists := accumulators[fID]; fExists {
						acc.findings = append(acc.findings, fAcc.findings...)
					}
				}
			}
		}
	}

	// Ingest standalone Hosts if not registered
	for _, h := range input.Hosts {
		if nip, err := normalize.IP(h.IP); err == nil && nip != "" {
			getOrCreate("host:"+nip, nip)
		}
	}

	// 8. Calculate Priority Scores
	var results []models.ResearchTarget
	keys := make([]string, 0, len(accumulators))
	for k := range accumulators {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		acc := accumulators[k]
		score, reasons, evidence := computePriority(acc)
		id := "target-" + hashID(acc.canonicalID)[:16]

		results = append(results, models.ResearchTarget{
			ID:       id,
			Target:   acc.target,
			Signals:  dedupeSignals(acc.signals),
			Evidence: dedupeSortedStrings(evidence),
			Priority: score,
			Reasons:  dedupeSortedStrings(reasons),
		})
	}

	// Final Sort: Priority desc, Target asc, ID asc
	sort.Slice(results, func(i, j int) bool {
		if results[i].Priority != results[j].Priority {
			return results[i].Priority > results[j].Priority
		}
		if results[i].Target != results[j].Target {
			return results[i].Target < results[j].Target
		}
		return results[i].ID < results[j].ID
	})

	return results
}

func computePriority(acc *targetAccumulator) (int, []string, []string) {
	var total int
	var reasons []string
	var evidence []string

	// 1. Findings (Max +45)
	if len(acc.findings) > 0 {
		fScore, fReasons, fEv := evaluateFindings(acc.findings)
		total += fScore
		reasons = append(reasons, fReasons...)
		evidence = append(evidence, fEv...)
	}

	// 2. Signals (Max +35)
	if len(acc.signals) > 0 {
		sScore, sReasons, sEv := evaluateSignals(acc.signals)
		total += sScore
		reasons = append(reasons, sReasons...)
		evidence = append(evidence, sEv...)
	}

	// 3. Parameters (Max +15)
	if len(acc.parameters) > 0 {
		pScore, pReasons, pEv := evaluateParameters(acc.parameters)
		total += pScore
		reasons = append(reasons, pReasons...)
		evidence = append(evidence, pEv...)
	}

	// 4. Endpoint Characteristics (Max +20)
	if len(acc.endpoints) > 0 {
		epScore, epReasons, epEv := evaluateEndpoints(acc.endpoints)
		total += epScore
		reasons = append(reasons, epReasons...)
		evidence = append(evidence, epEv...)
	}

	// 5. Service Exposure (Max +10)
	if len(acc.services) > 0 {
		svcScore, svcReasons, svcEv := evaluateServices(acc.services)
		total += svcScore
		reasons = append(reasons, svcReasons...)
		evidence = append(evidence, svcEv...)
	}

	// 6. Correlation Evidence (Max +15)
	if len(acc.corrAssets) > 0 {
		corrScore := 3 + (len(acc.corrAssets)-1)*2
		if corrScore > 15 {
			corrScore = 15
		}
		total += corrScore
		reasons = append(reasons, fmt.Sprintf("correlated assets: %d", len(acc.corrAssets)))
		evidence = append(evidence, fmt.Sprintf("correlation_count:%d", len(acc.corrAssets)))
	}

	// 7. Asset Breadth (Max +8)
	bScore, bReasons, bEv := evaluateBreadth(acc)
	if bScore > 0 {
		total += bScore
		reasons = append(reasons, bReasons...)
		evidence = append(evidence, bEv...)
	}

	if total > 100 {
		total = 100
	}
	if total < 0 {
		total = 0
	}

	return total, reasons, evidence
}

func evaluateFindings(findings []models.Finding) (int, []string, []string) {
	weights := map[string]int{
		"critical": 35,
		"high":     25,
		"medium":   15,
		"low":      8,
		"info":     3,
		"unknown":  1,
	}

	maxBase := 0
	topSev := ""
	distinct := make(map[string]struct{})
	var ev []string

	for _, f := range findings {
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		w, ok := weights[sev]
		if !ok {
			w = weights["unknown"]
			sev = "unknown"
		}
		if w > maxBase {
			maxBase = w
			topSev = sev
		}
		normTarget, _, _ := parseTargetHostPath(f.Target)
		loc := normalizeFindingLocation(f.Location)
		proto := strings.ToLower(strings.TrimSpace(f.Protocol))
		if proto == "" {
			proto = "unknown"
		}
		key := fmt.Sprintf("%s::%s::%s::%s", normTarget, strings.TrimSpace(f.TemplateID), proto, loc)
		distinct[key] = struct{}{}
		ev = append(ev, fmt.Sprintf("finding:%s:%s", f.TemplateID, sev))
	}

	score := maxBase + (len(distinct)-1)*2
	if score > 45 {
		score = 45
	}
	reason := fmt.Sprintf("existing finding severity: %s", topSev)
	return score, []string{reason}, ev
}

func evaluateSignals(signals []models.IntelligenceSignal) (int, []string, []string) {
	weights := map[string]int{
		"js_secret_pattern": 25,
		"js_absolute_url":   15,
		"js_api_path":       12,
		"js_graphql":        12,
		"js_parameter":      8,
	}

	maxVal := 0
	topType := ""
	distinctTypes := make(map[string]struct{})
	var ev []string

	for _, s := range signals {
		w, ok := weights[s.Type]
		if !ok {
			continue
		}
		mult := confidenceMultiplier(s.Confidence)
		val := int(math.Round(float64(w) * mult))
		if val > maxVal {
			maxVal = val
			topType = s.Type
		}
		distinctTypes[s.Type] = struct{}{}
		if len(s.Evidence) > 0 {
			ev = append(ev, fmt.Sprintf("signal:%s:%s", s.Type, s.Evidence[0]))
		}
	}

	score := maxVal + (len(distinctTypes)-1)*2
	if score > 35 {
		score = 35
	}
	var reasons []string
	if topType != "" {
		reasons = append(reasons, fmt.Sprintf("js signal: %s", topType))
	}
	return score, reasons, ev
}

func evaluateParameters(params []models.Parameter) (int, []string, []string) {
	distinct := make(map[string]struct{})
	var ev []string
	for _, p := range params {
		name := strings.TrimSpace(p.Name)
		if name != "" {
			distinct[name] = struct{}{}
			ev = append(ev, "parameter:"+name)
		}
	}

	score := 5 + (len(distinct) - 1)
	if score > 15 {
		score = 15
	}
	reason := fmt.Sprintf("parameters discovered: %d", len(distinct))
	return score, []string{reason}, ev
}

func evaluateEndpoints(endpoints []models.WebEndpoint) (int, []string, []string) {
	score := 5
	var reasons []string
	var ev []string

	reasons = append(reasons, "endpoint exists")
	hasGraphQL := false
	hasAPI := false
	hasAuth := false

	for _, ep := range endpoints {
		u, err := url.Parse(ep.URL)
		if err != nil {
			continue
		}
		path := u.Path
		if !hasGraphQL && isExplicitGraphQLPath(path) {
			hasGraphQL = true
			score += 8
			reasons = append(reasons, "graphql endpoint")
			ev = append(ev, "endpoint_characteristic:graphql")
		}
		if !hasAPI && isAPIPath(path) {
			hasAPI = true
			score += 5
			reasons = append(reasons, "api-like endpoint")
			ev = append(ev, "endpoint_characteristic:api")
		}
		if !hasAuth && isSegmentAuthPath(path) {
			hasAuth = true
			score += 5
			reasons = append(reasons, "authentication-related endpoint")
			ev = append(ev, "endpoint_characteristic:auth")
		}
	}

	if score > 20 {
		score = 20
	}
	return score, reasons, ev
}

func evaluateServices(services []models.Service) (int, []string, []string) {
	score := 5
	distinctServices := make(map[string]struct{})
	var reasons []string
	var ev []string

	for _, s := range services {
		proto := strings.ToLower(strings.TrimSpace(s.Protocol))
		svcName := strings.ToLower(strings.TrimSpace(s.ServiceName))
		key := fmt.Sprintf("%d/%s", s.Port, proto)
		if _, seen := distinctServices[key]; seen {
			continue
		}
		distinctServices[key] = struct{}{}

		switch {
		case strings.Contains(svcName, "http") || s.Port == 80 || s.Port == 443 || s.Port == 8080 || s.Port == 8443:
			score += 2
			reasons = append(reasons, "exposed service: http")
		case strings.Contains(svcName, "ssh") || s.Port == 22:
			score += 2
			reasons = append(reasons, "exposed service: ssh")
		case strings.Contains(svcName, "ftp") || s.Port == 21:
			score += 3
			reasons = append(reasons, "exposed service: ftp")
		default:
			score += 1
			reasons = append(reasons, fmt.Sprintf("exposed service: %s", proto))
		}
		ev = append(ev, fmt.Sprintf("service:%d/%s", s.Port, proto))
	}

	if score > 10 {
		score = 10
	}
	return score, reasons, ev
}

func evaluateBreadth(acc *targetAccumulator) (int, []string, []string) {
	score := 0
	var reasons []string
	var ev []string

	if len(acc.jsFiles) > 0 {
		score += 3
		reasons = append(reasons, "associated with js")
		ev = append(ev, "breadth:js")
	}

	distinctEndpoints := make(map[string]struct{})
	for _, ep := range acc.endpoints {
		if norm, err := normalize.URL(ep.URL); err == nil {
			distinctEndpoints[norm] = struct{}{}
		}
	}
	if len(distinctEndpoints) > 1 {
		score += len(distinctEndpoints) - 1
		reasons = append(reasons, fmt.Sprintf("multiple endpoints: %d", len(distinctEndpoints)))
		ev = append(ev, fmt.Sprintf("breadth:endpoints:%d", len(distinctEndpoints)))
	}

	if score > 8 {
		score = 8
	}
	return score, reasons, ev
}

func confidenceMultiplier(conf float64) float64 {
	switch {
	case conf >= 0.95:
		return 1.00
	case conf >= 0.90:
		return 0.90
	case conf >= 0.80:
		return 0.80
	case conf >= 0.70:
		return 0.70
	default:
		return 0.60
	}
}

func isExplicitGraphQLPath(p string) bool {
	clean := cleanPath(p)
	switch clean {
	case "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql", "/api/v1/graphql", "/api/v2/graphql":
		return true
	}
	return false
}

func isAPIPath(p string) bool {
	clean := cleanPath(p)
	return strings.HasPrefix(clean, "/api/") ||
		strings.HasPrefix(clean, "/api/v1/") ||
		strings.HasPrefix(clean, "/api/v2/") ||
		strings.HasPrefix(clean, "/v1/") ||
		strings.HasPrefix(clean, "/v2/")
}

func isSegmentAuthPath(p string) bool {
	clean := cleanPath(p)
	segments := strings.Split(strings.Trim(clean, "/"), "/")
	authTokens := map[string]bool{
		"login":    true,
		"signin":   true,
		"sign-up":  true,
		"signup":   true,
		"register": true,
		"auth":     true,
		"oauth":    true,
		"token":    true,
	}

	for _, seg := range segments {
		seg = strings.ToLower(strings.TrimSpace(seg))
		if authTokens[seg] {
			return true
		}
	}
	return false
}

func normalizeFindingLocation(loc string) string {
	trimmed := strings.TrimSpace(loc)
	if trimmed == "" {
		return ""
	}
	if norm, err := normalize.URL(trimmed); err == nil && norm != "" {
		return norm
	}
	return trimmed
}

func parseTargetHostPath(raw string) (string, string, string) {
	t := strings.TrimSpace(raw)
	if t == "" {
		return "", "", ""
	}
	if strings.HasPrefix(strings.ToLower(t), "http://") || strings.HasPrefix(strings.ToLower(t), "https://") {
		if norm, err := normalize.URL(t); err == nil {
			if u, err := url.Parse(norm); err == nil {
				return norm, u.Hostname(), cleanPath(u.Path)
			}
		}
	}
	if ip := net.ParseIP(t); ip != nil {
		if norm, err := normalize.IP(t); err == nil {
			return norm, norm, ""
		}
	}
	if norm, err := normalize.Domain(t); err == nil {
		return norm, norm, ""
	}
	return "", "", ""
}

func canonicalHostString(h string) string {
	trimmed := strings.TrimSpace(h)
	if nip, err := normalize.IP(trimmed); err == nil {
		return nip
	}
	if nd, err := normalize.Domain(trimmed); err == nil {
		return nd
	}
	return ""
}

func cleanPath(p string) string {
	p = strings.TrimSpace(p)
	if idx := strings.Index(p, "?"); idx != -1 {
		p = p[:idx]
	}
	p = strings.TrimRight(p, "/")
	if p == "" {
		return "/"
	}
	return p
}

func hashID(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func dedupeSignals(signals []models.IntelligenceSignal) []models.IntelligenceSignal {
	seen := make(map[string]models.IntelligenceSignal)
	for _, s := range signals {
		ev := ""
		if len(s.Evidence) > 0 {
			ev = s.Evidence[0]
		}
		key := fmt.Sprintf("%s:%s:%s", s.Type, s.Target, ev)
		seen[key] = s
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	res := make([]models.IntelligenceSignal, 0, len(keys))
	for _, k := range keys {
		res = append(res, seen[k])
	}
	return res
}

func dedupeSortedStrings(slice []string) []string {
	seen := make(map[string]struct{})
	var res []string
	for _, s := range slice {
		trimmed := strings.TrimSpace(s)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; !ok {
			seen[trimmed] = struct{}{}
			res = append(res, trimmed)
		}
	}
	sort.Strings(res)
	return res
}
