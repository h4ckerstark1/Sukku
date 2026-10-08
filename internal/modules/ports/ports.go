package ports

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"sukku/internal/models"
	"sukku/internal/store"
)

var (
	reportRe = regexp.MustCompile(`^Nmap scan report for (\S+)(?: \(([^)]+)\))?$`)
	portRe   = regexp.MustCompile(`^(\d+)/(tcp|udp|sctp)\s+(\S+)(?:\s+(\S+))?`)
	looseRe  = regexp.MustCompile(`^\d+/`)
)

// Runner executes nmap against the given targets and writes the original,
// unmodified nmap output to rawPath.
type Runner interface {
	RunPortscan(ctx context.Context, targets []string, rawPath string) error
}

// ExecRunner runs the real nmap binary with the legacy flags (-Pn), reading
// targets from stdin (-iL -) instead of live.txt.
type ExecRunner struct{}

func (r *ExecRunner) RunPortscan(ctx context.Context, targets []string, rawPath string) error {
	rawFile, err := os.Create(rawPath)
	if err != nil {
		return fmt.Errorf("failed to create raw portscan file %s: %w", rawPath, err)
	}
	defer rawFile.Close()

	cmd := exec.CommandContext(ctx, "nmap", "-iL", "-", "-Pn")
	cmd.Stdin = strings.NewReader(strings.Join(targets, "\n") + "\n")
	cmd.Stdout = rawFile
	cmd.Stderr = io.Discard

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run nmap: %w", err)
	}

	return nil
}

type Config struct {
	PortscanRaw string
	PortsFile   string
	Runner      Runner
}

func Run(ctx context.Context, cfg Config, assetStore *store.AssetStore) error {
	if assetStore == nil {
		return fmt.Errorf("asset store is nil")
	}

	if cfg.Runner == nil {
		cfg.Runner = &ExecRunner{}
	}

	rawDir := filepath.Dir(cfg.PortscanRaw)
	if err := os.MkdirAll(rawDir, 0755); err != nil {
		return fmt.Errorf("failed to create raw output directory %s: %w", rawDir, err)
	}

	targets := collectTargets(assetStore)

	if len(targets) == 0 {
		fmt.Println("[-] Warning: no web endpoints to scan, skipping nmap")

		f, err := os.Create(cfg.PortscanRaw)
		if err != nil {
			return fmt.Errorf("failed to create raw portscan file %s: %w", cfg.PortscanRaw, err)
		}
		f.Close()
	} else if err := cfg.Runner.RunPortscan(ctx, targets, cfg.PortscanRaw); err != nil {
		return fmt.Errorf("failed to execute nmap: %w", err)
	}

	rawFile, err := os.Open(cfg.PortscanRaw)
	if err != nil {
		return fmt.Errorf("failed to open raw portscan output %s: %w", cfg.PortscanRaw, err)
	}
	defer rawFile.Close()

	scanner := bufio.NewScanner(rawFile)
	currentHost := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if m := reportRe.FindStringSubmatch(line); m != nil {
			currentHost = m[1]
			continue
		}

		if strings.HasPrefix(line, "Nmap scan report for") {
			currentHost = ""
			fmt.Printf("[-] Warning: malformed nmap report line skipped: %s\n", line)
			continue
		}

		m := portRe.FindStringSubmatch(line)
		if m == nil {
			if looseRe.MatchString(line) {
				fmt.Printf("[-] Warning: malformed nmap port line skipped: %s\n", line)
			}
			continue
		}

		// Only open ports become services.
		if m[3] != "open" {
			continue
		}

		if currentHost == "" {
			fmt.Printf("[-] Warning: port line without host skipped: %s\n", line)
			continue
		}

		port, err := strconv.Atoi(m[1])
		if err != nil {
			fmt.Printf("[-] Warning: invalid nmap port skipped: %s\n", line)
			continue
		}

		serviceName := m[4]
		if serviceName == "unknown" {
			serviceName = ""
		}

		svc := models.Service{
			Host:        currentHost,
			Port:        port,
			Protocol:    m[2],
			ServiceName: serviceName,
		}

		// AssetStore normalizes the service and handles deduplication.
		if err := assetStore.AddService(svc); err != nil {
			fmt.Printf("[-] Warning: invalid nmap service skipped: %s (%v)\n", line, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf(
			"failed to scan raw portscan output %s: %w",
			cfg.PortscanRaw,
			err,
		)
	}

	return exportLegacyPorts(cfg.PortscanRaw, cfg.PortsFile)
}

// collectTargets returns the unique, sorted hostnames of all stored web endpoints.
func collectTargets(assetStore *store.AssetStore) []string {
	seen := make(map[string]struct{})

	for _, ep := range assetStore.WebEndpoints() {
		host := strings.TrimSpace(ep.Host)
		if host == "" {
			if u, err := url.Parse(ep.URL); err == nil {
				host = u.Hostname()
			}
		}
		if host == "" {
			continue
		}
		seen[strings.ToLower(host)] = struct{}{}
	}

	targets := make([]string, 0, len(seen))
	for h := range seen {
		targets = append(targets, h)
	}
	sort.Strings(targets)

	return targets
}

// exportLegacyPorts writes ports.txt as an exact copy of the raw nmap output,
// which is the format the legacy implementation produced.
func exportLegacyPorts(rawPath, path string) error {
	dst, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create legacy ports output %s: %w", path, err)
	}
	defer dst.Close()

	src, err := os.Open(rawPath)
	if err != nil {
		return fmt.Errorf("failed to open raw portscan output %s: %w", rawPath, err)
	}
	defer src.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("failed to write to %s: %w", path, err)
	}

	return nil
}
