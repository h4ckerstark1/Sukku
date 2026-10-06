package probing

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"sukku/internal/models"
	"sukku/internal/store"
)

// Runner executes HTTPX against an input file of hosts and writes the
// original, unmodified HTTPX output to rawPath.
type Runner interface {
	RunHTTPX(ctx context.Context, inputPath, rawPath string) error
}

// ExecRunner runs the real httpx binary. It is equivalent to the legacy
// `cat subdomains.txt | httpx -silent`, except stdout goes to the raw file.
type ExecRunner struct{}

func (r *ExecRunner) RunHTTPX(ctx context.Context, inputPath, rawPath string) error {
	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open httpx input %s: %w", inputPath, err)
	}
	defer inFile.Close()

	rawFile, err := os.Create(rawPath)
	if err != nil {
		return fmt.Errorf("failed to create raw httpx file %s: %w", rawPath, err)
	}
	defer rawFile.Close()

	cmd := exec.CommandContext(ctx, "httpx", "-silent")
	cmd.Stdin = inFile
	cmd.Stdout = rawFile
	cmd.Stderr = io.Discard

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run httpx: %w", err)
	}

	return nil
}

type Config struct {
	SubdomainsFile string
	HTTPXRaw       string
	LiveFile       string
	Runner         Runner
}

func Run(ctx context.Context, cfg Config, assetStore *store.AssetStore) error {
	if assetStore == nil {
		return fmt.Errorf("asset store is nil")
	}

	if cfg.Runner == nil {
		cfg.Runner = &ExecRunner{}
	}

	rawDir := filepath.Dir(cfg.HTTPXRaw)
	if err := os.MkdirAll(rawDir, 0755); err != nil {
		return fmt.Errorf("failed to create raw output directory %s: %w", rawDir, err)
	}

	if err := cfg.Runner.RunHTTPX(ctx, cfg.SubdomainsFile, cfg.HTTPXRaw); err != nil {
		return fmt.Errorf("failed to execute httpx: %w", err)
	}

	rawFile, err := os.Open(cfg.HTTPXRaw)
	if err != nil {
		return fmt.Errorf("failed to open raw httpx output %s: %w", cfg.HTTPXRaw, err)
	}
	defer rawFile.Close()

	scanner := bufio.NewScanner(rawFile)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		u, err := url.Parse(line)
		if err != nil || u.Hostname() == "" {
			fmt.Printf("[-] Warning: invalid httpx record skipped: %s\n", line)
			continue
		}

		endpoint := models.WebEndpoint{
			URL:  line,
			Host: strings.ToLower(u.Hostname()),
		}

		// AssetStore normalizes the URL and handles deduplication.
		if err := assetStore.AddWebEndpoint(endpoint); err != nil {
			fmt.Printf("[-] Warning: invalid httpx endpoint skipped: %s (%v)\n", line, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf(
			"failed to scan raw httpx output %s: %w",
			cfg.HTTPXRaw,
			err,
		)
	}

	return exportLegacyLive(cfg.LiveFile, assetStore)
}

func exportLegacyLive(path string, assetStore *store.AssetStore) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create legacy live output %s: %w", path, err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	for _, endpoint := range assetStore.WebEndpoints() {
		if _, err := writer.WriteString(endpoint.URL + "\n"); err != nil {
			return fmt.Errorf("failed to write to %s: %w", path, err)
		}
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush %s: %w", path, err)
	}

	return nil
}
