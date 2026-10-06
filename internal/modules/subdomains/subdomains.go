package subdomains

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"sukku/internal/models"
	"sukku/internal/store"
)

type Runner interface {
	RunSubfinder(ctx context.Context, domain, rawPath string) error
}

type ExecRunner struct{}

func (r *ExecRunner) RunSubfinder(ctx context.Context, domain, rawPath string) error {
	rawFile, err := os.Create(rawPath)
	if err != nil {
		return fmt.Errorf("failed to create raw subfinder file %s: %w", rawPath, err)
	}
	defer rawFile.Close()

	cmd := exec.CommandContext(ctx, "subfinder", "-d", domain, "-silent")
	cmd.Stdout = rawFile
	cmd.Stderr = io.Discard

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run subfinder: %w", err)
	}

	return nil
}

type Config struct {
	DomainFile     string
	Domain         string
	SubfinderRaw   string
	SubdomainsFile string
	Runner         Runner
}

func Run(ctx context.Context, cfg Config, assetStore *store.AssetStore) error {
	if assetStore == nil {
		return fmt.Errorf("asset store is nil")
	}

	if cfg.Runner == nil {
		cfg.Runner = &ExecRunner{}
	}

	rawDir := filepath.Dir(cfg.SubfinderRaw)
	if err := os.MkdirAll(rawDir, 0755); err != nil {
		return fmt.Errorf("failed to create raw output directory %s: %w", rawDir, err)
	}

	if err := cfg.Runner.RunSubfinder(ctx, cfg.Domain, cfg.SubfinderRaw); err != nil {
		return fmt.Errorf("failed to execute subfinder: %w", err)
	}

	rawFile, err := os.Open(cfg.SubfinderRaw)
	if err != nil {
		return fmt.Errorf("failed to open raw subfinder output %s: %w", cfg.SubfinderRaw, err)
	}
	defer rawFile.Close()

	scanner := bufio.NewScanner(rawFile)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		domain := models.Domain{Name: line}

		if err := assetStore.AddDomain(domain); err != nil {
			fmt.Printf("[-] Warning: invalid subfinder domain skipped: %s (%v)\n", line, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf(
			"failed to scan raw subfinder output %s: %w",
			cfg.SubfinderRaw,
			err,
		)
	}

	return exportLegacySubdomains(cfg.SubdomainsFile, assetStore)
}

func exportLegacySubdomains(path string, assetStore *store.AssetStore) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf(
			"failed to create legacy subdomains output %s: %w",
			path,
			err,
		)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	for _, domain := range assetStore.Domains() {
		if _, err := writer.WriteString(domain.Name + "\n"); err != nil {
			return fmt.Errorf("failed to write to %s: %w", path, err)
		}
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush %s: %w", path, err)
	}

	return nil
}
