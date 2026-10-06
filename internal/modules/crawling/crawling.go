package crawling

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
	"sukku/internal/normalize"
	"sukku/internal/store"
)

type Runner interface {
	RunKatana(ctx context.Context, livePath, rawPath string) error
}

type ExecRunner struct{}

func (r *ExecRunner) RunKatana(ctx context.Context, livePath, rawPath string) error {
	rawFile, err := os.Create(rawPath)
	if err != nil {
		return fmt.Errorf("failed to create raw katana file %s: %w", rawPath, err)
	}
	defer rawFile.Close()

	pipeline := fmt.Sprintf("cat %s | katana -silent", livePath)
	cmd := exec.CommandContext(ctx, "bash", "-c", pipeline)
	cmd.Stdout = rawFile
	cmd.Stderr = io.Discard

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run katana: %w", err)
	}

	return nil
}

type Config struct {
	LiveFile    string
	KatanaRaw   string
	JSFilesFile string
	Runner      Runner
}

func Run(ctx context.Context, cfg Config, assetStore *store.AssetStore) error {
	if assetStore == nil {
		return fmt.Errorf("asset store is nil")
	}

	if cfg.Runner == nil {
		cfg.Runner = &ExecRunner{}
	}

	rawDir := filepath.Dir(cfg.KatanaRaw)
	if err := os.MkdirAll(rawDir, 0755); err != nil {
		return fmt.Errorf("failed to create raw output directory %s: %w", rawDir, err)
	}

	if err := cfg.Runner.RunKatana(ctx, cfg.LiveFile, cfg.KatanaRaw); err != nil {
		return fmt.Errorf("failed to execute katana crawler: %w", err)
	}

	rawFile, err := os.Open(cfg.KatanaRaw)
	if err != nil {
		return fmt.Errorf("failed to open raw katana output %s: %w", cfg.KatanaRaw, err)
	}
	defer rawFile.Close()

	scanner := bufio.NewScanner(rawFile)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		normURL, err := normalize.URL(line)
		if err != nil {
			fmt.Printf("[-] Warning: invalid URL skipped: %s (%v)\n", line, err)
			continue
		}

		parsed, err := url.Parse(normURL)
		if err != nil {
			fmt.Printf("[-] Warning: failed to parse URL %s: %v\n", normURL, err)
			continue
		}

		host := parsed.Hostname()

		endpoint := models.WebEndpoint{
			URL:  normURL,
			Host: host,
		}

		if err := assetStore.AddWebEndpoint(endpoint); err != nil {
			fmt.Printf("[-] Warning: failed to add endpoint %s: %v\n", normURL, err)
		}

		if isJSPath(parsed.Path) {
			jsFile := models.JSFile{
				URL:  normURL,
				Host: host,
			}

			if err := assetStore.AddJSFile(jsFile); err != nil {
				fmt.Printf("[-] Warning: failed to add JS file %s: %v\n", normURL, err)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf(
			"failed to scan raw katana output %s: %w",
			cfg.KatanaRaw,
			err,
		)
	}

	return exportLegacyJSFiles(cfg.JSFilesFile, assetStore)
}

func isJSPath(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".js"
}

func exportLegacyJSFiles(path string, assetStore *store.AssetStore) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf(
			"failed to create legacy jsfiles output %s: %w",
			path,
			err,
		)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	for _, js := range assetStore.JSFiles() {
		if _, err := writer.WriteString(js.URL + "\n"); err != nil {
			return fmt.Errorf(
				"failed to write to %s: %w",
				path,
				err,
			)
		}
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush %s: %w", path, err)
	}

	return nil
}
