package main

import (
	"errors"
	"strings"
	"testing"
)

func TestRunPipelineStopsAtFirstError(t *testing.T) {
	wantErr := errors.New("simulated stage failure")
	calls := 0

	err := runPipeline(
		func() error {
			calls++
			return nil
		},
		func() error {
			calls++
			return wantErr
		},
		func() error {
			calls++
			return nil
		},
	)

	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped error %v, got %v", wantErr, err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 stages to run, got %d", calls)
	}
}

func TestRunPipelineSuccess(t *testing.T) {
	calls := 0

	err := runPipeline(
		func() error {
			calls++
			return nil
		},
		func() error {
			calls++
			return nil
		},
		func() error {
			calls++
			return nil
		},
	)

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 stages to run, got %d", calls)
	}
}

func TestRunPipelineEmpty(t *testing.T) {
	if err := runPipeline(); err != nil {
		t.Fatalf("expected nil error for empty pipeline, got %s", strings.TrimSpace(err.Error()))
	}
}
