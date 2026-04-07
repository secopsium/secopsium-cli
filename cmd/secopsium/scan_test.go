package main

import (
	"errors"
	"testing"

	"github.com/secopsium/secopsium-cli/internal/model"
)

func TestScanExitErrorFailsWhenAllScannersFail(t *testing.T) {
	result := model.ScanResult{
		Summary: model.Summary{
			ScannerTotal:     3,
			ScannerSucceeded: 0,
			ScannerFailed:    3,
		},
	}

	err := scanExitError(result, false, false)
	if err == nil {
		t.Fatalf("expected exit error")
	}

	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) || exitErr.Code != 2 {
		t.Fatalf("expected exit code 2, got %#v", err)
	}
}

func TestScanExitErrorFailsInStrictModeOnPartialScannerFailure(t *testing.T) {
	result := model.ScanResult{
		Summary: model.Summary{
			ScannerTotal:     3,
			ScannerSucceeded: 2,
			ScannerFailed:    1,
		},
	}

	err := scanExitError(result, true, false)
	if err == nil {
		t.Fatalf("expected strict mode to fail")
	}
}

func TestScanExitErrorAllowsBestEffortPartialFailure(t *testing.T) {
	result := model.ScanResult{
		Summary: model.Summary{
			ScannerTotal:     3,
			ScannerSucceeded: 2,
			ScannerFailed:    1,
		},
	}

	if err := scanExitError(result, false, false); err != nil {
		t.Fatalf("expected best-effort mode to succeed: %v", err)
	}
}

func TestScanExitErrorUsesFindingsExitCode(t *testing.T) {
	result := model.ScanResult{
		Findings: []model.Finding{{Title: "secret"}},
		Summary: model.Summary{
			ScannerTotal:     3,
			ScannerSucceeded: 3,
			ScannerFailed:    0,
		},
	}

	err := scanExitError(result, false, true)
	if err == nil {
		t.Fatalf("expected findings exit error")
	}

	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) || exitErr.Code != 3 {
		t.Fatalf("expected exit code 3, got %#v", err)
	}
}
