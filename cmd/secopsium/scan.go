package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/secopsium/secopsium-cli/internal/config"
	"github.com/secopsium/secopsium-cli/internal/filter"
	"github.com/secopsium/secopsium-cli/internal/model"
	"github.com/secopsium/secopsium-cli/internal/output"
	"github.com/secopsium/secopsium-cli/internal/repo"
	"github.com/secopsium/secopsium-cli/internal/runner"
	"github.com/secopsium/secopsium-cli/internal/tools"
	"github.com/secopsium/secopsium-cli/scanner"
	configscanner "github.com/secopsium/secopsium-cli/scanner/config"
	jsscanner "github.com/secopsium/secopsium-cli/scanner/js"
	"github.com/secopsium/secopsium-cli/scanner/secrets"
	"github.com/spf13/cobra"
)

type scanFlags struct {
	repoURL        string
	ref            string
	jsonOutput     bool
	timeout        time.Duration
	cloneTimeout   time.Duration
	ignoreFile     string
	failOnFindings bool
	strict         bool
	bestEffort     bool
	allowFileURL   bool
	maxRepoSizeMB  int64
	jsMaxFileSizeMB int64
	installMissing bool
}

func NewScanCmd(rootOpts *RootOptions) *cobra.Command {
	flags := &scanFlags{}

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a local repository path or a remote Git URL",
		Args: func(cmd *cobra.Command, args []string) error {
			if flags.repoURL != "" && len(args) > 0 {
				return errors.New("use either a local path argument or --repo, not both")
			}
			if flags.repoURL == "" && len(args) > 1 {
				return errors.New("scan accepts at most one path argument")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			if cmd.Flags().Changed("strict") && cmd.Flags().Changed("best-effort") {
				return errors.New("use either --strict or --best-effort, not both")
			}

			scanCtx := ctx
			cancel := func() {}
			if flags.timeout > 0 {
				var scanCancel context.CancelFunc
				scanCtx, scanCancel = context.WithTimeout(ctx, flags.timeout)
				cancel = scanCancel
			}
			defer cancel()

			settings, err := config.Load(rootOpts.ConfigPath)
			if err != nil {
				return fmt.Errorf("load config %s: %w", rootOpts.ConfigPath, err)
			}
			outputFormat := settings.OutputFormat
			if flags.jsonOutput {
				outputFormat = config.FormatJSON
			}

			preScanWarnings := make([]model.ScannerWarning, 0, 1)
			resolvedTools, toolWarnings, toolErr := ensureRequiredTools(ctx, cmd, rootOpts, flags.installMissing)
			if len(toolWarnings) > 0 {
				preScanWarnings = append(preScanWarnings, toolWarnings...)
			}
			restorePATH := prependManagedToolPath(rootOpts, resolvedTools)
			defer restorePATH()
			if toolErr != nil {
				if flags.strict {
					return toolErr
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "  !! %s\n", toolErr.Error())
			}

			targetPath := "."
			displayTarget := targetPath
			if len(args) == 1 {
				targetPath = args[0]
				displayTarget = targetPath
			}

			clonedPath := ""
			if flags.repoURL != "" {
				if _, err := repo.ValidateURL(flags.repoURL, flags.allowFileURL); err != nil {
					return err
				}

				fmt.Fprintf(cmd.ErrOrStderr(), "==> Clone\n  -> fetching %s\n", flags.repoURL)

				cloneCtx := scanCtx
				cloneCancel := func() {}
				if flags.cloneTimeout > 0 {
					var cancelFn context.CancelFunc
					cloneCtx, cancelFn = context.WithTimeout(scanCtx, flags.cloneTimeout)
					cloneCancel = cancelFn
				}
				defer cloneCancel()

				var err error
				clonedPath, err = repo.CloneToTemp(cloneCtx, repo.CloneRequest{
					URL:          flags.repoURL,
					Ref:          flags.ref,
					MaxSizeBytes: flags.maxRepoSizeMB * 1024 * 1024,
				})
				if err != nil {
					return fmt.Errorf("clone failed: %w", err)
				}
				targetPath = clonedPath
				displayTarget = flags.repoURL
			}

			absTarget, err := filepath.Abs(targetPath)
			if err != nil {
				return fmt.Errorf("resolve target path: %w", err)
			}
			info, err := os.Stat(absTarget)
			if err != nil {
				return fmt.Errorf("access target path %q: %w", absTarget, err)
			}
			if !info.IsDir() {
				return fmt.Errorf("target path must be a directory: %s", absTarget)
			}

			ignorePath := filter.ResolveIgnoreFile(absTarget, flags.ignoreFile)
			matcher, err := filter.NewMatcherFromFile(ignorePath)
			if err != nil {
				return fmt.Errorf("load ignore file %s: %w", ignorePath, err)
			}

			fmt.Fprintf(cmd.ErrOrStderr(), "==> Scan\n  -> target: %s\n", displayTarget)
			if len(tools.MissingTools(resolvedTools)) == 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "  -> scanners: Gitleaks, Semgrep, JS exposure\n")
			}

			scanRunner := runner.New([]scanner.Scanner{
				secrets.New(),
				configscanner.New(),
				jsscanner.New(),
			}, flags.timeout)

			result, err := scanRunner.Run(scanCtx, runner.Request{
				TargetPath:         absTarget,
				DisplayTarget:      displayTarget,
				Ignore:             matcher,
				UnsafeRawOutput:    rootOpts.UnsafeRawOutput,
				Strict:             flags.strict,
				JSMaxFileSizeBytes: flags.jsMaxFileSizeMB * 1024 * 1024,
			})
			if len(preScanWarnings) > 0 {
				result.Warnings = append(preScanWarnings, result.Warnings...)
			}
			if clonedPath != "" {
				if cleanupErr := os.RemoveAll(clonedPath); cleanupErr != nil && err == nil {
					result.Warnings = append(result.Warnings, model.ScannerWarning{
						Kind:    model.WarningKindCleanup,
						Scanner: "clone",
						Message: cleanupErr.Error(),
					})
					result.Summary = model.BuildSummary(result.Findings, result.Warnings, result.Summary.ScannerTotal)
				}
			}
			if err != nil {
				return err
			}
			result.Summary = model.BuildSummary(result.Findings, result.Warnings, result.Summary.ScannerTotal)

			if err := output.Print(result, outputFormat, rootOpts.NoColor, rootOpts.UnsafeRawOutput); err != nil {
				return err
			}

			return scanExitError(result, flags.strict, flags.failOnFindings)
		},
	}

	cmd.Flags().StringVar(&flags.repoURL, "repo", "", "remote Git repository URL to scan")
	cmd.Flags().StringVar(&flags.ref, "ref", "", "remote branch name to clone when using --repo")
	cmd.Flags().BoolVar(&flags.jsonOutput, "json", false, "render scan output as JSON")
	cmd.Flags().DurationVar(&flags.timeout, "timeout", 2*time.Minute, "overall timeout for clone and scan execution")
	cmd.Flags().DurationVar(&flags.cloneTimeout, "clone-timeout", 60*time.Second, "timeout for remote repository cloning")
	cmd.Flags().StringVar(&flags.ignoreFile, "ignore-file", "", "path to ignore file (defaults to .secopsiumignore)")
	cmd.Flags().BoolVar(&flags.failOnFindings, "fail-on-findings", false, "exit with code 3 if findings are present")
	cmd.Flags().BoolVar(&flags.strict, "strict", false, "exit non-zero if any scanner fails")
	cmd.Flags().BoolVar(&flags.bestEffort, "best-effort", false, "continue on scanner failures (default behavior)")
	cmd.Flags().BoolVar(&flags.allowFileURL, "allow-file-url", false, "allow file:// repository URLs when using --repo")
	cmd.Flags().Int64Var(&flags.maxRepoSizeMB, "max-repo-size-mb", repo.DefaultMaxRepoSizeBytes/(1024*1024), "best-effort maximum size for cloned repositories in MB")
	cmd.Flags().Int64Var(&flags.jsMaxFileSizeMB, "js-max-file-size-mb", jsscanner.DefaultMaxFileSizeBytes/(1024*1024), "maximum JS/TS file size to scan in MB before files are skipped with a warning")
	cmd.Flags().BoolVar(&flags.installMissing, "install-missing", false, "auto-install managed copies of missing scanner tools")

	return cmd
}

func scanExitError(result model.ScanResult, strict bool, failOnFindings bool) error {
	if result.Summary.ScannerSucceeded == 0 {
		return NewExitCodeError(2, errors.New("all scanners failed"))
	}
	if strict && result.Summary.ScannerFailed > 0 {
		return NewExitCodeError(2, fmt.Errorf("scan completed with %d scanner failure(s)", result.Summary.ScannerFailed))
	}
	if failOnFindings && len(result.Findings) > 0 {
		return NewExitCodeError(3, nil)
	}
	return nil
}
