package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/secopsium/secopsium-cli/internal/model"
	"github.com/secopsium/secopsium-cli/internal/tools"
	"github.com/spf13/cobra"
)

type statusPrinter struct {
	out io.Writer
}

func newStatusPrinter(out io.Writer) *statusPrinter {
	if out == nil {
		out = io.Discard
	}
	return &statusPrinter{out: out}
}

func (p *statusPrinter) Section(title string) {
	fmt.Fprintf(p.out, "==> %s\n", title)
}

func (p *statusPrinter) Step(message string) {
	fmt.Fprintf(p.out, "  -> %s\n", message)
}

func (p *statusPrinter) OK(message string) {
	fmt.Fprintf(p.out, "  ok %s\n", message)
}

func (p *statusPrinter) Warn(message string) {
	fmt.Fprintf(p.out, "  !! %s\n", message)
}

func (p *statusPrinter) Writer() io.Writer {
	return p.out
}

func ensureRequiredTools(
	ctx context.Context,
	cmd *cobra.Command,
	rootOpts *RootOptions,
	installMissing bool,
) ([]tools.ResolvedTool, []model.ScannerWarning, error) {
	manager := tools.NewManager(rootOpts.ToolsDir)
	status := newStatusPrinter(cmd.ErrOrStderr())

	resolved, err := manager.Resolve(ctx, tools.RequiredScanTools())
	if err != nil {
		return nil, nil, err
	}

	status.Section("Tooling")
	status.Step(fmt.Sprintf("managed tools directory: %s", manager.RootDir()))
	printResolvedTools(status, resolved, false)

	missing := tools.MissingTools(resolved)
	if len(missing) == 0 {
		return resolved, nil, nil
	}

	status.Warn(fmt.Sprintf("Missing required tools: %s", formatToolIDs(missing)))

	shouldInstall := installMissing || rootOpts.Yes
	if !shouldInstall && isInteractiveInput(cmd.InOrStdin()) {
		answer, promptErr := promptYesNo(
			cmd.InOrStdin(),
			cmd.ErrOrStderr(),
			fmt.Sprintf("Install missing tools into %s now?", manager.RootDir()),
			true,
		)
		if promptErr != nil {
			return resolved, nil, promptErr
		}
		shouldInstall = answer
	}

	if !shouldInstall {
		status.Step("Run `secopsium setup` or re-run with `--install-missing --yes` for zero-setup installs.")
		return resolved, nil, nil
	}

	status.Section("Setup")
	status.Step(fmt.Sprintf("installing %s", formatToolIDs(missing)))
	if _, err := manager.Install(ctx, missing, status.Writer()); err != nil {
		updated, resolveErr := manager.Resolve(ctx, tools.RequiredScanTools())
		if resolveErr == nil {
			resolved = updated
		}
		warnings := []model.ScannerWarning{{
			Kind:    model.WarningKindToolInstall,
			Scanner: "setup",
			Message: fmt.Sprintf("managed tool install failed: %v", err),
		}}
		return resolved, warnings, fmt.Errorf("install missing tools: %w", err)
	}

	resolved, err = manager.Resolve(ctx, tools.RequiredScanTools())
	if err != nil {
		return nil, nil, err
	}

	status.OK("Managed tool install completed.")
	printResolvedTools(status, resolved, true)
	return resolved, nil, nil
}

func printResolvedTools(status *statusPrinter, resolved []tools.ResolvedTool, includePath bool) {
	for _, tool := range resolved {
		switch {
		case tool.Ready:
			version := strings.TrimSpace(tool.Version)
			if version == "" {
				version = tool.Spec.Version
			}
			status.OK(fmt.Sprintf("%s %s (%s)", tool.Spec.DisplayName, version, tool.StatusText))
			if includePath {
				status.Step(fmt.Sprintf("%s path: %s", tool.Spec.DisplayName, formatToolPath(tool.Path)))
			}
		default:
			status.Warn(fmt.Sprintf("%s missing", tool.Spec.DisplayName))
		}
	}
}

func formatToolIDs(ids []tools.ToolID) string {
	if len(ids) == 0 {
		return ""
	}

	names := make([]string, 0, len(ids))
	for _, id := range ids {
		names = append(names, displayNameForTool(id))
	}
	return strings.Join(names, ", ")
}

func displayNameForTool(id tools.ToolID) string {
	for _, spec := range tools.SupportedTools() {
		if spec.ID == id {
			return spec.DisplayName
		}
	}
	return string(id)
}

func isInteractiveInput(reader io.Reader) bool {
	if strings.TrimSpace(os.Getenv("CI")) != "" {
		return false
	}

	file, ok := reader.(*os.File)
	if !ok {
		return false
	}

	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func promptYesNo(in io.Reader, out io.Writer, prompt string, defaultYes bool) (bool, error) {
	reader := bufio.NewReader(in)
	suffix := " [Y/n]: "
	if !defaultYes {
		suffix = " [y/N]: "
	}

	for {
		fmt.Fprint(out, prompt, suffix)
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return false, err
		}

		answer := strings.ToLower(strings.TrimSpace(line))
		switch answer {
		case "":
			return defaultYes, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}

		if err == io.EOF {
			return defaultYes, nil
		}
		fmt.Fprintln(out, "Please answer yes or no.")
	}
}

func prependManagedToolPath(rootOpts *RootOptions, resolved []tools.ResolvedTool) func() {
	manager := tools.NewManager(rootOpts.ToolsDir)
	return manager.PrependToPATH(resolved)
}

func formatToolPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return "-"
	}
	return filepath.Clean(path)
}
