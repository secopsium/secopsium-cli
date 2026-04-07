package main

import (
	"context"
	"fmt"

	"github.com/secopsium/secopsium-cli/internal/tools"
	"github.com/spf13/cobra"
)

func NewSetupCmd(rootOpts *RootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Install and verify managed scanner tools",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			status := newStatusPrinter(cmd.OutOrStdout())
			manager := tools.NewManager(rootOpts.ToolsDir)

			status.Section("SecOpsium Setup")
			status.Step(fmt.Sprintf("managed tools directory: %s", manager.RootDir()))

			resolved, err := manager.Resolve(ctx, tools.RequiredScanTools())
			if err != nil {
				return err
			}

			missing := tools.MissingTools(resolved)
			if len(missing) == 0 {
				status.OK("All required scanner tools are already available.")
				printResolvedTools(status, resolved, true)
				return nil
			}

			status.Step(fmt.Sprintf("installing missing tools: %s", formatToolIDs(missing)))
			if _, err := manager.Install(ctx, missing, status.Writer()); err != nil {
				return fmt.Errorf("install missing tools: %w", err)
			}

			resolved, err = manager.Resolve(ctx, tools.RequiredScanTools())
			if err != nil {
				return err
			}
			printResolvedTools(status, resolved, true)

			if remaining := tools.MissingTools(resolved); len(remaining) > 0 {
				return NewExitCodeError(2, fmt.Errorf("setup completed with missing tools: %s", formatToolIDs(remaining)))
			}

			status.OK("Scanner tools are ready.")
			return nil
		},
	}

	return cmd
}
