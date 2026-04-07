package main

import (
	"context"
	"fmt"

	"github.com/secopsium/secopsium-cli/internal/tools"
	"github.com/spf13/cobra"
)

func NewDoctorCmd(rootOpts *RootOptions) *cobra.Command {
	var strict bool

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Inspect scanner tool availability and managed install state",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			status := newStatusPrinter(cmd.OutOrStdout())
			manager := tools.NewManager(rootOpts.ToolsDir)

			status.Section("SecOpsium Doctor")
			status.Step(fmt.Sprintf("managed tools directory: %s", manager.RootDir()))

			resolved, err := manager.Resolve(ctx, tools.RequiredScanTools())
			if err != nil {
				return err
			}

			printResolvedTools(status, resolved, true)
			missing := tools.MissingTools(resolved)
			if len(missing) == 0 {
				status.OK("All required scanner tools are available.")
				return nil
			}

			status.Warn(fmt.Sprintf("Missing required tools: %s", formatToolIDs(missing)))
			status.Step("Run `secopsium setup` to install managed copies.")

			if strict {
				return NewExitCodeError(2, fmt.Errorf("missing required tools: %s", formatToolIDs(missing)))
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&strict, "strict", false, "exit non-zero when required tools are missing")
	return cmd
}
