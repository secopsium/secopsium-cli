package main

import (
	"github.com/secopsium/secopsium-cli/internal/tools"
	"github.com/spf13/cobra"
)

type RootOptions struct {
	ConfigPath      string
	NoColor         bool
	UnsafeRawOutput bool
	ToolsDir        string
	Yes             bool
}

func Execute() error {
	return NewRootCmd().Execute()
}

func NewRootCmd() *cobra.Command {
	rootOpts := &RootOptions{}

	cmd := &cobra.Command{
		Use:           "secopsium",
		Short:         "SecOpsium open-source security scanning CLI",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.PersistentFlags().StringVar(&rootOpts.ConfigPath, "config", ".secopsium-cli.yaml", "path to CLI config file")
	cmd.PersistentFlags().BoolVar(&rootOpts.NoColor, "no-color", false, "disable colored output")
	cmd.PersistentFlags().BoolVar(&rootOpts.UnsafeRawOutput, "unsafe-raw-output", false, "disable default redaction and print raw finding evidence")
	cmd.PersistentFlags().StringVar(&rootOpts.ToolsDir, "tools-dir", tools.DefaultToolsDir(), "directory used for managed scanner tool installs")
	cmd.PersistentFlags().BoolVarP(&rootOpts.Yes, "yes", "y", false, "assume yes when prompting to install missing tools")

	cmd.AddCommand(NewScanCmd(rootOpts))
	cmd.AddCommand(NewSetupCmd(rootOpts))
	cmd.AddCommand(NewDoctorCmd(rootOpts))
	cmd.AddCommand(NewVersionCmd())
	cmd.AddCommand(NewOutputCmd(rootOpts))
	cmd.AddCommand(NewIgnoreCmd())

	return cmd
}
