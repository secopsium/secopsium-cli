package main

import (
	"errors"
	"fmt"

	"github.com/secopsium/secopsium-cli/internal/config"
	"github.com/spf13/cobra"
)

func NewOutputCmd(rootOpts *RootOptions) *cobra.Command {
	var jsonFlag bool
	var humanFlag bool

	cmd := &cobra.Command{
		Use:   "output",
		Short: "Manage default output format",
		RunE: func(cmd *cobra.Command, args []string) error {
			if jsonFlag && humanFlag {
				return errors.New("choose one of --json or --human")
			}

			settings, err := config.Load(rootOpts.ConfigPath)
			if err != nil {
				return fmt.Errorf("load config %s: %w", rootOpts.ConfigPath, err)
			}

			if jsonFlag {
				settings.OutputFormat = config.FormatJSON
			}
			if humanFlag {
				settings.OutputFormat = config.FormatHuman
			}

			if jsonFlag || humanFlag {
				if err := config.Save(rootOpts.ConfigPath, settings); err != nil {
					return fmt.Errorf("save config %s: %w", rootOpts.ConfigPath, err)
				}
			}

			fmt.Printf("Default output format: %s\n", settings.OutputFormat)
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonFlag, "json", false, "set default output format to JSON")
	cmd.Flags().BoolVar(&humanFlag, "human", false, "set default output format to human")

	return cmd
}
