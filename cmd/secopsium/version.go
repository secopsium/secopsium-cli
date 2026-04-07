package main

import (
	"fmt"

	"github.com/secopsium/secopsium-cli/internal/buildinfo"
	"github.com/spf13/cobra"
)

func NewVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show CLI version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "secopsium %s\n", buildinfo.Version)
			fmt.Fprintf(cmd.OutOrStdout(), "commit: %s\n", buildinfo.Commit)
			fmt.Fprintf(cmd.OutOrStdout(), "built:  %s\n", buildinfo.Date)
		},
	}
}
