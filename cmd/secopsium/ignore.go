package main

import (
	"errors"
	"fmt"

	"github.com/secopsium/secopsium-cli/internal/filter"
	"github.com/spf13/cobra"
)

func NewIgnoreCmd() *cobra.Command {
	var ignoreFile string

	cmd := &cobra.Command{
		Use:   "ignore",
		Short: "Manage ignore patterns used by scan",
	}
	cmd.PersistentFlags().StringVar(&ignoreFile, "file", filter.DefaultIgnoreFilename, "ignore file path")

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Create a default ignore file",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := filter.InitIgnoreFile(ignoreFile); err != nil {
				return err
			}
			fmt.Printf("Created %s\n", ignoreFile)
			return nil
		},
	}

	addCmd := &cobra.Command{
		Use:   "add <pattern> [pattern...]",
		Short: "Add one or more ignore patterns",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := filter.AddPatterns(ignoreFile, args); err != nil {
				return err
			}
			fmt.Printf("Updated %s\n", ignoreFile)
			return nil
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List effective ignore patterns (defaults + file patterns)",
		RunE: func(cmd *cobra.Command, args []string) error {
			matcher, err := filter.NewMatcherFromFile(ignoreFile)
			if err != nil {
				return err
			}
			patterns := matcher.Patterns()
			if len(patterns) == 0 {
				return errors.New("no ignore patterns configured")
			}
			for _, pattern := range patterns {
				fmt.Println(pattern)
			}
			return nil
		},
	}

	cmd.AddCommand(initCmd, addCmd, listCmd)
	return cmd
}
