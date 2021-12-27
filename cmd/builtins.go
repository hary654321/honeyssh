package cmd

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"
	"josephlewis.net/honeyssh/commands"
)

// serveCmd represents the serve command
var builtinsCmd = &cobra.Command{
	Use:   "builtins",
	Short: "Show the builtin commands for the honeypot.",
	RunE: func(cmd *cobra.Command, args []string) error {
		var builtins []string

		for _, cmd := range commands.ListBuiltinCommands() {
			builtins = append(builtins, cmd.Names...)
		}

		for cmd, _ := range commands.AllBuiltins {
			builtins = append(builtins, "shell:"+cmd)
		}

		sort.Strings(builtins)

		for _, v := range builtins {
			fmt.Fprintln(cmd.OutOrStdout(), v)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(builtinsCmd)
}
