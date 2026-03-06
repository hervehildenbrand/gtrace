package main

import (
	"fmt"
	"os"

	mcpserver "github.com/hervehildenbrand/gtrace/internal/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
)

// NewMCPCmd creates the `gtrace mcp` subcommand that starts an MCP server over stdio.
func NewMCPCmd() *cobra.Command {
	var apiKey string

	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Start MCP server over stdio",
		Long:  "Starts an MCP (Model Context Protocol) server over stdio, exposing gtrace tools for use by AI assistants and MCP-aware clients.",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Fall back to environment variable
			if apiKey == "" {
				apiKey = os.Getenv("GLOBALPING_API_KEY")
			}

			s := mcpserver.NewServer(Version, apiKey)

			if err := server.ServeStdio(s); err != nil {
				return fmt.Errorf("MCP server error: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&apiKey, "api-key", "", "GlobalPing API key (or set GLOBALPING_API_KEY)")

	return cmd
}
