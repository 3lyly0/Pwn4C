package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "pwn4c",
	Short: "Pwn4C: Offensive Wi-Fi Drone Management Framework",
	Long: `Pwn4C converts a Xiaomi Mi Router 4C (MediaTek MT7628N) into a headless
Wi-Fi penetration testing implant. It provides orchestration for deployment,
discovery, channel monitoring, and control channel telemetry.`,
}

// Execute executes the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	// Global flags will be registered here.
}
