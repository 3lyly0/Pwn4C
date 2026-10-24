package cmd

import (
	"fmt"
	"os"

	"github.com/3lyly0/Pwn4C/internal/drone"
	"github.com/spf13/cobra"
)

var globalPSK string

var rootCmd = &cobra.Command{
	Use:   "pwn4c",
	Short: "Pwn4C: Offensive Wi-Fi Drone Management Framework",
	Long: `Pwn4C converts a Xiaomi Mi Router 4C (MediaTek MT7628N) into a headless
Wi-Fi penetration testing implant. It provides orchestration for deployment,
discovery, channel monitoring, and control channel telemetry.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if globalPSK != "" {
			drone.DefaultPSK = globalPSK
		}
	},
}

// Execute executes the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&globalPSK, "psk", "", "Pre-shared key for HMAC-SHA256 control channel authentication (or set PWN4C_PSK)")
}
