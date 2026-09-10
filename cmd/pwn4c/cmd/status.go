package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Query status and health of the drone TCP control channel",
	Long:  "Sends telemetry probe packets over the TCP control channel (port 4444) to evaluate link health and radio state.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("[+] Querying drone TCP control channel status...")
		fmt.Println("[*] Stub: control channel telemetry probe not yet linked.")
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
