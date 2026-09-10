package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	monitorChannel int
	monitorOutput  string
)

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Stream raw 802.11 monitor frames from drone to host",
	Long:  "Configures the drone radio into 802.11 monitor mode and streams live PCAP frames over the network.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("[+] Starting monitor mode stream on channel: %d\n", monitorChannel)
		if monitorOutput != "" {
			fmt.Printf("[+] Writing PCAP capture to file: %s\n", monitorOutput)
		} else {
			fmt.Println("[*] Output destination not specified; streaming to stdout buffer.")
		}
		fmt.Println("[*] Stub: frame streaming engine not yet linked.")
	},
}

func init() {
	monitorCmd.Flags().IntVarP(&monitorChannel, "channel", "c", 1, "Wi-Fi channel to monitor (1-14)")
	monitorCmd.Flags().StringVarP(&monitorOutput, "output", "o", "", "Destination PCAP file path")
	rootCmd.AddCommand(monitorCmd)
}
