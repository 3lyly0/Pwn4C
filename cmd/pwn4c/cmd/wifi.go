package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	wifiStatusTarget     string
	wifiDisconnectTarget string
)

var wifiStatusCmd = &cobra.Command{
	Use:   "wifi-status [target_ip]",
	Short: "Show the drone's upstream Wi-Fi station link",
	Long:  "Reports whether the drone is associated with an upstream network, and its SSID, BSSID, channel and DHCP address.",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := wifiStatusTarget
		if len(args) > 0 {
			target = args[0]
		}
		target = resolveTargetOrExit(target)

		client := connectOrExit(target)
		defer client.Close()

		st, err := client.WifiStatus()
		if err != nil {
			fmt.Printf("[!] Failed to query Wi-Fi status: %v\n", err)
			return
		}

		if !st.Connected {
			fmt.Println("[-] Drone is not associated with any network (radio idle).")
			return
		}

		fmt.Println("\n============ DRONE UPLINK ============")
		fmt.Printf(" SSID     : %s\n", st.SSID)
		fmt.Printf(" BSSID    : %s\n", st.BSSID)
		fmt.Printf(" Channel  : %d\n", st.Channel)
		fmt.Printf(" IP (wan) : %s\n", st.IP)
		fmt.Println("======================================")
	},
}

var wifiDisconnectCmd = &cobra.Command{
	Use:   "wifi-disconnect [target_ip]",
	Short: "Disconnect the drone from the upstream Wi-Fi network",
	Long:  "Removes the station profile and returns the radio to the boot-safe DOWN state. The stock AP profile stays untouched.",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := wifiDisconnectTarget
		if len(args) > 0 {
			target = args[0]
		}
		target = resolveTargetOrExit(target)

		client := connectOrExit(target)
		defer client.Close()

		fmt.Println("[+] Removing the station profile...")
		if err := client.WifiDisconnect(); err != nil {
			fmt.Printf("[!] Disconnect failed: %v\n", err)
			return
		}
		fmt.Println("[+] Drone left the network; radio is back to the idle (DOWN) state.")
	},
}

func init() {
	wifiStatusCmd.Flags().StringVarP(&wifiStatusTarget, "target", "t", "", "Target drone IP (defaults to auto-discovery)")
	wifiDisconnectCmd.Flags().StringVarP(&wifiDisconnectTarget, "target", "t", "", "Target drone IP (defaults to auto-discovery)")
	rootCmd.AddCommand(wifiStatusCmd)
	rootCmd.AddCommand(wifiDisconnectCmd)
}
