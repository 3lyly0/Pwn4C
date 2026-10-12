package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/3lyly0/Pwn4C/internal/drone"
	"github.com/spf13/cobra"
)

var (
	configMAC     string
	configPower   int
	configRestore bool
	configReboot  bool
	configTarget  string
)

var configCmd = &cobra.Command{
	Use:   "config [target_drone_ip]",
	Short: "Configure drone radio parameters (MAC address, TX power, restore normal)",
	Long:  "Allows adjusting RF power, changing or randomizing the MAC address, resetting to normal router mode, or rebooting the drone.",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := configTarget
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

		client, err := drone.ConnectControl(target, 5*time.Second)
		if err != nil {
			fmt.Printf("[!] Failed to connect to drone: %v\n", err)
			os.Exit(1)
		}
		defer client.Close()

		if configRestore {
			fmt.Println("[+] Restoring managed AP/client Wi-Fi (RESTORE_NORMAL)...")
			if err := client.RestoreNormal(); err != nil {
				fmt.Printf("[!] Restore failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("[+] Drone radio returned to normal mode.")
			return
		}

		if configReboot {
			fmt.Println("[+] Sending REBOOT command...")
			if err := client.Reboot(); err != nil {
				fmt.Printf("[!] Reboot command failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("[+] Reboot signal acknowledged. Connection will drop.")
			return
		}

		applied := false

		if cmd.Flags().Changed("mac") {
			fmt.Println("[+] Setting MAC address...")
			newMAC, err := client.SetMAC(configMAC)
			if err != nil {
				fmt.Printf("[!] Failed to set MAC: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("[+] MAC updated to: %s\n", newMAC)
			applied = true
		}

		if cmd.Flags().Changed("power") {
			fmt.Printf("[+] Setting TX power to %d dBm...\n", configPower)
			if err := client.SetTxPower(configPower); err != nil {
				fmt.Printf("[!] Failed to set TX power: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("[+] TX power set to %d dBm.\n", configPower)
			applied = true
		}

		if !applied {
			fmt.Println("[*] No configuration flags specified. Use --help to view available options.")
		}
	},
}

func init() {
	configCmd.Flags().StringVar(&configMAC, "mac", "", "MAC address to set (omit value or leave empty for random)")
	configCmd.Flags().IntVarP(&configPower, "power", "p", 20, "TX power in dBm (1-20)")
	configCmd.Flags().BoolVar(&configRestore, "restore", false, "Exit monitor mode and restore normal Wi-Fi")
	configCmd.Flags().BoolVar(&configReboot, "reboot", false, "Reboot the drone remotely")
	configCmd.Flags().StringVarP(&configTarget, "target", "t", "", "Drone IP address")
	rootCmd.AddCommand(configCmd)
}
