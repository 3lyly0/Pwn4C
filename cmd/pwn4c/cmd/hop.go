package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/3lyly0/Pwn4C/internal/drone"
	"github.com/spf13/cobra"
)

var (
	hopDwellMs  int
	hopChannels string
	hopTarget   string
)

// parseChannelList parses a comma-separated list of 2.4 GHz channel numbers.
func parseChannelList(list string) ([]int, error) {
	var channels []int
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ch, err := strconv.Atoi(part)
		if err != nil || ch < 1 || ch > 13 {
			return nil, fmt.Errorf("invalid channel '%s' (must be between 1 and 13)", part)
		}
		channels = append(channels, ch)
	}
	if len(channels) == 0 {
		return nil, fmt.Errorf("no valid channels specified")
	}
	return channels, nil
}

var hopCmd = &cobra.Command{
	Use:   "hop [target_drone_ip]",
	Short: "Continuously hop across 2.4 GHz Wi-Fi channels",
	Long:  "Commands the drone to cycle through 802.11 channels with a configurable dwell time for wide-spectrum scanning.",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := hopTarget
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

		// Parse channel list
		channels, err := parseChannelList(hopChannels)
		if err != nil {
			fmt.Printf("[!] %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[+] Connecting to drone at %s:%d...\n", target, drone.DefaultControlPort)
		client, err := drone.ConnectControl(target, 5*time.Second)
		if err != nil {
			fmt.Printf("[!] Failed to connect: %v\n", err)
			os.Exit(1)
		}
		defer client.Close()

		// Ensure monitor mode
		status, err := client.GetStatus()
		if err != nil {
			fmt.Printf("[!] Failed to query status: %v\n", err)
			os.Exit(1)
		}

		if !status.MonitorActive {
			fmt.Println("[+] Activating monitor mode...")
			if err := client.StartMonitor(channels[0]); err != nil {
				fmt.Printf("[!] Failed to activate monitor mode: %v\n", err)
				os.Exit(1)
			}
		}

		fmt.Printf("[+] Starting autonomous drone-side channel hopper across %v (Dwell: %dms)...\n", channels, hopDwellMs)
		if err := client.StartHop(channels, hopDwellMs); err != nil {
			fmt.Printf("[!] Drone rejected HOP_START: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] Autonomous hopping active on drone. Press Ctrl+C to stop.")

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

		<-sigCh
		fmt.Println("\n[*] Stopping autonomous channel hopping...")
		_ = client.StopHop()
		fmt.Println("[+] Channel hopper stopped.")
	},
}

func init() {
	hopCmd.Flags().IntVarP(&hopDwellMs, "dwell", "d", 250, "Dwell time per channel in milliseconds")
	hopCmd.Flags().StringVarP(&hopChannels, "channels", "c", "1,2,3,4,5,6,7,8,9,10,11,12,13", "Comma-separated list of channels to hop")
	hopCmd.Flags().StringVarP(&hopTarget, "target", "t", "", "Drone IP address")
	rootCmd.AddCommand(hopCmd)
}
