package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/3lyly0/Pwn4C/internal/drone"
	"github.com/spf13/cobra"
)

var (
	monitorChannel int
	monitorOutput  string
	monitorTarget  string
)

var monitorCmd = &cobra.Command{
	Use:   "monitor [target_ip]",
	Short: "Stream raw 802.11 monitor frames from drone to host",
	Long:  "Configures the drone radio into 802.11 monitor mode and streams live PCAP frames over the network.",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := monitorTarget
		if len(args) > 0 {
			target = args[0]
		}

		if target == "" {
			fmt.Println("[*] No target specified, searching for active drones...")
			drones, err := drone.Discover(2*time.Second, "")
			if err != nil || len(drones) == 0 {
				fmt.Println("[!] No drone discovered. Please specify target IP (e.g. pwn4c monitor 192.168.4.1 -c 6).")
				os.Exit(1)
			}
			target = drones[0].IP
			fmt.Printf("[+] Discovered drone at %s\n", target)
		}

		// 1. Start local UDP stream receiver on port 5555
		var frameCount uint64
		receiver, err := drone.StartStreamReceiver(drone.DefaultStreamPort, monitorOutput, func(seq uint32, frame []byte) {
			frameCount++
			if frameCount%50 == 0 || frameCount == 1 {
				fmt.Printf("\r[+] Captured %d frames (last size: %d bytes)...", frameCount, len(frame))
			}
		})
		if err != nil {
			fmt.Printf("[!] Failed to bind UDP stream receiver: %v\n", err)
			os.Exit(1)
		}
		defer receiver.Close()

		if monitorOutput != "" {
			fmt.Printf("[+] Writing PCAP dump to: %s\n", monitorOutput)
		}

		// 2. Connect to drone via TCP control channel
		fmt.Printf("[+] Connecting to drone control at %s:%d...\n", target, drone.DefaultControlPort)
		client, err := drone.ConnectControl(target, 5*time.Second)
		if err != nil {
			fmt.Printf("[!] Failed to connect to control channel: %v\n", err)
			os.Exit(1)
		}
		defer client.Close()

		// 3. Command drone to start monitor mode
		fmt.Printf("[+] Starting monitor mode on channel %d...\n", monitorChannel)
		if err := client.StartMonitor(monitorChannel); err != nil {
			fmt.Printf("[!] Drone rejected START_MONITOR: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("[+] Monitor mode streaming active. Press Ctrl+C to stop.")

		// Handle graceful termination
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

		<-sigCh
		fmt.Println("\n[*] Stopping monitor session...")

		_ = client.StopMonitor()
		_ = receiver.Close()

		fmt.Printf("[+] Completed. Total frames captured: %d\n", frameCount)
	},
}

func init() {
	monitorCmd.Flags().IntVarP(&monitorChannel, "channel", "c", 1, "Wi-Fi channel to monitor (1-13)")
	monitorCmd.Flags().StringVarP(&monitorOutput, "output", "o", "capture.pcap", "Destination PCAP file path")
	monitorCmd.Flags().StringVarP(&monitorTarget, "target", "t", "", "Target drone IP (defaults to auto-discovery)")
	rootCmd.AddCommand(monitorCmd)
}
