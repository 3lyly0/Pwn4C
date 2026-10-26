package cmd

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/3lyly0/Pwn4C/internal/drone"
	"github.com/spf13/cobra"
)

var (
	monitorChannel     int
	monitorOutput      string
	monitorTarget      string
	monitorMgmtOnly    bool
	monitorFilterBSSID string
	monitorHop         bool
	monitorHopChannels string
	monitorHopDwell    int
)

var monitorCmd = &cobra.Command{
	Use:   "monitor [target_ip]",
	Short: "Stream raw 802.11 monitor frames from drone to host",
	Long: `Configures the drone radio into 802.11 monitor mode and streams live PCAP frames over the network.
Use -o - to stream raw PCAP bytes to stdout for live Wireshark analysis:
  pwn4c monitor -c 6 -o - | wireshark -k -i -`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// When streaming raw PCAP binary to stdout (-o -), route all human
		// progress logs to stderr so stdout remains a pure PCAP byte stream (§4.3).
		var logOut io.Writer = os.Stdout
		if monitorOutput == "-" {
			logOut = os.Stderr
		}

		target := monitorTarget
		if len(args) > 0 {
			target = args[0]
		}

		if target == "" {
			fmt.Fprintln(logOut, "[*] No target specified, searching for active drones...")
			drones, err := drone.Discover(2*time.Second, "")
			if err != nil || len(drones) == 0 {
				fmt.Fprintln(logOut, "[!] No drone discovered. Please specify target IP (e.g. pwn4c monitor 192.168.4.1 -c 6).")
				os.Exit(1)
			}
			target = drones[0].IP
			fmt.Fprintf(logOut, "[+] Discovered drone at %s\n", target)
		}

		// 1. Start local UDP stream receiver on port 5555
		var frameCount uint64
		receiver, err := drone.StartStreamReceiver(drone.DefaultStreamPort, monitorOutput, func(seq uint32, frame []byte) {
			frameCount++
			if frameCount%50 == 0 || frameCount == 1 {
				fmt.Fprintf(logOut, "\r[+] Captured %d frames (last size: %d bytes)...", frameCount, len(frame))
			}
		})
		if err != nil {
			fmt.Fprintf(logOut, "[!] Failed to bind UDP stream receiver: %v\n", err)
			os.Exit(1)
		}
		defer receiver.Close()

		if monitorOutput == "-" {
			fmt.Fprintln(logOut, "[+] Streaming raw PCAP output to stdout (Wireshark pipe mode)")
		} else if monitorOutput != "" {
			fmt.Fprintf(logOut, "[+] Writing PCAP dump to: %s\n", monitorOutput)
		}

		// 2. Connect to drone via TCP control channel
		fmt.Fprintf(logOut, "[+] Connecting to drone control at %s:%d...\n", target, drone.DefaultControlPort)
		client, err := drone.ConnectControl(target, 5*time.Second)
		if err != nil {
			fmt.Fprintf(logOut, "[!] Failed to connect to control channel: %v\n", err)
			os.Exit(1)
		}
		defer client.Close()

		// 3. Command drone to start monitor mode
		fmt.Fprintf(logOut, "[+] Starting monitor mode on channel %d...\n", monitorChannel)
		if err := client.StartMonitor(monitorChannel); err != nil {
			fmt.Fprintf(logOut, "[!] Drone rejected START_MONITOR: %v\n", err)
			os.Exit(1)
		}

		if monitorMgmtOnly || monitorFilterBSSID != "" {
			fmt.Fprintf(logOut, "[+] Attaching kernel BPF frame filter (mgmt_only=%v, bssid=%s)...\n",
				monitorMgmtOnly, monitorFilterBSSID)
			if err := client.SetFilter(monitorMgmtOnly, monitorFilterBSSID); err != nil {
				fmt.Fprintf(logOut, "[!] Warning: failed to attach BPF filter: %v\n", err)
			}
		} else if err := client.SetFilter(false, ""); err != nil {
			// The daemon keeps filter state across sessions; clear it so a
			// previous --filter-bssid run does not silently narrow this one.
			fmt.Fprintf(logOut, "[!] Warning: failed to clear inherited BPF filter: %v\n", err)
		}

		// 4. Optionally start autonomous hopping on the same control session,
		// so no second CLI process displaces this capture connection.
		var hopList []int
		if monitorHop {
			channels, err := parseChannelList(monitorHopChannels)
			if err != nil {
				fmt.Fprintf(logOut, "[!] %v\n", err)
				_ = client.StopMonitor()
				os.Exit(1)
			}
			hopList = channels
			if monitorHopDwell < 50 {
				monitorHopDwell = 50
			}
			fmt.Fprintf(logOut, "[+] Starting autonomous channel hop across %v (dwell %dms)...\n",
				hopList, monitorHopDwell)
			if err := client.StartHop(hopList, monitorHopDwell); err != nil {
				fmt.Fprintf(logOut, "[!] Warning: failed to start channel hopping: %v\n", err)
				hopList = nil
			}
		}

		fmt.Fprintln(logOut, "[+] Monitor mode streaming active. Press Ctrl+C to stop.")

		// Handle graceful termination
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

		<-sigCh
		fmt.Fprintln(logOut, "\n[*] Stopping monitor session...")

		if len(hopList) > 0 {
			_ = client.StopHop()
		}
		_ = client.StopMonitor()
		_ = receiver.Close()

		fmt.Fprintf(logOut, "[+] Completed. Total frames captured: %d\n", frameCount)
	},
}

func init() {
	monitorCmd.Flags().IntVarP(&monitorChannel, "channel", "c", 1, "Wi-Fi channel to monitor (1-13)")
	monitorCmd.Flags().StringVarP(&monitorOutput, "output", "o", "capture.pcap", "Destination PCAP file path (use '-' for stdout)")
	monitorCmd.Flags().StringVarP(&monitorTarget, "target", "t", "", "Target drone IP (defaults to auto-discovery)")
	monitorCmd.Flags().BoolVar(&monitorMgmtOnly, "mgmt-only", false, "Kernel BPF filter: 802.11 management frames only")
	monitorCmd.Flags().StringVar(&monitorFilterBSSID, "filter-bssid", "", "Kernel BPF filter: target BSSID MAC address")
	monitorCmd.Flags().BoolVar(&monitorHop, "hop", false, "Enable autonomous drone-side channel hopping")
	monitorCmd.Flags().StringVar(&monitorHopChannels, "channels", "1,6,11", "Comma-separated channels for --hop (e.g. 1,6,11)")
	monitorCmd.Flags().IntVar(&monitorHopDwell, "dwell", 250, "Dwell time per channel in ms for --hop")
	rootCmd.AddCommand(monitorCmd)
}
