package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/3lyly0/Pwn4C/internal/drone"
	"github.com/spf13/cobra"
)

var (
	clientsChannel int
	clientsSeconds int
	clientsJSON    bool
	clientsWatch   bool
	clientsBSSID   string
	clientsAssoc   bool
	clientsReset   bool
	clientsTarget  string
	clientsMinRSSI int
)

var clientsCmd = &cobra.Command{
	Use:   "clients [target_drone_ip]",
	Short: "Inventory the stations around the drone (associated clients and PNL probes)",
	Long: `Listens in monitor mode and reports every station the radio hears:

  * clients associated to an access point (from data frames and assoc requests)
  * clients that are only probing for a network (their PNL entry)

Each row carries the station MAC, the BSSID it is talking to, the last RSSI the
radio reported, how many frames were seen, and how long ago it was last heard.
That is the targeting step: pick a BSSID to kick, a channel to herd with CSA,
or a network to impersonate.

  pwn4c clients -c 6 -s 20
  pwn4c clients -c 6 --bssid AA:BB:CC:DD:EE:FF --assoc-only
  pwn4c clients --json

If monitor mode is already active the command reads the inventory that the
current capture has built up; otherwise it starts the radio on -c for -s
seconds and stops it again. --watch keeps refreshing the table until Ctrl+C.

The table survives STOP_MONITOR inside the daemon and is cleared by the next
START_MONITOR, so stopping the radio does not lose what was seen.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if clientsChannel < 1 || clientsChannel > 13 {
			fmt.Println("[!] --channel must be between 1 and 13.")
			os.Exit(1)
		}
		if clientsSeconds < 1 || clientsSeconds > 3600 {
			fmt.Println("[!] --seconds must be between 1 and 3600.")
			os.Exit(1)
		}
		if clientsBSSID != "" {
			if !strings.Contains(clientsBSSID, ":") && !strings.Contains(clientsBSSID, "-") {
				fmt.Printf("[!] Invalid BSSID %q\n", clientsBSSID)
				os.Exit(1)
			}
		}

		target := clientsTarget
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
		// an inventory of the wrong channel is just an empty table.
		channel := clientsChannel
		channelExplicit := cmd.Flags().Changed("channel")
		if !channelExplicit && status.MonitorActive &&
			status.Channel >= 1 && status.Channel <= 13 {
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
		} else if status.Channel != channel && channelExplicit {
			fmt.Printf("[+] Switching channel from %d to %d...\n", status.Channel, channel)
			if err := client.SetChannel(channel); err != nil {
				fmt.Printf("[!] Failed to switch channel: %v\n", err)
				os.Exit(1)
			}
		}

		// A BSSID filter left behind by an earlier listen session would hide
		// every other station. Clear it: the inventory wants everything.
		if err := client.SetFilter(false, ""); err != nil {
			fmt.Printf("[!] Warning: failed to clear the frame filter: %v\n", err)
		}

		if clientsReset {
			if _, err := client.GetClients(0, true); err != nil {
				fmt.Printf("[!] Warning: failed to reset the client table: %v\n", err)
			}
		}

		if clientsWatch {
			watchClients(client, channel)
			if weStarted {
				fmt.Println("[*] Stopping monitor mode...")
				if err := client.StopMonitor(); err != nil {
					fmt.Printf("[!] Warning: failed to stop monitor mode: %v\n", err)
				}
			}
			return
		}

		stations := collectClients(client, channel, clientsSeconds)
		stations = filterClients(stations)

		if weStarted {
			fmt.Println("[*] Stopping monitor mode...")
			if err := client.StopMonitor(); err != nil {
				fmt.Printf("[!] Warning: failed to stop monitor mode: %v\n", err)
			}
		}

		if clientsJSON {
			printClientsJSON(stations)
			return
		}
		if len(stations) == 0 {
			fmt.Println("[-] No stations heard.")
			fmt.Println("    Hints:")
			fmt.Println("      - confirm the AP channel: pwn4c networks")
			fmt.Println("      - listen longer (--seconds 60); probes are bursty")
			fmt.Println("      - a quiet channel has nothing to see — hop with 'pwn4c hop'")
			return
		}
		printClientTable(stations, channel)
	},
}

// mergeClient folds one poll into the inventory. A station already in the list
// is replaced with the fresher snapshot, so the table printed when the listen
// ends describes the last poll (RSSI, frame count, age) instead of the first
// time the station was heard. It reports whether the station is new.
func mergeClient(stations []drone.Client, index map[string]int, c drone.Client) ([]drone.Client, bool) {
	key := strings.ToUpper(c.STA)
	if i, ok := index[key]; ok {
		stations[i] = c
		return stations, false
	}
	index[key] = len(stations)
	return append(stations, c), true
}

// collectClients polls the daemon until the deadline and returns every station
// it has seen, reporting new ones as they appear.
func collectClients(client *drone.ControlClient, channel, seconds int) []drone.Client {
	index := make(map[string]int)
	var stations []drone.Client

	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	fmt.Printf("[*] Listening on channel %d for up to %ds...\n", channel, seconds)

	for {
		page, err := client.GetAllClients()
		if err != nil {
			fmt.Printf("\n[!] Failed to read the client table: %v\n", err)
			return stations
		}
		for _, c := range page {
			var isNew bool
			stations, isNew = mergeClient(stations, index, c)
			if !isNew {
				continue
			}
			fmt.Printf("[+] %s  %s\n", c.DisplaySTA(), clientSummary(c))
		}
		if time.Now().After(deadline) {
			return stations
		}
		time.Sleep(time.Second)
	}
}

// watchClients refreshes the inventory every couple of seconds until Ctrl+C.
func watchClients(client *drone.ControlClient, channel int) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	fmt.Printf("[*] Watching channel %d — press Ctrl+C to stop.\n", channel)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		stations, err := client.GetAllClients()
		if err != nil {
			fmt.Printf("[!] Failed to read the client table: %v\n", err)
		} else {
			stations = filterClients(stations)
			if clientsJSON {
				printClientsJSON(stations)
			} else {
				printClientTable(stations, channel)
			}
		}

		select {
		case <-sigCh:
			return
		case <-ticker.C:
		}
	}
}

// clientSummary is the one-line description used while collecting.
func clientSummary(c drone.Client) string {
	var parts []string
	if c.Associated {
		parts = append(parts, "associated "+c.DisplayBSSID())
	} else if c.Probed {
		parts = append(parts, "probing")
	} else {
		parts = append(parts, "seen")
	}
	if ssid := c.ProbeSSID(); ssid != "" {
		parts = append(parts, fmt.Sprintf("pnl=%q", ssid))
	}
	if c.HasRSSI {
		parts = append(parts, fmt.Sprintf("%d dBm", c.RSSI))
	}
	return strings.Join(parts, " · ")
}

// filterClients applies the --bssid / --assoc-only / --min-rssi filters and
// sorts the survivors the way an operator reads them: associated first, then
// strongest signal.
func filterClients(stations []drone.Client) []drone.Client {
	out := make([]drone.Client, 0, len(stations))

	for _, c := range stations {
		if clientsBSSID != "" && !strings.EqualFold(c.BSSID, clientsBSSID) {
			continue
		}
		if clientsAssoc && !c.Associated {
			continue
		}
		if clientsMinRSSI != 0 && (!c.HasRSSI || c.RSSI < clientsMinRSSI) {
			continue
		}
		out = append(out, c)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Associated != out[j].Associated {
			return out[i].Associated
		}
		si, sj := out[i].RSSI, out[j].RSSI
		if out[i].HasRSSI != out[j].HasRSSI {
			return out[i].HasRSSI
		}
		if si != sj {
			return si > sj
		}
		return out[i].STA < out[j].STA
	})

	return out
}

// printClientTable renders the inventory.
func printClientTable(stations []drone.Client, channel int) {
	fmt.Printf("\n[+] %d station(s) heard on channel %d:\n\n", len(stations), channel)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "#\tSTA\tSTATE\tBSSID\tPNL / SSID\tRSSI\tFRAMES\tLAST SEEN")
	fmt.Fprintln(w, "-\t---\t-----\t-----\t----------\t----\t------\t---------")

	for i, c := range stations {
		state := "probe"
		if c.Associated {
			state = "assoc"
		} else if !c.Probed {
			state = "seen"
		}

		bssid := c.DisplayBSSID()
		if bssid == "" {
			bssid = "-"
		}
		ssid := c.ProbeSSID()
		if ssid == "" {
			ssid = "-"
		}
		rssi := "n/a"
		if c.HasRSSI {
			rssi = fmt.Sprintf("%d dBm", c.RSSI)
		}

		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
			i+1, c.DisplaySTA(), state, bssid, ssid, rssi, c.Frames,
			formatAge(c.AgeMS))
	}
	w.Flush()
	fmt.Println()
}

// printClientsJSON emits one JSON object per station, matching the field names
// the daemon uses so a consumer can pipe the two formats together.
func printClientsJSON(stations []drone.Client) {
	for _, c := range stations {
		out := struct {
			STA        string `json:"sta"`
			BSSID      string `json:"bssid"`
			Associated bool   `json:"associated"`
			Probed     bool   `json:"probed"`
			SSID       string `json:"ssid"`
			SSIDHex    string `json:"ssid_hex"`
			RSSI       int    `json:"rssi"`
			HasRSSI    bool   `json:"has_rssi"`
			Frames     int    `json:"frames"`
			AgeMS      int64  `json:"age_ms"`
		}{
			STA:        c.DisplaySTA(),
			BSSID:      c.DisplayBSSID(),
			Associated: c.Associated,
			Probed:     c.Probed,
			SSID:       c.SSID,
			SSIDHex:    strings.ToLower(c.SSIDHex),
			RSSI:       c.RSSI,
			HasRSSI:    c.HasRSSI,
			Frames:     c.Frames,
			AgeMS:      c.AgeMS,
		}

		line, err := json.Marshal(out)
		if err != nil {
			fmt.Printf("[!] Failed to encode a station: %v\n", err)
			continue
		}
		fmt.Println(string(line))
	}
}

// formatAge renders a millisecond age the way a human scans it.
func formatAge(ms int64) string {
	if ms < 0 {
		ms = 0
	}
	switch {
	case ms < 1000:
		return fmt.Sprintf("%dms", ms)
	case ms < 60_000:
		return fmt.Sprintf("%.1fs", float64(ms)/1000)
	case ms < 3_600_000:
		return fmt.Sprintf("%dm%02ds", ms/60_000, (ms/1000)%60)
	default:
		return fmt.Sprintf("%dh%02dm", ms/3_600_000, (ms/60_000)%60)
	}
}

func init() {
	clientsCmd.Flags().IntVarP(&clientsChannel, "channel", "c", 6, "Wi-Fi channel to listen on (1-13)")
	clientsCmd.Flags().IntVarP(&clientsSeconds, "seconds", "s", 20, "How long to listen before printing the inventory")
	clientsCmd.Flags().BoolVar(&clientsJSON, "json", false, "Print one JSON object per station (machine readable)")
	clientsCmd.Flags().BoolVar(&clientsWatch, "watch", false, "Keep refreshing the inventory until Ctrl+C")
	clientsCmd.Flags().StringVarP(&clientsBSSID, "bssid", "b", "", "Only show stations seen with this BSSID")
	clientsCmd.Flags().BoolVar(&clientsAssoc, "assoc-only", false, "Only show stations that are associated")
	clientsCmd.Flags().IntVar(&clientsMinRSSI, "min-rssi", 0, "Only show stations at or above this RSSI (dBm)")
	clientsCmd.Flags().BoolVar(&clientsReset, "reset", false, "Clear the daemon's table before listening")
	clientsCmd.Flags().StringVarP(&clientsTarget, "target", "t", "", "Drone IP address")
	rootCmd.AddCommand(clientsCmd)
}
