package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/3lyly0/Pwn4C/internal/drone"
	"github.com/spf13/cobra"
)

var (
	discoverTimeout     int
	discoverInterface   string
	discoverWaitTimeout int
	discoverRetryEvery  int
	discoverNoWait      bool
)

// defaultWaitTimeout is how long `pwn4c discover` keeps probing for a drone
// before giving up. The old behaviour — one 3s probe round, then exit — made
// operators retype the command over and over while a drone was still booting
// after a flash.
const defaultWaitTimeout = 15

var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Scan local subnet for active Pwn4C drone implants",
	Long: `Broadcasts discovery beacons over the local network interface to detect
listening Pwn4C implants.

By default the probe keeps retrying for up to 15 seconds, so a drone that is
still booting after a flash is picked up as soon as it comes online — no need
to retype the command. Use --wait-timeout 0 to wait forever, or --no-wait to
restore the old single-round behaviour.`,
	Run: func(cmd *cobra.Command, args []string) {
		ifaceLabel := "all IPv4 interfaces"
		if discoverInterface != "" {
			ifaceLabel = discoverInterface
		}

		deadline := time.Time{}
		if !discoverNoWait {
			if discoverWaitTimeout > 0 {
				deadline = time.Now().Add(time.Duration(discoverWaitTimeout) * time.Second)
			}
		}

		attempt := 0
		for {
			attempt++
			if attempt == 1 {
				fmt.Printf("[+] Probing %s (timeout %ds)...\n", ifaceLabel, discoverTimeout)
			} else {
				fmt.Printf("\r[+] Probing %s (attempt %d, retry every %ds)...", ifaceLabel, attempt, discoverRetryEvery)
			}

			drones, err := drone.Discover(time.Duration(discoverTimeout)*time.Second, discoverInterface)
			if err != nil {
				fmt.Printf("\n[!] Discovery error: %v\n", err)
				os.Exit(1)
			}

			if len(drones) > 0 {
				if attempt > 1 {
					fmt.Println()
				}
				printDroneTable(drones)
				return
			}

			if discoverNoWait || (!deadline.IsZero() && !time.Now().Before(deadline)) {
				break
			}
			time.Sleep(time.Duration(discoverRetryEvery) * time.Second)
		}

		fmt.Println("[-] No active Pwn4C drones discovered on the local subnet.")
		fmt.Println("    If the drone is reachable (ping 192.168.4.1), retry with: pwn4c discover --interface <name>")
		fmt.Println("    Windows: run `Get-NetIPAddress -AddressFamily IPv4` to list interface names.")
	},
}

func printDroneTable(drones []drone.DiscoveredDrone) {
	fmt.Printf("\n[+] Found %d drone(s):\n\n", len(drones))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "IP ADDRESS\tDRONE ID\tSTATE\tCHIP\tFIRMWARE\tUPTIME")
	fmt.Fprintln(w, "----------\t--------\t-----\t----\t--------\t------")

	for _, d := range drones {
		uptime := time.Duration(d.Announce.UptimeSeconds) * time.Second
		fmt.Fprintf(w, "%s:%d\t%s\t%s\t%s\t%s\t%s\n",
			d.IP,
			d.Port,
			d.Announce.DroneID,
			d.Announce.Radio.State,
			d.Announce.Radio.Chipset,
			d.Announce.FirmwareVersion,
			uptime.Round(time.Second).String(),
		)
	}
	w.Flush()
	fmt.Println()
}

func init() {
	discoverCmd.Flags().IntVarP(&discoverTimeout, "timeout", "t", 3, "Per-round discovery probe timeout in seconds")
	discoverCmd.Flags().StringVarP(&discoverInterface, "interface", "i", "", "Only probe this network interface (default: all IPv4 interfaces)")
	discoverCmd.Flags().IntVar(&discoverWaitTimeout, "wait-timeout", defaultWaitTimeout, "Keep retrying until this many seconds (0 = wait forever)")
	discoverCmd.Flags().IntVar(&discoverRetryEvery, "retry-every", 2, "Seconds between probe rounds while waiting")
	discoverCmd.Flags().BoolVar(&discoverNoWait, "no-wait", false, "Single probe round, exit immediately when nothing answers")
	rootCmd.AddCommand(discoverCmd)
}
