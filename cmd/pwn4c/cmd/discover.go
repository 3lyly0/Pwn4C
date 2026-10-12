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
	discoverTimeout int
)

var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Scan local subnet for active Pwn4C drone implants",
	Long:  "Broadcasts discovery beacons over the local network interface to detect listening Pwn4C implants.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("[+] Broadcasting discovery probes (timeout %ds)...\n", discoverTimeout)

		drones, err := drone.Discover(time.Duration(discoverTimeout)*time.Second, "")
		if err != nil {
			fmt.Printf("[!] Discovery error: %v\n", err)
			os.Exit(1)
		}

		if len(drones) == 0 {
			fmt.Println("[-] No active Pwn4C drones discovered on the local subnet.")
			return
		}

		fmt.Printf("\n[+] Found %d drone(s):\n\n", len(drones))
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "IP ADDRESS\tDRONE ID\tSTATE\tCHIP\tFIRMWARE\tUPTIME")
		fmt.Fprintln(w, "----------\t--------\t-----\t----\t--------\t------")

		for _, d := range drones {
			uptime := time.Duration(d.Announce.UptimeSeconds) * time.Second
			fmt.Fprintf(w, "%s:%d\t%s\t%s\t%s\t%s\t%s\n",
				d.IP,
				d.Announce.ControlPort,
				d.Announce.DroneID,
				d.Announce.Radio.State,
				d.Announce.Radio.Chipset,
				d.Announce.FirmwareVersion,
				uptime.Round(time.Second).String(),
			)
		}
		w.Flush()
		fmt.Println()
	},
}

func init() {
	discoverCmd.Flags().IntVarP(&discoverTimeout, "timeout", "t", 3, "Discovery timeout in seconds")
	rootCmd.AddCommand(discoverCmd)
}
