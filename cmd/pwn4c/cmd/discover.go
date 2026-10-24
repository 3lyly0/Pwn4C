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
	discoverTimeout   int
	discoverInterface string
)

var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Scan local subnet for active Pwn4C drone implants",
	Long:  "Broadcasts discovery beacons over the local network interface to detect listening Pwn4C implants.",
	Run: func(cmd *cobra.Command, args []string) {
		if discoverInterface != "" {
			fmt.Printf("[+] Probing interface %s (timeout %ds)...\n", discoverInterface, discoverTimeout)
		} else {
			fmt.Printf("[+] Probing all IPv4 interfaces (timeout %ds)...\n", discoverTimeout)
		}

		drones, err := drone.Discover(time.Duration(discoverTimeout)*time.Second, discoverInterface)
		if err != nil {
			fmt.Printf("[!] Discovery error: %v\n", err)
			os.Exit(1)
		}

		if len(drones) == 0 {
			fmt.Println("[-] No active Pwn4C drones discovered on the local subnet.")
			fmt.Println("    If the drone is reachable (ping 192.168.4.1), retry with: pwn4c discover --interface <name>")
			fmt.Println("    Windows: run `Get-NetIPAddress -AddressFamily IPv4` to list interface names.")
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
	},
}

func init() {
	discoverCmd.Flags().IntVarP(&discoverTimeout, "timeout", "t", 3, "Discovery timeout in seconds")
	discoverCmd.Flags().StringVarP(&discoverInterface, "interface", "i", "", "Only probe this network interface (default: all IPv4 interfaces)")
	rootCmd.AddCommand(discoverCmd)
}
