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
	networksDwell  int
	networksTarget string
	networksJSON   bool
)

var networksCmd = &cobra.Command{
	Use:     "networks [target_ip]",
	Aliases: []string{"scan"},
	Short:   "Survey nearby Wi-Fi networks from the drone's monitor radio",
	Long: `Places the drone radio in monitor mode, sweeps the 2.4 GHz band and reports
every access point heard, sorted by signal strength.

Hidden networks are reported with their advertised SSID length — most APs
blank the SSID information element but keep its real size, which is enough to
recognize them later.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := networksTarget
		if len(args) > 0 {
			target = args[0]
		}
		target = resolveTargetOrExit(target)

		client := connectOrExit(target)
		defer client.Close()

		fmt.Printf("[+] Surveying nearby networks (dwell %dms, this blocks the drone briefly)...\n",
			networksDwell)
		nets, err := client.ScanNetworks(networksDwell)
		if err != nil {
			fmt.Printf("[!] Scan failed: %v\n", err)
			os.Exit(1)
		}

		if networksJSON {
			for _, n := range nets {
				fmt.Printf("{\"ssid\":%q,\"bssid\":%q,\"channel\":%d,\"signal_dbm\":%d,\"hidden\":%t,\"ssid_len\":%d}\n",
					n.SSID, n.BSSID, n.Channel, n.SignalDbm, n.Hidden, n.SSIDLength)
			}
			return
		}

		if len(nets) == 0 {
			fmt.Println("[-] No networks heard. Try a longer dwell (--dwell 8000) or check the antenna environment.")
			return
		}

		printNetworkTable(nets)
	},
}

// printNetworkTable renders the survey the way the operator reads it: hidden
// networks show their advertised SSID length instead of an empty name.
func printNetworkTable(nets []drone.WirelessNetwork) {
	fmt.Printf("\n[+] %d network(s) heard:\n\n", len(nets))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "#\tSSID\tBSSID\tCH\tSIGNAL\tTYPE")
	fmt.Fprintln(w, "-\t----\t-----\t--\t------\t----")

	for i, n := range nets {
		ssid := n.SSID
		typ := "AP"
		if n.Hidden {
			if n.SSIDLength > 0 {
				ssid = fmt.Sprintf("<hidden · %d chars>", n.SSIDLength)
			} else {
				ssid = "<hidden · unknown length>"
			}
			typ = "hidden"
		}
		signal := fmt.Sprintf("%d dBm", n.SignalDbm)
		if n.SignalDbm == 0 {
			signal = "n/a"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%s\t%s\n",
			i+1, ssid, n.BSSID, n.Channel, signal, typ)
	}
	w.Flush()
	fmt.Println()
}

// resolveTargetOrExit auto-discovers a drone when no explicit IP is given.
func resolveTargetOrExit(target string) string {
	if target != "" {
		return target
	}
	fmt.Println("[*] No target specified, searching for active drones...")
	drones, err := drone.Discover(2*time.Second, "")
	if err != nil || len(drones) == 0 {
		fmt.Println("[!] No drone discovered. Please specify target IP directly.")
		os.Exit(1)
	}
	fmt.Printf("[+] Discovered drone at %s\n", drones[0].IP)
	return drones[0].IP
}

// connectOrExit opens the control channel or exits with a readable error.
func connectOrExit(target string) *drone.ControlClient {
	fmt.Printf("[+] Connecting to drone at %s:%d...\n", target, drone.DefaultControlPort)
	client, err := drone.ConnectControl(target, 5*time.Second)
	if err != nil {
		fmt.Printf("[!] Failed to connect: %v\n", err)
		os.Exit(1)
	}
	return client
}

func init() {
	networksCmd.Flags().IntVarP(&networksDwell, "dwell", "d", 4000, "Survey duration per call in milliseconds (1000-15000)")
	networksCmd.Flags().StringVarP(&networksTarget, "target", "t", "", "Target drone IP (defaults to auto-discovery)")
	networksCmd.Flags().BoolVar(&networksJSON, "json", false, "Print one JSON object per network (machine readable)")
	rootCmd.AddCommand(networksCmd)
}
