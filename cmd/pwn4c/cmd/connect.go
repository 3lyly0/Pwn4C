package cmd

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	connectPassword   string
	connectBSSID      string
	connectEncryption string
	connectTimeout    int
	connectTarget     string
)

var connectCmd = &cobra.Command{
	Use:   "connect <ssid> [password]",
	Short: "Join the drone to an upstream Wi-Fi network (station mode)",
	Long: `Configures the drone radio as a station and associates it with the given
network. The upstream link rides the wan interface, so the drone itself gains
connectivity while the control channel stays on the Ethernet cable.

Hidden networks work the same way: pass the SSID and the drone will scan for
it by name. If the password flag is omitted, the password is asked for
interactively (hidden input); an empty password joins an open network.

Association is asynchronous — this command polls WIFI_STATUS until the link
is up (or --timeout expires) and then prints the assigned IP.`,
	Args: cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		ssid := args[0]
		target := connectTarget
		target = resolveTargetOrExit(target)

		client := connectOrExit(target)
		defer client.Close()

		password := connectPassword
		if len(args) == 2 && !cmd.Flags().Changed("password") {
			password = args[1]
		} else if !cmd.Flags().Changed("password") {
			// Ask interactively; empty answer = open network.
			fmt.Print("[*] Enter Wi-Fi password (empty = open network): ")
			raw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				fmt.Printf("[!] Failed to read password: %v\n", err)
				os.Exit(1)
			}
			password = strings.TrimSpace(string(raw))
		}

		if password != "" && (len(password) < 8 || len(password) > 63) {
			fmt.Println("[!] WPA passphrase must be 8-63 characters.")
			os.Exit(1)
		}

		if _, err := net.ParseMAC(ssid); err == nil && connectBSSID == "" {
			fmt.Printf("[i] Note: '%s' looks like a BSSID (MAC address). Wi-Fi connects using the network's SSID name (e.g. \"Test Network 123\").\n", ssid)
		}
		label := ssid
		if password == "" {
			label += " (open network)"
		}
		fmt.Printf("[+] Joining %s...\n", label)
		if err := client.WifiConnect(ssid, password, connectBSSID, connectEncryption); err != nil {
			fmt.Printf("[!] Connect failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("[*] Association in progress (monitor mode is unavailable while joined)...")
		deadline := time.Now().Add(time.Duration(connectTimeout) * time.Second)
		for {
			st, err := client.WifiStatus()
			if err == nil && st.Connected {
				fmt.Println("[+] Drone joined the network:")
				fmt.Printf("    SSID     : %s\n", st.SSID)
				fmt.Printf("    BSSID    : %s\n", st.BSSID)
				fmt.Printf("    Channel  : %d\n", st.Channel)
				fmt.Printf("    IP (wan) : %s\n", st.IP)
				return
			}
			if time.Now().After(deadline) {
				fmt.Println("[!] Timed out waiting for association. Check the SSID/password, then retry.")
				fmt.Println("    The station profile stays configured; pwn4c wifi-status shows the current state.")
				os.Exit(1)
			}
			time.Sleep(2 * time.Second)
		}
	},
}

func init() {
	connectCmd.Flags().StringVarP(&connectPassword, "password", "p", "", "WPA passphrase (omit to be asked; empty = open network)")
	connectCmd.Flags().StringVar(&connectBSSID, "bssid", "", "Pin a specific AP by BSSID")
	connectCmd.Flags().StringVar(&connectEncryption, "encryption", "", "Override UCI encryption (psk2, psk, sae, sae-mixed, psk2-mixed)")
	connectCmd.Flags().IntVar(&connectTimeout, "timeout", 45, "Seconds to wait for association")
	connectCmd.Flags().StringVarP(&connectTarget, "target", "t", "", "Target drone IP (defaults to auto-discovery)")
	rootCmd.AddCommand(connectCmd)
}
