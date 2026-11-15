package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/3lyly0/Pwn4C/internal/drone"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	connectPassword   string
	connectBSSID      string
	connectEncryption string
	connectTimeout    int
	connectTarget     string
	connectNoShare    bool
	connectMAC        string
	connectRandomMAC  bool
	connectRetry      int
)

// randomLocallyAdministeredMAC returns a unicast, locally-administered address.
func randomLocallyAdministeredMAC() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[0] = (b[0] & 0xfe) | 0x02 // clear multicast, set local bit
	return net.HardwareAddr(b[:]).String(), nil
}

// waitForWifiJoin polls WIFI_STATUS until the station is joined, and reports
// whether the caller may retry (transient failure) or must stop (bad key).
func waitForWifiJoin(client *drone.ControlClient, timeoutSec int, share bool) (bool, bool) {
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
	lastState := ""
	var last *drone.WifiLinkStatus
	retryable := true

	for {
		st, err := client.WifiStatus()
		if err == nil {
			last = st

			// Only print on transitions: the daemon is polled once a second.
			if st.State != lastState {
				lastState = st.State
				switch st.State {
				case "associating":
					fmt.Println("[*] Associated; verifying WPA key (4-way handshake)...")
				case "dhcp":
					fmt.Println("[+] WPA key accepted; waiting for a DHCP lease...")
				case "auth_failed":
					fmt.Println("[!] Authentication failed: the access point rejected the key.")
					fmt.Println("    Check the password and the security mode (psk2 for WPA2, sae for WPA3).")
					retryable = false
					return false, retryable
				case "connect_failed":
					detail := st.ErrorDetail
					if detail == "" {
						detail = "association failure"
					}
					fmt.Printf("[!] Association failed (%s); the key was not rejected.\n", detail)
					return false, retryable
				}
			}

			// Success requires both a completed handshake and an address.
			if st.Connected && st.IP != "" {
				fmt.Println("[+] Drone joined the network:")
				fmt.Printf("    SSID     : %s\n", st.SSID)
				fmt.Printf("    BSSID    : %s\n", st.BSSID)
				fmt.Printf("    Channel  : %d\n", st.Channel)
				if st.Iface != "" {
					fmt.Printf("    Iface    : %s\n", st.Iface)
				}
				fmt.Printf("    IP (wan) : %s\n", st.IP)
				if st.Sharing {
					fmt.Println("    Sharing  : enabled — hosts on 192.168.4.0/24 are NATed through this link")
				} else if share {
					fmt.Println("    Sharing  : requested but not active — run 'pwn4c wifi-status'")
				} else {
					fmt.Println("    Sharing  : disabled (--no-share); the LAN stays isolated")
				}
				return true, false
			}
		}

		if time.Now().After(deadline) {
			switch {
			case last != nil && last.Connected:
				fmt.Println("[!] Joined the access point, but no DHCP lease was assigned.")
				fmt.Println("    The WPA key is correct; check the upstream DHCP server.")
			case last != nil && last.Associated:
				fmt.Println("[!] Associated, but the WPA handshake never completed.")
				fmt.Println("    Check the password and the security mode, then retry.")
			case last != nil && last.ErrorDetail != "":
				fmt.Printf("[!] Timed out: %s\n", last.ErrorDetail)
			default:
				fmt.Println("[!] Timed out waiting for association. Check the SSID/password, then retry.")
			}
			return false, retryable
		}
		time.Sleep(1 * time.Second)
	}
}

var connectCmd = &cobra.Command{
	Use:   "connect <ssid> [password]",
	Short: "Join the drone to an upstream Wi-Fi network (station mode)",
	Long: `Configures the drone radio as a station and associates it with the given
network. The upstream link rides the wan interface, so the drone itself gains
connectivity while the control channel stays on the Ethernet cable.

By default the drone also NATs its LAN (192.168.4.0/24) behind that link, so a
host plugged into a LAN port reaches the internet through the drone's Wi-Fi.
The image ships without a firewall, so this is a single masquerade rule
installed by /usr/lib/pwn4c/share.sh; pass --no-share to leave the LAN isolated
and give the drone upstream access only.

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
			// Do not trim spaces: a WPA passphrase may legitimately begin or
			// end with one. Only strip the line terminator.
			password = strings.TrimRight(string(raw), "\r\n")
		}

		if password != "" {
			hexPSK := len(password) == 64
			if hexPSK {
				_, err := hex.DecodeString(password)
				hexPSK = err == nil
			}
			if !hexPSK && (len(password) < 8 || len(password) > 63) {
				fmt.Println("[!] WPA passphrase must be 8-63 characters (or a 64-hex PSK).")
				os.Exit(1)
			}
		}

		if _, err := net.ParseMAC(ssid); err == nil && connectBSSID == "" {
			fmt.Printf("[i] Note: '%s' looks like a BSSID (MAC address). Wi-Fi connects using the network's SSID name (e.g. \"MyNetwork\").\n", ssid)
		}

		mac := connectMAC
		if connectRandomMAC {
			generated, err := randomLocallyAdministeredMAC()
			if err != nil {
				fmt.Printf("[!] Failed to generate a random MAC: %v\n", err)
				os.Exit(1)
			}
			mac = generated
		}
		if mac != "" {
			if _, err := net.ParseMAC(mac); err != nil {
				fmt.Printf("[!] Invalid station MAC %q: %v\n", mac, err)
				os.Exit(1)
			}
		}

		label := ssid
		if password == "" {
			label += " (open network)"
		}
		share := !connectNoShare
		attempts := 1
		if connectRetry > 0 {
			attempts += connectRetry
		}

		for attempt := 1; attempt <= attempts; attempt++ {
			if attempt > 1 {
				fmt.Printf("[*] Retry %d/%d...\n", attempt-1, connectRetry)
			}
			fmt.Printf("[+] Joining %s...\n", label)
			if mac != "" {
				fmt.Printf("[*] Station MAC: %s\n", mac)
			}
			fmt.Println("[*] Restarting the radio and applying the station profile (can take ~30s)...")
			if err := client.WifiConnectWithMAC(ssid, password, connectBSSID,
				connectEncryption, mac, share); err != nil {
				fmt.Printf("[!] Connect failed: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("[*] Association in progress (monitor mode is unavailable while joined)...")
			ok, retryable := waitForWifiJoin(client, connectTimeout, share)
			if ok {
				return
			}
			if !retryable || attempt == attempts {
				fmt.Println("    The station profile stays configured; pwn4c wifi-status shows the current state.")
				os.Exit(1)
			}

			// A CONN_FAILED/TEMP-DISABLED network is ignored by the supplicant
			// for minutes unless wifi is restarted, which WifiConnect does.
			fmt.Println("[*] Transient failure; restarting the station profile...")
		}
	},
}

func init() {
	connectCmd.Flags().StringVarP(&connectPassword, "password", "p", "", "WPA passphrase (omit to be asked; empty = open network)")
	connectCmd.Flags().StringVar(&connectBSSID, "bssid", "", "Pin a specific AP by BSSID")
	connectCmd.Flags().StringVar(&connectEncryption, "encryption", "", "Override UCI encryption (psk2, psk, psk-mixed, sae, sae-mixed)")
	connectCmd.Flags().StringVar(&connectMAC, "mac", "", "Station MAC address to use for this network")
	connectCmd.Flags().BoolVar(&connectRandomMAC, "random-mac", false, "Use a random locally-administered station MAC")
	connectCmd.Flags().IntVar(&connectRetry, "retry", 0, "Retry transient association failures N extra times")
	connectCmd.Flags().IntVar(&connectTimeout, "timeout", 60, "Seconds to wait for association and DHCP")
	connectCmd.Flags().BoolVar(&connectNoShare, "no-share", false, "Do not NAT the drone's LAN behind the upstream link")
	connectCmd.Flags().StringVarP(&connectTarget, "target", "t", "", "Target drone IP (defaults to auto-discovery)")
	rootCmd.AddCommand(connectCmd)
}
