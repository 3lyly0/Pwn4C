package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/3lyly0/Pwn4C/internal/drone"
	"github.com/spf13/cobra"
)

var (
	upgradeImage    string
	upgradeBootWait int
	upgradeTarget   string
	upgradeSkipWait bool
)

var upgradeCmd = &cobra.Command{
	Use:   "upgrade [target_ip]",
	Short: "Update the drone firmware over the air from a sysupgrade image",
	Long: `Streams a Pwn4C sysupgrade image to the drone over the control channel and
flashes it with sysupgrade.

The image is served from a temporary HTTP server on this host; the drone
downloads it, verifies the size and SHA-256, and only then starts flashing —
a corrupted transfer can never reach the flash chip. After the flash the
router reboots; this command waits for the drone to come back online and
reports the running firmware version.

The drone must be reachable over the LAN link (usually 192.168.4.1).`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := upgradeTarget
		if len(args) > 0 {
			target = args[0]
		}
		target = resolveTargetOrExit(target)

		if upgradeImage == "" {
			fmt.Println("[!] Error: --image <sysupgrade.bin> is required.")
			os.Exit(1)
		}

		size, sha, err := drone.ComputeImageMeta(upgradeImage)
		if err != nil {
			fmt.Printf("[!] Cannot read image: %v\n", err)
			os.Exit(1)
		}
		if size < 512*1024 || size > 8*1024*1024 {
			fmt.Printf("[!] Image size %d bytes is outside the plausible 512KB-8MB sysupgrade range.\n", size)
			os.Exit(1)
		}

		fmt.Printf("[+] Image : %s\n", upgradeImage)
		fmt.Printf("    Size  : %d bytes\n", size)
		fmt.Printf("    SHA256: %s\n", sha)

		// The drone must be able to reach this host — resolve the
		// local IP through the same route the control channel uses.
		localIP, err := drone.LocalIPFor(target)
		if err != nil {
			fmt.Printf("[!] Cannot determine the local IP toward %s: %v\n", target, err)
			os.Exit(1)
		}

		server, err := drone.StartImageServer(upgradeImage)
		if err != nil {
			fmt.Printf("[!] Failed to start the image server: %v\n", err)
			os.Exit(1)
		}
		defer server.Close()

		imageURL := fmt.Sprintf("http://%s:%d/image", localIP, server.Port())
		fmt.Printf("[+] Serving the image at %s (allow inbound TCP %d in your firewall)\n",
			imageURL, server.Port())

		client := connectOrExit(target)
		defer client.Close()

		fmt.Println("[+] Sending UPGRADE command (the drone verifies size + SHA-256 before flashing)...")
		if err := client.Upgrade(imageURL, size, sha); err != nil {
			fmt.Printf("[!] Upgrade failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("[+] Image verified on the drone — flashing now.")
		fmt.Println("[*] The drone will reboot. Do not power it off.")
		_ = client.Close()

		if upgradeSkipWait {
			fmt.Println("[*] --no-wait given: re-run `pwn4c discover` in ~90 seconds to find the drone.")
			return
		}

		waitForDroneAfterUpgrade(target)
	},
}

// waitForDroneAfterUpgrade polls discovery until the drone is back, then
// reports the freshly booted firmware version.
func waitForDroneAfterUpgrade(target string) {
	fmt.Printf("[*] Waiting up to %ds for the drone to come back online...\n", upgradeBootWait)
	deadline := time.Now().Add(time.Duration(upgradeBootWait) * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(5 * time.Second)
		remaining := int(time.Until(deadline).Seconds())
		fmt.Printf("\r[*] Polling discover... (%ds remaining)   ", remaining)

		drones, err := drone.Discover(2*time.Second, "")
		if err != nil || len(drones) == 0 {
			continue
		}
		fmt.Println()

		for _, d := range drones {
			if d.IP != target {
				continue
			}
			st, err := droneStatusQuick(target)
			if err != nil {
				fmt.Printf("[+] Drone is back at %s (firmware %s)\n",
					target, d.Announce.FirmwareVersion)
				return
			}
			fmt.Printf("[+] Drone is back at %s\n", target)
			fmt.Printf("    Firmware : %s\n", st.FirmwareVersion)
			fmt.Printf("    Drone ID : %s\n", st.DroneID)
			fmt.Printf("    Uptime   : %ds\n", st.UptimeSeconds)
			return
		}
		// Found some drone, not our target — keep waiting.
	}
	fmt.Println("\n[!] The drone did not come back within the wait window.")
	fmt.Println("    Check the 192.168.4.0/24 link, then run: pwn4c discover --wait-timeout 120")
	os.Exit(1)
}

// droneStatusQuick fetches GET_STATUS telemetry without CLI noise.
func droneStatusQuick(target string) (*drone.StatusData, error) {
	client, err := drone.ConnectControl(target, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	return client.GetStatus()
}

func init() {
	upgradeCmd.Flags().StringVarP(&upgradeImage, "image", "i", "", "Path to the Pwn4C sysupgrade image to flash")
	upgradeCmd.Flags().StringVarP(&upgradeTarget, "target", "t", "", "Target drone IP (defaults to auto-discovery)")
	upgradeCmd.Flags().IntVar(&upgradeBootWait, "boot-wait", 300, "Seconds to wait for the drone to reboot and re-announce")
	upgradeCmd.Flags().BoolVar(&upgradeSkipWait, "no-wait", false, "Do not wait for the reboot; exit after handing over the image")
	rootCmd.AddCommand(upgradeCmd)
}
