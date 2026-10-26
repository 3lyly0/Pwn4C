package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/3lyly0/Pwn4C/internal/drone"
	"github.com/spf13/cobra"
)

var (
	statusTarget  string
	statusTimeout int
)

var statusCmd = &cobra.Command{
	Use:   "status [target_ip]",
	Short: "Query status and health of the drone TCP control channel",
	Long:  "Sends telemetry probe packets over the TCP control channel (port 4444) to evaluate link health and radio state.",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := statusTarget
		if len(args) > 0 {
			target = args[0]
		}

		if target == "" {
			fmt.Println("[*] No target specified, searching for active drones...")
			drones, err := drone.Discover(2*time.Second, "")
			if err != nil || len(drones) == 0 {
				fmt.Println("[!] No drone discovered. Please specify target IP directly (e.g. pwn4c status 192.168.4.1).")
				os.Exit(1)
			}
			target = drones[0].IP
			fmt.Printf("[+] Discovered drone at %s\n", target)
		}

		fmt.Printf("[+] Connecting to drone at %s:%d...\n", target, drone.DefaultControlPort)
		client, err := drone.ConnectControl(target, time.Duration(statusTimeout)*time.Second)
		if err != nil {
			fmt.Printf("[!] Failed to connect to control port: %v\n", err)
			os.Exit(1)
		}
		defer client.Close()

		st, err := client.GetStatus()
		if err != nil {
			fmt.Printf("[!] Failed to retrieve status: %v\n", err)
			os.Exit(1)
		}

		uptime := time.Duration(st.UptimeSeconds) * time.Second

		fmt.Println("\n================ DRONE TELEMETRY ================")
		fmt.Printf(" Drone ID         : %s\n", st.DroneID)
		fmt.Printf(" Firmware         : %s\n", st.FirmwareVersion)
		fmt.Printf(" State            : %s\n", st.State)
		fmt.Printf(" Monitor Active   : %t\n", st.MonitorActive)
		fmt.Printf(" Current Channel  : %d\n", st.Channel)
		fmt.Printf(" Uptime           : %s\n", uptime.Round(time.Second).String())
		fmt.Printf(" CPU Temp         : %d °C\n", st.CPUTempCelsius)
		fmt.Printf(" Free RAM         : %d MB\n", st.FreeRAMBytes/(1024*1024))
		fmt.Printf(" TX Queue         : %d / %d\n", st.TxQueueDepth, st.TxQueueMax)
		fmt.Printf(" RX Frames        : %d\n", st.RxFrames)
		fmt.Printf(" TX Stream Frames : %d\n", st.TxFrames)
		if st.InjectFrames != nil {
			fmt.Printf(" Injected Frames  : %d\n", *st.InjectFrames)
		}
		fmt.Printf(" Ring Overruns    : %d\n", st.RingOverruns)
		fmt.Printf(" Inject Failures  : %d\n", st.InjectFailures)
		fmt.Printf(" Kernel Drops     : %d\n", st.KernelDrops)
		fmt.Printf(" Iface Recoveries : %d\n", st.IfaceRecoveries)
		fmt.Println("==================================================")
	},
}

func init() {
	statusCmd.Flags().StringVarP(&statusTarget, "target", "t", "", "Target drone IP (defaults to auto-discovery)")
	statusCmd.Flags().IntVar(&statusTimeout, "timeout", 5, "Connection timeout in seconds")
	rootCmd.AddCommand(statusCmd)
}
