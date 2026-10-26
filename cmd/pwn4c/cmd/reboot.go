package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	rebootTarget  string
	rebootYes     bool
	rebootNoWait  bool
	rebootTimeout int
)

var rebootCmd = &cobra.Command{
	Use:   "reboot [target_ip]",
	Short: "Reboot the drone over the control channel",
	Long: `Asks the daemon to reboot the router. The control session ends with the
request, so this command then waits for the drone to re-announce on the
192.168.4.0/24 link and prints its uptime once it is back.

Pass --yes to skip the confirmation prompt (scripts), or --no-wait to exit
immediately after sending the request.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := rebootTarget
		if len(args) > 0 {
			target = args[0]
		}
		target = resolveTargetOrExit(target)

		if !rebootYes {
			fmt.Printf("[*] Reboot the drone at %s now? [y/N]: ", target)
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			switch strings.ToLower(strings.TrimSpace(line)) {
			case "y", "yes":
			default:
				fmt.Println("[-] Aborted.")
				return
			}
		}

		client := connectOrExit(target)
		err := client.Reboot()
		client.Close()
		if err != nil {
			fmt.Printf("[!] Reboot failed: %v\n", err)
			os.Exit(1)
		}

		if rebootNoWait {
			fmt.Println("[+] Reboot requested. Re-run 'pwn4c discover' in ~90 seconds.")
			return
		}
		waitForDroneToReturn(target, rebootTimeout)
	},
}

func init() {
	rebootCmd.Flags().StringVarP(&rebootTarget, "target", "t", "", "Target drone IP (defaults to auto-discovery)")
	rebootCmd.Flags().BoolVarP(&rebootYes, "yes", "y", false, "Do not ask for confirmation")
	rebootCmd.Flags().BoolVar(&rebootNoWait, "no-wait", false, "Exit after sending the request")
	rebootCmd.Flags().IntVar(&rebootTimeout, "timeout", 120, "Seconds to wait for the drone to come back")
	rootCmd.AddCommand(rebootCmd)
}
