package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/3lyly0/Pwn4C/internal/exploit"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var infectFirmwarePath string

var infectCmd = &cobra.Command{
	Use:   "infect [target_ip]",
	Short: "Automates deployment on a stock Xiaomi Mi Router 4C (air-gapped capable)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetIP := args[0]

		fmt.Printf("[*] Target: %s\n", targetIP)
		fmt.Print("[*] Enter router admin password: ")

		bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			fmt.Printf("[!] Failed to read password: %v\n", err)
			os.Exit(1)
		}

		password := strings.TrimSpace(string(bytePassword))

		if err := exploit.RunInfection(targetIP, password, infectFirmwarePath); err != nil {
			fmt.Printf("[!] Infection failed: %v\n", err)
			os.Exit(1)
		}

		if infectFirmwarePath != "" {
			fmt.Println("[+] Flash transfer complete. Router should reboot into Pwn4C OS on 192.168.4.1.")
		} else {
			fmt.Println("[+] Infection complete.")
		}
	},
}

func init() {
	infectCmd.Flags().StringVarP(&infectFirmwarePath, "flash", "f", "", "Path to Pwn4C sysupgrade.bin for direct air-gapped flash to OS1 (primary deployment path)")
	rootCmd.AddCommand(infectCmd)
}
