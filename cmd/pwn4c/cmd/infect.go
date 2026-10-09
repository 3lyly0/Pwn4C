package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/3lyly0/Pwn4C/internal/exploit"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var infectCmd = &cobra.Command{
	Use:   "infect [target_ip]",
	Short: "Automates deployment on a stock Xiaomi Mi Router 4C",
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

		if err := exploit.RunInfection(targetIP, password); err != nil {
			fmt.Printf("[!] Infection failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("[+] Infection complete. Router is accessible via SSH.")
	},
}

func init() {
	rootCmd.AddCommand(infectCmd)
}
