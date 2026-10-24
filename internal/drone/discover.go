package drone

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Default ports per api_reference.md
const (
	DefaultDiscoveryPort = 4440
	DefaultControlPort   = 4444
	DefaultStreamPort    = 5555
	DefaultBroadcastAddr = "255.255.255.255"
	ProtocolVersion      = 1
)

// DiscoverRequest represents the JSON packet broadcasted by Host
type DiscoverRequest struct {
	Type          string `json:"type"`
	Version       int    `json:"version"`
	Client        string `json:"client"`
	ClientVersion string `json:"client_version"`
	Timestamp     int64  `json:"timestamp"`
}

// RadioInfo represents radio metadata in ANNOUNCE or STATUS
type RadioInfo struct {
	Chipset       string `json:"chipset"`
	Band          string `json:"band"`
	Channels      []int  `json:"channels"`
	MaxTxPowerDbm int    `json:"max_tx_power_dbm"`
	State         string `json:"state"`
}

// AnnounceResponse represents the JSON response sent by Drone
type AnnounceResponse struct {
	Type            string    `json:"type"`
	Version         int       `json:"version"`
	DroneID         string    `json:"drone_id"`
	FirmwareVersion string    `json:"firmware_version"`
	Hardware        string    `json:"hardware"`
	UptimeSeconds   int64     `json:"uptime_seconds"`
	Capabilities    []string  `json:"capabilities"`
	Radio           RadioInfo `json:"radio"`
	ControlPort     int       `json:"control_port"`
	StreamPort      int       `json:"stream_port"`
}

// DiscoveredDrone contains Announce details plus the network address
type DiscoveredDrone struct {
	IP       string
	Port     int
	Announce AnnounceResponse
}

// probeTarget is one IPv4 address we are able to broadcast from.
type probeTarget struct {
	Interface string
	IP        net.IP
	Mask      net.IPMask
}

// probe is a live discovery socket bound to a single interface address.
type probe struct {
	target probeTarget
	conn   *net.UDPConn
	dsts   []*net.UDPAddr
}

// datagram is one received UDP payload with its source address.
type datagram struct {
	data []byte
	from net.Addr
}

// limitedBroadcast is the 255.255.255.255:4440 destination.
func limitedBroadcast() *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4bcast, Port: DefaultDiscoveryPort}
}

// Discover probes every usable IPv4 interface for listening drones.
//
// Sending a single packet to 255.255.255.255 is not enough on a multi-homed
// host (Hyper-V, WSL, VMware, VPN adapters): the kernel chooses the egress
// interface from the routing table, which is frequently not the one the drone
// is attached to. We therefore bind one socket per interface address and send
// both the subnet-directed broadcast and the limited broadcast from it, so
// every link gets a probe and the drone can reply unicast to the source
// address it saw.
//
// ifaceName restricts probing to a single interface (matched by name); an
// empty value probes all of them.
func Discover(timeout time.Duration, ifaceName string) ([]DiscoveredDrone, error) {
	targets, err := probeTargets(ifaceName)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, errors.New("no usable IPv4 interface found; connect a LAN cable or pass --interface")
	}

	payload, err := json.Marshal(DiscoverRequest{
		Type:          "DISCOVER",
		Version:       ProtocolVersion,
		Client:        "pwn4c",
		ClientVersion: "0.1.0",
		Timestamp:     time.Now().Unix(),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal discover request: %w", err)
	}

	probes, setupErrs := openProbes(targets)
	defer func() {
		for _, p := range probes {
			_ = p.conn.Close()
		}
	}()
	if len(probes) == 0 {
		return nil, fmt.Errorf("could not open a discovery socket: %w", errors.Join(setupErrs...))
	}

	replies := make(chan datagram, 64)
	for _, p := range probes {
		go readAnnounces(p.conn, replies)
	}

	// Three rounds, 50 ms apart — same cadence as the old single-socket probe.
	var sendErrs []error
	sent := 0
	for round := 0; round < 3; round++ {
		for _, p := range probes {
			for _, dst := range p.dsts {
				if _, err := p.conn.WriteToUDP(payload, dst); err != nil {
					sendErrs = append(sendErrs, fmt.Errorf("%s (%s -> %s): %w", p.target.Interface, p.target.IP, dst.IP, err))
					continue
				}
				sent++
			}
		}
		if round < 2 {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if sent == 0 {
		return nil, fmt.Errorf("discovery broadcast failed on every interface: %w", errors.Join(sendErrs...))
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	var drones []DiscoveredDrone
	seen := make(map[string]bool)

collect:
	for {
		select {
		case r := <-replies:
			drone, ok := parseAnnounce(r)
			if !ok || seen[drone.IP] {
				continue
			}
			seen[drone.IP] = true
			drones = append(drones, drone)
		case <-timer.C:
			break collect
		}
	}

	return drones, nil
}

// probeTargets enumerates up, non-loopback IPv4 interface addresses. When
// ifaceName is set only that interface is considered.
func probeTargets(ifaceName string) ([]probeTarget, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerate interfaces: %w", err)
	}

	var targets []probeTarget
	for _, ifi := range ifaces {
		if ifaceName != "" && !strings.EqualFold(ifi.Name, ifaceName) {
			continue
		}
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}
			targets = append(targets, probeTarget{
				Interface: ifi.Name,
				IP:        ip4,
				Mask:      ipnet.Mask,
			})
		}
	}

	if ifaceName != "" && len(targets) == 0 {
		return nil, fmt.Errorf("interface %q not found or has no usable IPv4 address", ifaceName)
	}

	return targets, nil
}

// openProbes binds one UDP socket per interface address.
func openProbes(targets []probeTarget) ([]*probe, []error) {
	var probes []*probe
	var errs []error

	for _, t := range targets {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: t.IP, Port: 0})
		if err != nil {
			errs = append(errs, fmt.Errorf("%s (%s): %w", t.Interface, t.IP, err))
			continue
		}

		dsts := []*net.UDPAddr{limitedBroadcast()}
		if bcast := subnetBroadcast(t.IP, t.Mask); bcast != nil && !bcast.Equal(t.IP) {
			dsts = append(dsts, &net.UDPAddr{IP: bcast, Port: DefaultDiscoveryPort})
		}

		probes = append(probes, &probe{target: t, conn: conn, dsts: dsts})
	}

	return probes, errs
}

// readAnnounces forwards every datagram received on conn to out until the
// socket is closed or the read deadline expires.
func readAnnounces(conn *net.UDPConn, out chan<- datagram) {
	buf := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		select {
		case out <- datagram{data: data, from: addr}:
		default:
			// Reader is saturated; drop rather than block the socket.
		}
	}
}

// parseAnnounce validates one received datagram and converts it to a drone.
func parseAnnounce(r datagram) (DiscoveredDrone, bool) {
	var resp AnnounceResponse
	if err := json.Unmarshal(r.data, &resp); err != nil {
		return DiscoveredDrone{}, false
	}
	if resp.Type != "ANNOUNCE" {
		return DiscoveredDrone{}, false
	}

	host, _, err := net.SplitHostPort(r.from.String())
	if err != nil {
		host = r.from.String()
	}

	port := resp.ControlPort
	if port == 0 {
		port = DefaultControlPort
	}

	return DiscoveredDrone{IP: host, Port: port, Announce: resp}, true
}

// subnetBroadcast returns the subnet-directed broadcast address for an IPv4
// address and netmask (e.g. 192.168.4.185/24 -> 192.168.4.255). It returns nil
// when the mask is not a usable IPv4 mask.
func subnetBroadcast(ip net.IP, mask net.IPMask) net.IP {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}

	m := mask
	if len(m) == net.IPv6len {
		m = m[12:]
	}
	if len(m) != net.IPv4len {
		return nil
	}

	bcast := make(net.IP, net.IPv4len)
	for i := range bcast {
		bcast[i] = ip4[i] | ^m[i]
	}
	return bcast
}
