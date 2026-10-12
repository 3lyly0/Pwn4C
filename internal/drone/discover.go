package drone

import (
	"encoding/json"
	"fmt"
	"net"
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

// Discover sends UDP broadcast packets and listens for Drone ANNOUNCE responses
func Discover(timeout time.Duration, ifaceName string) ([]DiscoveredDrone, error) {
	broadcastAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", DefaultBroadcastAddr, DefaultDiscoveryPort))
	if err != nil {
		return nil, fmt.Errorf("resolve broadcast address: %w", err)
	}

	// Listen on ephemeral port for unicast responses from drone
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}
	defer conn.Close()

	req := DiscoverRequest{
		Type:          "DISCOVER",
		Version:       ProtocolVersion,
		Client:        "pwn4c",
		ClientVersion: "0.1.0",
		Timestamp:     time.Now().Unix(),
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal discover request: %w", err)
	}

	// Broadcast request up to 3 times
	for i := 0; i < 3; i++ {
		_, err = conn.WriteToUDP(payload, broadcastAddr)
		if err != nil {
			// Some interfaces error on 255.255.255.255 if not bound, continue
		}
		time.Sleep(50 * time.Millisecond)
	}

	deadline := time.Now().Add(timeout)
	_ = conn.SetReadDeadline(deadline)

	var drones []DiscoveredDrone
	seen := make(map[string]bool)
	buf := make([]byte, 4096)

	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			break
		}

		var announce AnnounceResponse
		if err := json.Unmarshal(buf[:n], &announce); err != nil {
			continue
		}

		if announce.Type != "ANNOUNCE" {
			continue
		}

		hostIP, _, splitErr := net.SplitHostPort(addr.String())
		if splitErr != nil {
			hostIP = addr.String()
		}

		if seen[hostIP] {
			continue
		}
		seen[hostIP] = true

		drones = append(drones, DiscoveredDrone{
			IP:       hostIP,
			Port:     announce.ControlPort,
			Announce: announce,
		})
	}

	return drones, nil
}
