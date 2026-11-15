package drone

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// RogueAPParams describes the twin to start.
//
// The daemon runs hostapd on a dedicated `__ap` vif on the same phy as the
// monitor, so the twin must live on the same channel as an active capture.
// An empty Passphrase produces an open network; 8-63 characters produce
// WPA2-PSK with CCMP.
type RogueAPParams struct {
	SSID       string
	BSSID      string
	Channel    int
	Passphrase string
	Hidden     bool
}

// RogueAPData is the START_ROGUE_AP / STOP_ROGUE_AP / GET_ROGUE_AP payload.
//
// The daemon reports facts: whether the twin is up, its security mode, the
// dedicated interface and subnet, how many stations hostapd has associated,
// and whether the capture that was running when it started is still active.
type RogueAPData struct {
	Active        bool   `json:"active"`
	SSID          string `json:"ssid"`
	BSSID         string `json:"bssid"`
	Channel       int    `json:"channel"`
	Hidden        bool   `json:"hidden"`
	Security      string `json:"security"`
	Interface     string `json:"interface"`
	IP            string `json:"ip"`
	Clients       int    `json:"clients"`
	UptimeSec     int64  `json:"uptime_sec"`
	Hostapd       bool   `json:"hostapd"`
	Dnsmasq       bool   `json:"dnsmasq"`
	MonitorActive bool   `json:"monitor_active"`
}

// ValidateRogueAPParams mirrors the daemon's checks so the CLI fails before
// opening a control connection.
func ValidateRogueAPParams(p RogueAPParams) error {
	if n := len(p.SSID); n < 1 || n > 32 {
		return fmt.Errorf("SSID must be 1-32 bytes (got %d)", n)
	}
	hw, err := net.ParseMAC(p.BSSID)
	if err != nil {
		return fmt.Errorf("invalid BSSID %q: %w", p.BSSID, err)
	}
	if len(hw) != 6 {
		return fmt.Errorf("invalid BSSID %q: not 6 octets", p.BSSID)
	}
	if hw[0]&0x01 != 0 {
		return fmt.Errorf("BSSID %q is a group address", p.BSSID)
	}
	if p.Channel < 1 || p.Channel > 13 {
		return fmt.Errorf("channel must be between 1 and 13")
	}
	if p.Passphrase != "" {
		if n := len(p.Passphrase); n < 8 || n > 63 {
			return fmt.Errorf("passphrase must be 8-63 characters (or empty for an open AP)")
		}
	}
	return nil
}

// StartRogueAP brings the twin up and returns its state.
func (c *ControlClient) StartRogueAP(p RogueAPParams) (*RogueAPData, error) {
	if err := ValidateRogueAPParams(p); err != nil {
		return nil, err
	}

	params := map[string]interface{}{
		"ssid":    p.SSID,
		"bssid":   p.BSSID,
		"channel": p.Channel,
		"hidden":  p.Hidden,
	}
	if p.Passphrase != "" {
		params["passphrase"] = p.Passphrase
	}

	return c.rogueCommand("START_ROGUE_AP", params)
}

// StopRogueAP tears the twin down. It is idempotent: stopping a twin that is
// not running is not an error.
func (c *ControlClient) StopRogueAP() (*RogueAPData, error) {
	return c.rogueCommand("STOP_ROGUE_AP", map[string]interface{}{})
}

// GetRogueAP reads the twin's current state.
func (c *ControlClient) GetRogueAP() (*RogueAPData, error) {
	return c.rogueCommand("GET_ROGUE_AP", map[string]interface{}{})
}

func (c *ControlClient) rogueCommand(cmd string, params map[string]interface{}) (*RogueAPData, error) {
	resp, err := c.SendCommand(cmd, params)
	if err != nil {
		return nil, err
	}
	if resp.Status != "ok" {
		if resp.Error != nil {
			return nil, fmt.Errorf("%s: %s: %s", cmd, resp.Error.Code, resp.Error.Message)
		}
		return nil, fmt.Errorf("%s failed with status %q", cmd, resp.Status)
	}

	var out RogueAPData
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, fmt.Errorf("decode %s: %w", cmd, err)
	}
	return &out, nil
}

// DisplayBSSID returns the twin's BSSID in the lowercase form the CLI prints.
func (r RogueAPData) DisplayBSSID() string {
	return strings.ToLower(r.BSSID)
}

// IsWPA reports whether the twin requires a passphrase.
func (r RogueAPData) IsWPA() bool {
	return r.Security == "wpa2-psk"
}
