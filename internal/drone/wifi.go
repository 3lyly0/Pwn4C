package drone

import (
	"encoding/json"
	"fmt"
	"strings"
)

// WirelessNetwork is one AP entry in a WIFI_SCAN survey response. Hidden
// networks carry an empty SSID with Hidden=true; SSIDLength reports the
// advertised IE length when the AP broadcasts it (many hidden APs do).
type WirelessNetwork struct {
	SSID       string `json:"ssid"`
	BSSID      string `json:"bssid"`
	Channel    int    `json:"channel"`
	SignalDbm  int    `json:"signal_dbm"`
	Hidden     bool   `json:"hidden"`
	SSIDLength int    `json:"ssid_len,omitempty"`
}

type scanResult struct {
	Count    int               `json:"count"`
	DwellMs  int               `json:"dwell_ms"`
	Networks []WirelessNetwork `json:"networks"`
}

// WifiLinkStatus is the WIFI_STATUS payload: the drone's upstream station
// link. Connected means the WPA 4-way handshake completed (or, on older
// daemons, that an address was leased); IP is reported separately so a
// caller can distinguish "joined, waiting for DHCP" from "not joined".
type WifiLinkStatus struct {
	Connected  bool   `json:"connected"`
	Associated bool   `json:"associated"`
	SSID       string `json:"ssid"`
	BSSID      string `json:"bssid"`
	IP         string `json:"ip"`
	Channel    int    `json:"channel"`
	Mode       string `json:"mode"`
	State      string `json:"state"`
	Error      string `json:"error"`
	WPAState   string `json:"wpa_state"`
	// Sharing is true when the drone NATs 192.168.4.0/24 behind the station
	// link. Always false on firmware older than v1.4.0.
	Sharing bool `json:"sharing"`
}

// okOrError maps a failed BaseResponse onto a Go error.
func okOrError(resp *BaseResponse, what string) error {
	if strings.ToLower(resp.Status) == "ok" {
		return nil
	}
	if resp.Error != nil {
		return fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
	}
	return fmt.Errorf("%s failed", what)
}

// ScanNetworks surveys nearby access points from the drone's monitor radio.
// dwellMs controls how long the sweep runs per call (daemon clamps it to
// 1s..15s). Networks come back sorted by signal strength, strongest first.
func (c *ControlClient) ScanNetworks(dwellMs int) ([]WirelessNetwork, error) {
	params := map[string]interface{}{
		"dwell_ms": dwellMs,
	}
	resp, err := c.SendCommand("WIFI_SCAN", params)
	if err != nil {
		return nil, err
	}
	if err := okOrError(resp, "WIFI_SCAN"); err != nil {
		return nil, err
	}

	var res scanResult
	if err := json.Unmarshal(resp.Data, &res); err != nil {
		return nil, fmt.Errorf("unmarshal scan result: %w", err)
	}
	return res.Networks, nil
}

// WifiConnect joins the drone to an upstream network. An empty password
// selects an open network; bssid optionally pins a specific AP; encryption
// overrides the default psk2 (allowed: psk2, psk, psk-mixed, sae, sae-mixed).
// share NATs the drone's LAN behind the station link so a host plugged into a
// LAN port reaches the internet. Association completes asynchronously — poll
// WifiStatus afterwards.
func (c *ControlClient) WifiConnect(ssid, password, bssid, encryption string, share bool) error {
	resp, err := c.SendCommand("WIFI_CONNECT", wifiConnectParams(ssid, password, bssid, encryption, share))
	if err != nil {
		return err
	}
	return okOrError(resp, "WIFI_CONNECT")
}

// wifiConnectParams builds the WIFI_CONNECT payload. Split out so the wire
// format can be asserted without a live drone.
func wifiConnectParams(ssid, password, bssid, encryption string, share bool) map[string]interface{} {
	params := map[string]interface{}{
		"ssid":  ssid,
		"share": share,
	}
	if password != "" {
		params["psk"] = password
	}
	if bssid != "" {
		params["bssid"] = bssid
	}
	if encryption != "" {
		params["encryption"] = encryption
	}
	return params
}

// WifiStatus reports the drone's upstream station link state.
func (c *ControlClient) WifiStatus() (*WifiLinkStatus, error) {
	resp, err := c.SendCommand("WIFI_STATUS", nil)
	if err != nil {
		return nil, err
	}
	if err := okOrError(resp, "WIFI_STATUS"); err != nil {
		return nil, err
	}

	var st WifiLinkStatus
	if err := json.Unmarshal(resp.Data, &st); err != nil {
		return nil, fmt.Errorf("unmarshal wifi status: %w", err)
	}
	return &st, nil
}

// WifiDisconnect removes the station profile and returns the radio to the
// boot-safe DOWN state.
func (c *ControlClient) WifiDisconnect() error {
	resp, err := c.SendCommand("WIFI_DISCONNECT", nil)
	if err != nil {
		return err
	}
	return okOrError(resp, "WIFI_DISCONNECT")
}
