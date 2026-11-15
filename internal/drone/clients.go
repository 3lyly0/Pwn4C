package drone

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Client is one station reported by the daemon's GET_CLIENTS.
//
// The daemon reports facts it saw on the air: which BSSID the station is
// talking to, the last antenna signal, the SSID it probed for (its PNL entry),
// and how long ago it was last seen. The host decides what to do with them.
type Client struct {
	STA        string `json:"sta"`
	BSSID      string `json:"bssid"`
	Associated bool   `json:"associated"`
	Probed     bool   `json:"probed"`
	SSID       string `json:"ssid"`
	SSIDLen    int    `json:"ssid_len"`
	SSIDHex    string `json:"ssid_hex"`
	RSSI       int    `json:"rssi"`
	HasRSSI    bool   `json:"has_rssi"`
	Frames     int    `json:"frames"`
	AgeMS      int64  `json:"age_ms"`
}

// ClientsData is the GET_CLIENTS payload. `Count` is the total across all
// pages and `Returned` is this page's size.
type ClientsData struct {
	Count     int      `json:"count"`
	Tracked   int      `json:"tracked"`
	Offset    int      `json:"offset"`
	Returned  int      `json:"returned"`
	Truncated bool     `json:"truncated"`
	Clients   []Client `json:"clients"`
}

// clientsPageLimit guards against a daemon that keeps reporting pages forever.
// The daemon table holds 32 stations, so this is far above reality.
const clientsPageLimit = 64

// GetClients fetches one page of stations, newest first. Pass reset=true to
// clear the daemon's table before reading it.
func (c *ControlClient) GetClients(offset int, reset bool) (*ClientsData, error) {
	params := map[string]interface{}{"offset": offset}
	if reset {
		params["reset"] = true
	}

	resp, err := c.SendCommand("GET_CLIENTS", params)
	if err != nil {
		return nil, err
	}
	if resp.Status != "ok" {
		if resp.Error != nil {
			return nil, fmt.Errorf("GET_CLIENTS: %s: %s", resp.Error.Code, resp.Error.Message)
		}
		return nil, fmt.Errorf("GET_CLIENTS failed with status %q", resp.Status)
	}

	var out ClientsData
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, fmt.Errorf("decode GET_CLIENTS: %w", err)
	}
	return &out, nil
}

// GetAllClients pages through the daemon table and returns every station.
func (c *ControlClient) GetAllClients() ([]Client, error) {
	var all []Client
	offset := 0

	for page := 0; page < clientsPageLimit; page++ {
		data, err := c.GetClients(offset, false)
		if err != nil {
			return nil, err
		}
		all = append(all, data.Clients...)

		if !data.Truncated || data.Returned == 0 {
			return all, nil
		}
		offset += data.Returned
	}

	return all, nil
}

// DisplaySTA returns the station MAC in the lowercase form the rest of the CLI
// prints; the daemon serialises MACs in uppercase.
func (c Client) DisplaySTA() string {
	return strings.ToLower(c.STA)
}

// DisplayBSSID returns the associated BSSID in lowercase, or "" when the
// station has only been seen probing.
func (c Client) DisplayBSSID() string {
	if c.BSSID == "" {
		return ""
	}
	return strings.ToLower(c.BSSID)
}

// ProbeSSID returns the SSID the station is looking for, preferring the escaped
// printable form and falling back to the raw hex when the SSID is not valid
// UTF-8 (the daemon sends both).
func (c Client) ProbeSSID() string {
	if c.SSID != "" {
		return c.SSID
	}
	if c.SSIDHex != "" {
		return "0x" + strings.ToLower(c.SSIDHex)
	}
	return ""
}
