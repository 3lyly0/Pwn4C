package drone

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// Handshake is one crackable unit reported by the daemon's GET_HANDSHAKES.
//
// A unit is either a complete 4-way handshake (an AP-side message that carries
// the ANonce plus a client-side message that carries the MIC and the client's
// EAPOL frame) or a PMKID lifted from an M1. The daemon reports facts; the
// host decides how to turn them into a hash.
type Handshake struct {
	BSSID       string `json:"bssid"`
	STA         string `json:"sta"`
	SSID        string `json:"ssid"`
	SSIDLen     int    `json:"ssid_len"`
	SSIDHex     string `json:"ssid_hex"`
	MessagePair int    `json:"message_pair"`
	Frames      int    `json:"frames"`
	ANonce      string `json:"anonce"`
	MIC         string `json:"mic"`
	PMKID       string `json:"pmkid"`
	EAPOL       string `json:"eapol"`
	EAPOLLen    int    `json:"eapol_len"`
}

// HandshakesData is the GET_HANDSHAKES payload. Only ready units are listed;
// `Count` is the total across all pages and `Returned` is this page's size.
type HandshakesData struct {
	Count      int         `json:"count"`
	Tracked    int         `json:"tracked"`
	Offset     int         `json:"offset"`
	Returned   int         `json:"returned"`
	Truncated  bool        `json:"truncated"`
	Handshakes []Handshake `json:"handshakes"`
}

// handshakesPageLimit guards against a daemon that keeps reporting pages
// forever. The daemon table holds 16 pairs, so this is far above reality.
const handshakesPageLimit = 64

// GetHandshakes fetches one page of ready units. Pass reset=true to clear the
// daemon's table before reading it.
func (c *ControlClient) GetHandshakes(offset int, reset bool) (*HandshakesData, error) {
	params := map[string]interface{}{"offset": offset}
	if reset {
		params["reset"] = true
	}

	resp, err := c.SendCommand("GET_HANDSHAKES", params)
	if err != nil {
		return nil, err
	}
	if resp.Status != "ok" {
		if resp.Error != nil {
			return nil, fmt.Errorf("GET_HANDSHAKES: %s: %s", resp.Error.Code, resp.Error.Message)
		}
		return nil, fmt.Errorf("GET_HANDSHAKES failed with status %q", resp.Status)
	}

	var out HandshakesData
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, fmt.Errorf("decode GET_HANDSHAKES: %w", err)
	}
	return &out, nil
}

// GetAllHandshakes pages through the daemon table and returns every ready unit.
func (c *ControlClient) GetAllHandshakes() ([]Handshake, error) {
	var all []Handshake
	offset := 0

	for page := 0; page < handshakesPageLimit; page++ {
		data, err := c.GetHandshakes(offset, false)
		if err != nil {
			return nil, err
		}
		all = append(all, data.Handshakes...)

		if !data.Truncated || data.Returned == 0 {
			return all, nil
		}
		offset += data.Returned
	}

	return all, nil
}

// HasPMKID reports whether the unit carries a PMKID (crackable on its own).
func (h Handshake) HasPMKID() bool {
	return strings.TrimSpace(h.PMKID) != ""
}

// ESSIDHex returns the ESSID as hashcat expects it: raw bytes, lowercase hex.
func (h Handshake) ESSIDHex() (string, error) {
	if h.SSIDHex != "" {
		raw, err := hex.DecodeString(h.SSIDHex)
		if err != nil {
			return "", fmt.Errorf("invalid ssid_hex: %w", err)
		}
		if len(raw) == 0 {
			return "", fmt.Errorf("ESSID is empty")
		}
		return hex.EncodeToString(raw), nil
	}
	if h.SSID == "" {
		return "", fmt.Errorf("ESSID unknown (no beacon captured for %s)", h.BSSID)
	}
	return hex.EncodeToString([]byte(h.SSID)), nil
}

// Hashcat22000 renders the unit as a hashcat mode-22000 line. A PMKID is
// preferred when present: it needs no client-side message and cracks alone.
func (h Handshake) Hashcat22000() (string, error) {
	if h.HasPMKID() {
		return h.PMKIDLine()
	}
	return h.EAPOLLine()
}

// PMKIDLine renders the `WPA*01*...` form.
func (h Handshake) PMKIDLine() (string, error) {
	if !h.HasPMKID() {
		return "", fmt.Errorf("no PMKID in this unit")
	}

	pmkid, err := hashcatHexField(h.PMKID, 32, "pmkid")
	if err != nil {
		return "", err
	}
	ap, err := hashcatMAC(h.BSSID)
	if err != nil {
		return "", fmt.Errorf("bssid: %w", err)
	}
	sta, err := hashcatMAC(h.STA)
	if err != nil {
		return "", fmt.Errorf("sta: %w", err)
	}
	essid, err := h.ESSIDHex()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("WPA*01*%s*%s*%s*%s***", pmkid, ap, sta, essid), nil
}

// EAPOLLine renders the `WPA*02*...` form for a complete handshake.
func (h Handshake) EAPOLLine() (string, error) {
	if h.MessagePair < 0 || h.MessagePair > 3 {
		return "", fmt.Errorf("handshake is incomplete (message pair %d)", h.MessagePair)
	}

	mic, err := hashcatHexField(h.MIC, 32, "mic")
	if err != nil {
		return "", err
	}
	anonce, err := hashcatHexField(h.ANonce, 64, "anonce")
	if err != nil {
		return "", err
	}
	eapol, err := hashcatHexField(h.EAPOL, 0, "eapol")
	if err != nil {
		return "", err
	}
	ap, err := hashcatMAC(h.BSSID)
	if err != nil {
		return "", fmt.Errorf("bssid: %w", err)
	}
	sta, err := hashcatMAC(h.STA)
	if err != nil {
		return "", fmt.Errorf("sta: %w", err)
	}
	essid, err := h.ESSIDHex()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("WPA*02*%s*%s*%s*%s*%s*%s*%02x",
		mic, ap, sta, essid, anonce, eapol, h.MessagePair), nil
}

// hashcatMAC converts a colon-separated MAC to the 12 lowercase hex characters
// hashcat expects.
func hashcatMAC(mac string) (string, error) {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return "", fmt.Errorf("invalid MAC %q", mac)
	}
	return hex.EncodeToString(hw), nil
}

// hashcatHexField validates an optional hex field and normalises its case.
// A length of 0 means "any even length".
func hashcatHexField(value string, wantLen int, name string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return "", fmt.Errorf("%s is empty", name)
	}
	if len(v)%2 != 0 {
		return "", fmt.Errorf("%s has an odd hex length (%d)", name, len(v))
	}
	if wantLen > 0 && len(v) != wantLen {
		return "", fmt.Errorf("%s must be %d hex chars, got %d", name, wantLen, len(v))
	}
	if _, err := hex.DecodeString(v); err != nil {
		return "", fmt.Errorf("%s is not valid hex: %w", name, err)
	}
	return v, nil
}
