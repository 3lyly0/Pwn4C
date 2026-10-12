package drone

import (
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

// BuildDeauthFrame creates an 802.11 Deauthentication frame wrapped in a minimal 8-byte RadioTap header.
// Radiotap header:
//
//	it_version: 0 (1 byte)
//	it_pad:     0 (1 byte)
//	it_len:     8 (2 bytes, little-endian: 0x08, 0x00)
//	it_present: 0 (4 bytes: 0x00, 0x00, 0x00, 0x00)
//
// 802.11 MAC Frame:
//
//	Frame Control: 0x00c0 (Type: Management, Subtype: Deauthentication)
//	Duration:      0x0000 (2 bytes)
//	Addr1 (RA/DA): Destination STA MAC or Broadcast (ff:ff:ff:ff:ff:ff)
//	Addr2 (TA/SA): Source BSSID / AP MAC
//	Addr3 (BSSID): BSSID / AP MAC
//	Seq-Control:   0x0000 (2 bytes)
//	Reason Code:   2 bytes little-endian (e.g. 0x07, 0x00 for Class 3)
func BuildDeauthFrame(bssidStr, clientStr string, reasonCode uint16) (string, error) {
	bssid, err := net.ParseMAC(bssidStr)
	if err != nil {
		return "", fmt.Errorf("invalid BSSID MAC: %w", err)
	}

	var client net.HardwareAddr
	if clientStr == "" || clientStr == "ff:ff:ff:ff:ff:ff" || clientStr == "FF:FF:FF:FF:FF:FF" {
		client = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	} else {
		client, err = net.ParseMAC(clientStr)
		if err != nil {
			return "", fmt.Errorf("invalid Client MAC: %w", err)
		}
	}

	frame := make([]byte, 0, 8+24+2)

	// 1. RadioTap Header (8 bytes)
	radiotap := []byte{0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00}
	frame = append(frame, radiotap...)

	// 2. 802.11 Management Header: Deauthentication (0x00c0 little endian -> 0xc0, 0x00)
	frame = append(frame, 0xc0, 0x00) // Type: Management, Subtype: Deauth
	frame = append(frame, 0x00, 0x00) // Duration

	// Addr1: Receiver Address (Client)
	frame = append(frame, client...)
	// Addr2: Transmitter Address (AP / BSSID)
	frame = append(frame, bssid...)
	// Addr3: Filtering Address (BSSID)
	frame = append(frame, bssid...)

	// Sequence Control (0)
	frame = append(frame, 0x00, 0x00)

	// Reason Code (2 bytes, little endian)
	frame = append(frame, byte(reasonCode&0xff), byte((reasonCode>>8)&0xff))

	return hex.EncodeToString(frame), nil
}
