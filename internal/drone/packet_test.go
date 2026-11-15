package drone

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestBuildDeauthFrame(t *testing.T) {
	bssid := "00:11:22:33:44:55"
	client := "AA:BB:CC:DD:EE:FF"

	frameHex, err := BuildDeauthFrame(bssid, client, ReasonClass3FromNonAssocSTA)
	if err != nil {
		t.Fatalf("unexpected error building deauth frame: %v", err)
	}

	frame, err := hex.DecodeString(frameHex)
	if err != nil {
		t.Fatalf("invalid hex generated: %v", err)
	}

	// 16 bytes radiotap + 24 bytes header + 2 bytes reason code = 42 bytes
	if len(frame) != 42 {
		t.Fatalf("expected 42 bytes, got %d", len(frame))
	}

	// Full radiotap header: len 16, Flags/Rate/Channel/TX flags present.
	if frame[2] != 0x10 || frame[3] != 0x00 {
		t.Errorf("radiotap length field mismatch: %x %x", frame[2], frame[3])
	}
	if frame[4]&0x1e != 0x1e {
		t.Errorf("radiotap present bitmap missing fields: %x", frame[4])
	}
	if frame[9] != 2 {
		t.Errorf("expected 1 Mbps rate field (2), got %d", frame[9])
	}
	freq := binary.LittleEndian.Uint16(frame[10:12])
	if freq != 2412 {
		t.Errorf("expected channel 1 frequency 2412, got %d", freq)
	}

	// Check 802.11 frame control: Management Deauth (0xc0, 0x00)
	if frame[16] != 0xc0 || frame[17] != 0x00 {
		t.Errorf("expected frame control 0xc0 0x00, got %x %x", frame[16], frame[17])
	}

	// Check Receiver Address (Client)
	expectedClient := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	for i := 0; i < 6; i++ {
		if frame[20+i] != expectedClient[i] {
			t.Errorf("client MAC byte %d mismatch", i)
		}
	}

	// Check Transmitter & BSSID Address (BSSID)
	expectedBSSID := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	for i := 0; i < 6; i++ {
		if frame[26+i] != expectedBSSID[i] {
			t.Errorf("BSSID MAC byte %d mismatch", i)
		}
		if frame[32+i] != expectedBSSID[i] {
			t.Errorf("Addr3 BSSID MAC byte %d mismatch", i)
		}
	}

	// Check Reason Code (ReasonClass3FromNonAssocSTA = 7)
	if frame[40] != 0x07 || frame[41] != 0x00 {
		t.Errorf("expected reason code 0x07 0x00, got %x %x", frame[40], frame[41])
	}
}

func TestBuildDeauthBroadcast(t *testing.T) {
	bssid := "00:11:22:33:44:55"
	frameHex, err := BuildDeauthFrame(bssid, "", ReasonDeauthLeaving)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	frame, err := hex.DecodeString(frameHex)
	if err != nil {
		t.Fatalf("invalid hex: %v", err)
	}

	// Destination should be broadcast
	for i := 0; i < 6; i++ {
		if frame[20+i] != 0xff {
			t.Errorf("expected broadcast byte at %d, got %x", i, frame[20+i])
		}
	}
}

func TestBuildDisassocFrame(t *testing.T) {
	bssid := "00:11:22:33:44:55"
	client := "AA:BB:CC:DD:EE:FF"

	opts := DefaultFrameOptions()
	opts.Channel = 6
	opts.RateMbps = 5.5
	opts.Disassoc = true

	frameHex, err := BuildManagementFrame(bssid, client,
		ReasonDisassocLeaving, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	frame, err := hex.DecodeString(frameHex)
	if err != nil {
		t.Fatalf("invalid hex: %v", err)
	}

	if frame[16] != 0xa0 {
		t.Errorf("expected disassoc frame control 0xa0, got %x", frame[16])
	}
	freq := binary.LittleEndian.Uint16(frame[10:12])
	if freq != 2437 {
		t.Errorf("expected channel 6 frequency 2437, got %d", freq)
	}
	if frame[9] != 11 { // 5.5 Mbps -> 11 * 500 kbps
		t.Errorf("expected 5.5 Mbps rate field 11, got %d", frame[9])
	}
}

func TestBuildReverseFrame(t *testing.T) {
	bssid := "00:11:22:33:44:55"
	client := "AA:BB:CC:DD:EE:FF"

	opts := DefaultFrameOptions()
	opts.Reverse = true

	frameHex, err := BuildManagementFrame(bssid, client,
		ReasonClass3FromNonAssocSTA, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	frame, _ := hex.DecodeString(frameHex)

	// Addr1 = AP, Addr2 = client
	expectedBSSID := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	expectedClient := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	for i := 0; i < 6; i++ {
		if frame[20+i] != expectedBSSID[i] {
			t.Errorf("Addr1 should be the AP at byte %d", i)
		}
		if frame[26+i] != expectedClient[i] {
			t.Errorf("Addr2 should be the client at byte %d", i)
		}
	}
}

func TestChannel14Frequency(t *testing.T) {
	opts := DefaultFrameOptions()
	opts.Channel = 14
	frameHex, err := BuildManagementFrame("00:11:22:33:44:55", "",
		ReasonDeauthLeaving, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	frame, _ := hex.DecodeString(frameHex)
	freq := binary.LittleEndian.Uint16(frame[10:12])
	if freq != 2484 {
		t.Errorf("expected channel 14 frequency 2484, got %d", freq)
	}
}
