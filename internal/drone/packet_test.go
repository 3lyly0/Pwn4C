package drone

import (
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

	// 8 bytes radiotap + 24 bytes header + 2 bytes reason code = 34 bytes
	if len(frame) != 34 {
		t.Fatalf("expected 34 bytes, got %d", len(frame))
	}

	// Check radiotap header (len = 8)
	if frame[2] != 0x08 || frame[3] != 0x00 {
		t.Errorf("radiotap length field mismatch: %x %x", frame[2], frame[3])
	}

	// Check 802.11 frame control: Management Deauth (0xc0, 0x00)
	if frame[8] != 0xc0 || frame[9] != 0x00 {
		t.Errorf("expected frame control 0xc0 0x00, got %x %x", frame[8], frame[9])
	}

	// Check Receiver Address (Client)
	expectedClient := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	for i := 0; i < 6; i++ {
		if frame[12+i] != expectedClient[i] {
			t.Errorf("client MAC byte %d mismatch", i)
		}
	}

	// Check Transmitter & BSSID Address (BSSID)
	expectedBSSID := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	for i := 0; i < 6; i++ {
		if frame[18+i] != expectedBSSID[i] {
			t.Errorf("BSSID MAC byte %d mismatch", i)
		}
	}

	// Check Reason Code (ReasonClass3FromNonAssocSTA = 7)
	if frame[32] != 0x07 || frame[33] != 0x00 {
		t.Errorf("expected reason code 0x07 0x00, got %x %x", frame[32], frame[33])
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
		if frame[12+i] != 0xff {
			t.Errorf("expected broadcast byte at %d, got %x", i, frame[12+i])
		}
	}
}
