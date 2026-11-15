package drone

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// findIE walks the element list starting at offset and returns the payload of
// the first element with the given ID.
func findIE(t *testing.T, frame []byte, offset int, id byte) []byte {
	t.Helper()
	for i := offset; i+2 <= len(frame); {
		eid := frame[i]
		elen := int(frame[i+1])
		if i+2+elen > len(frame) {
			t.Fatalf("element %d overruns the frame", eid)
		}
		if eid == id {
			return frame[i+2 : i+2+elen]
		}
		i += 2 + elen
	}
	t.Fatalf("element %d not found", id)
	return nil
}

func TestBuildCSABeacon(t *testing.T) {
	bssid := "00:11:22:33:44:55"
	opts := DefaultFrameOptions()
	opts.Channel = 6

	frameHex, err := BuildCSAFrame(CSAParams{
		BSSID:         bssid,
		SSID:          "lab-net",
		TargetChannel: 11,
		Count:         5,
		Seq:           3,
		Options:       opts,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	frame, err := hex.DecodeString(frameHex)
	if err != nil {
		t.Fatalf("invalid hex: %v", err)
	}

	// 16 radiotap + 24 header + 12 fixed + 9 SSID + 6 rates + 3 DS + 5 CSA.
	if want := 75; len(frame) != want {
		t.Fatalf("expected %d bytes, got %d", want, len(frame))
	}

	if frame[16] != 0x80 || frame[17] != 0x00 {
		t.Errorf("expected beacon frame control 0x80 0x00, got %x %x",
			frame[16], frame[17])
	}

	// Addr1 is broadcast, Addr2 and Addr3 are the AP.
	for i := 0; i < 6; i++ {
		if frame[20+i] != 0xff {
			t.Errorf("Addr1 byte %d is not broadcast: %x", i, frame[20+i])
		}
	}
	wantBSSID := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	for i := 0; i < 6; i++ {
		if frame[26+i] != wantBSSID[i] {
			t.Errorf("Addr2 byte %d mismatch", i)
		}
		if frame[32+i] != wantBSSID[i] {
			t.Errorf("Addr3 byte %d mismatch", i)
		}
	}

	// Sequence Control: seq 3 sits in bits 4-15.
	if got := binary.LittleEndian.Uint16(frame[38:40]); got != 3<<4 {
		t.Errorf("expected sequence control %#x, got %#x", 3<<4, got)
	}

	// Radiotap must carry the *current* channel, not the target.
	if freq := binary.LittleEndian.Uint16(frame[10:12]); freq != 2437 {
		t.Errorf("expected injection on channel 6 (2437 MHz), got %d", freq)
	}

	body := 16 + 24 + 12 // IEs start after the fixed beacon parameters
	if got := findIE(t, frame, body, ieSSID); string(got) != "lab-net" {
		t.Errorf("SSID element mismatch: %q", got)
	}
	if got := findIE(t, frame, body, ieDSParams); len(got) != 1 || got[0] != 6 {
		t.Errorf("DS parameter should be the current channel 6, got %v", got)
	}

	csa := findIE(t, frame, body, ieCSA)
	if len(csa) != 3 {
		t.Fatalf("CSA element should be 3 bytes, got %d", len(csa))
	}
	if csa[0] != 0x00 {
		t.Errorf("CSA mode should be 0 (no restriction), got %d", csa[0])
	}
	if csa[1] != 11 {
		t.Errorf("CSA target channel should be 11, got %d", csa[1])
	}
	if csa[2] != 5 {
		t.Errorf("CSA count should be 5, got %d", csa[2])
	}
}

func TestBuildCSAAction(t *testing.T) {
	opts := DefaultFrameOptions()
	opts.Channel = 1

	frameHex, err := BuildCSAFrame(CSAParams{
		BSSID:         "00:11:22:33:44:55",
		TargetChannel: 6,
		Count:         1,
		Client:        "AA:BB:CC:DD:EE:FF",
		Mode:          CSAModeAction,
		Options:       opts,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	frame, _ := hex.DecodeString(frameHex)

	// 16 + 24 + category/action (2) + CSA element (5).
	if want := 47; len(frame) != want {
		t.Fatalf("expected %d bytes, got %d", want, len(frame))
	}
	if frame[16] != 0xd0 || frame[17] != 0x00 {
		t.Errorf("expected action frame control 0xd0 0x00, got %x %x",
			frame[16], frame[17])
	}

	wantClient := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	for i := 0; i < 6; i++ {
		if frame[20+i] != wantClient[i] {
			t.Errorf("Addr1 byte %d should be the unicast client", i)
		}
	}

	body := 16 + 24
	if frame[body] != 0x00 || frame[body+1] != 0x04 {
		t.Errorf("expected Spectrum Management CSA action, got %x %x",
			frame[body], frame[body+1])
	}
	csa := findIE(t, frame, body+2, ieCSA)
	if csa[1] != 6 || csa[2] != 1 {
		t.Errorf("CSA element mismatch: %v", csa)
	}
}

func TestBuildCSAActionBroadcast(t *testing.T) {
	frameHex, err := BuildCSAFrame(CSAParams{
		BSSID:         "00:11:22:33:44:55",
		TargetChannel: 11,
		Count:         255,
		Mode:          CSAModeAction,
		Options:       DefaultFrameOptions(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	frame, _ := hex.DecodeString(frameHex)
	for i := 0; i < 6; i++ {
		if frame[20+i] != 0xff {
			t.Errorf("Addr1 byte %d should be broadcast, got %x", i, frame[20+i])
		}
	}
	csa := findIE(t, frame, 16+24+2, ieCSA)
	if csa[2] != 255 {
		t.Errorf("count should be clamped to 255, got %d", csa[2])
	}
}

func TestBuildCSACountClamped(t *testing.T) {
	frameHex, err := BuildCSAFrame(CSAParams{
		BSSID:         "00:11:22:33:44:55",
		TargetChannel: 6,
		Count:         0,
		Options:       DefaultFrameOptions(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	frame, _ := hex.DecodeString(frameHex)
	csa := findIE(t, frame, 16+24+12, ieCSA)
	if csa[2] != 1 {
		t.Errorf("count 0 should clamp to 1, got %d", csa[2])
	}
}

func TestBuildCSAValidation(t *testing.T) {
	cases := []struct {
		name string
		p    CSAParams
	}{
		{"bad bssid", CSAParams{BSSID: "nope", TargetChannel: 6}},
		{"target channel 0", CSAParams{BSSID: "00:11:22:33:44:55", TargetChannel: 0}},
		{"target channel 14", CSAParams{BSSID: "00:11:22:33:44:55", TargetChannel: 14}},
		{"ssid too long", CSAParams{
			BSSID:         "00:11:22:33:44:55",
			SSID:          "123456789012345678901234567890123",
			TargetChannel: 6,
		}},
		{"bad client", CSAParams{
			BSSID:         "00:11:22:33:44:55",
			TargetChannel: 6,
			Client:        "zz:zz:zz:zz:zz:zz",
			Mode:          CSAModeAction,
		}},
	}
	for _, tc := range cases {
		if _, err := BuildCSAFrame(tc.p); err == nil {
			t.Errorf("%s: expected an error", tc.name)
		}
	}
}

func TestParseCSAMode(t *testing.T) {
	if m, err := ParseCSAMode(""); err != nil || m != CSAModeBeacon {
		t.Errorf("empty mode should default to beacon, got %v %v", m, err)
	}
	if m, err := ParseCSAMode("action"); err != nil || m != CSAModeAction {
		t.Errorf("action mode not parsed: %v %v", m, err)
	}
	if _, err := ParseCSAMode("spectrum"); err == nil {
		t.Error("unknown mode should fail")
	}
	if CSAModeAction.String() != "action" || CSAModeBeacon.String() != "beacon" {
		t.Error("mode String() mismatch")
	}
}
