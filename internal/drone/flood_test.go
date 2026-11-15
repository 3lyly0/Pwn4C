package drone

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"testing"
)

func TestBuildBeaconFrame(t *testing.T) {
	opts := DefaultFrameOptions()
	opts.Channel = 11

	frameHex, err := BuildBeaconFrame(BeaconParams{
		BSSID:   "02:11:22:33:44:55",
		SSID:    "TP-LINK_4F2A",
		Seq:     7,
		Options: opts,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	frame, err := hex.DecodeString(frameHex)
	if err != nil {
		t.Fatalf("invalid hex: %v", err)
	}

	// 16 radiotap + 24 header + 12 fixed + 14 SSID + 6 rates + 3 DS.
	if want := 75; len(frame) != want {
		t.Fatalf("expected %d bytes, got %d", want, len(frame))
	}
	if frame[16] != 0x80 || frame[17] != 0x00 {
		t.Errorf("expected beacon frame control, got %x %x", frame[16], frame[17])
	}
	for i := 0; i < 6; i++ {
		if frame[20+i] != 0xff {
			t.Errorf("Addr1 byte %d is not broadcast", i)
		}
	}
	if got := binary.LittleEndian.Uint16(frame[38:40]); got != 7<<4 {
		t.Errorf("sequence control = %#x, want %#x", got, 7<<4)
	}
	if got := binary.LittleEndian.Uint16(frame[10:12]); got != 2462 {
		t.Errorf("radiotap frequency = %d, want 2462 (ch11)", got)
	}

	body := 16 + 24 + 12
	if got := findIE(t, frame, body, ieSSID); string(got) != "TP-LINK_4F2A" {
		t.Errorf("SSID element = %q", got)
	}
	if got := findIE(t, frame, body, ieDSParams); len(got) != 1 || got[0] != 11 {
		t.Errorf("DS parameter = %v, want channel 11", got)
	}
}

// A hidden network blanks the SSID element but stays a normal beacon.
func TestBuildBeaconHidden(t *testing.T) {
	frameHex, err := BuildBeaconFrame(BeaconParams{
		BSSID:   "02:11:22:33:44:55",
		SSID:    "should-not-appear",
		Hidden:  true,
		Options: DefaultFrameOptions(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	frame, _ := hex.DecodeString(frameHex)

	if strings.Contains(string(frame), "should-not-appear") {
		t.Fatal("hidden beacon leaked the SSID")
	}
	if got := findIE(t, frame, 16+24+12, ieSSID); len(got) != 0 {
		t.Errorf("hidden SSID element should be empty, got %q", got)
	}
}

func TestBuildBeaconValidation(t *testing.T) {
	cases := []struct {
		name string
		p    BeaconParams
	}{
		{"bad bssid", BeaconParams{BSSID: "nope"}},
		{"short bssid", BeaconParams{BSSID: "02:11:22:33:44"}},
		{"ssid too long", BeaconParams{
			BSSID: "02:11:22:33:44:55",
			SSID:  strings.Repeat("a", 33),
		}},
	}
	for _, tc := range cases {
		if _, err := BuildBeaconFrame(tc.p); err == nil {
			t.Errorf("%s: expected an error", tc.name)
		}
	}
}

func TestBuildAuthFrame(t *testing.T) {
	opts := DefaultFrameOptions()
	opts.Channel = 6

	frameHex, err := BuildAuthFrame(AuthParams{
		BSSID:   "02:11:22:33:44:55",
		Client:  "02:AA:BB:CC:DD:EE",
		Seq:     2,
		Options: opts,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	frame, _ := hex.DecodeString(frameHex)

	// 16 radiotap + 24 header + 6 body.
	if want := 46; len(frame) != want {
		t.Fatalf("expected %d bytes, got %d", want, len(frame))
	}
	if frame[16] != 0xb0 || frame[17] != 0x00 {
		t.Errorf("expected auth frame control, got %x %x", frame[16], frame[17])
	}

	// Addr1 = AP, Addr2 = client, Addr3 = AP.
	wantAP := []byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	wantSTA := []byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	for i := 0; i < 6; i++ {
		if frame[20+i] != wantAP[i] {
			t.Errorf("Addr1 byte %d mismatch", i)
		}
		if frame[26+i] != wantSTA[i] {
			t.Errorf("Addr2 byte %d mismatch", i)
		}
		if frame[32+i] != wantAP[i] {
			t.Errorf("Addr3 byte %d mismatch", i)
		}
	}

	body := 16 + 24
	if alg := binary.LittleEndian.Uint16(frame[body : body+2]); alg != 0 {
		t.Errorf("algorithm = %d, want 0 (Open System)", alg)
	}
	if seq := binary.LittleEndian.Uint16(frame[body+2 : body+4]); seq != 1 {
		t.Errorf("auth sequence = %d, want 1 (request)", seq)
	}
	if status := binary.LittleEndian.Uint16(frame[body+4 : body+6]); status != 0 {
		t.Errorf("status = %d, want 0", status)
	}
}

func TestBuildAuthFrameValidation(t *testing.T) {
	cases := []struct {
		name string
		p    AuthParams
	}{
		{"bad bssid", AuthParams{BSSID: "nope", Client: "02:AA:BB:CC:DD:EE"}},
		{"bad client", AuthParams{BSSID: "02:11:22:33:44:55", Client: "nope"}},
		{"group client", AuthParams{BSSID: "02:11:22:33:44:55", Client: "ff:ff:ff:ff:ff:ff"}},
		{"multicast client", AuthParams{BSSID: "02:11:22:33:44:55", Client: "01:00:5e:00:00:01"}},
	}
	for _, tc := range cases {
		if _, err := BuildAuthFrame(tc.p); err == nil {
			t.Errorf("%s: expected an error", tc.name)
		}
	}
}

// A random MAC must be locally administered, unicast, and differ each call.
func TestRandomMAC(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 64; i++ {
		mac := RandomMAC()
		if len(mac) != 17 {
			t.Fatalf("MAC %q is not 17 characters", mac)
		}
		hw, err := net.ParseMAC(mac)
		if err != nil {
			t.Fatalf("MAC %q does not parse: %v", mac, err)
		}
		if hw[0]&0x01 != 0 {
			t.Fatalf("MAC %q is a group address", mac)
		}
		if hw[0]&0x02 == 0 {
			t.Fatalf("MAC %q is not locally administered", mac)
		}
		if seen[mac] {
			t.Fatalf("duplicate random MAC %q", mac)
		}
		seen[mac] = true
	}
}

func TestRandomSSID(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 64; i++ {
		ssid := RandomSSID()
		if len(ssid) == 0 || len(ssid) > 32 {
			t.Fatalf("SSID %q is outside the 1-32 byte range", ssid)
		}
		if seen[ssid] {
			t.Fatalf("duplicate random SSID %q", ssid)
		}
		seen[ssid] = true

		// Every generated SSID must survive the beacon builder.
		if _, err := BuildBeaconFrame(BeaconParams{
			BSSID:   "02:11:22:33:44:55",
			SSID:    ssid,
			Options: DefaultFrameOptions(),
		}); err != nil {
			t.Fatalf("SSID %q rejected: %v", ssid, err)
		}
	}
}
