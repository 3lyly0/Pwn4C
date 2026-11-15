package drone

import (
	"encoding/json"
	"strings"
	"testing"
)

// A PMKID unit must render the `WPA*01*` form: PMKID, AP MAC, STA MAC, ESSID.
func TestHandshakePMKIDLine(t *testing.T) {
	h := Handshake{
		BSSID: "AA:BB:CC:DD:EE:FF",
		STA:   "02:00:00:BE:EF:02",
		SSID:  "lab",
		PMKID: "00112233445566778899AABBCCDDEEFF",
	}

	line, err := h.Hashcat22000()
	if err != nil {
		t.Fatalf("Hashcat22000: %v", err)
	}

	want := "WPA*01*00112233445566778899aabbccddeeff*aabbccddeeff*020000beef02*6c6162***"
	if line != want {
		t.Fatalf("line = %q, want %q", line, want)
	}
}

// A complete 4-way must render `WPA*02*` with the message-pair byte as the
// final field.
func TestHandshakeEAPOLLine(t *testing.T) {
	h := Handshake{
		BSSID:       "AA:BB:CC:DD:EE:FF",
		STA:         "02:00:00:BE:EF:02",
		SSID:        "lab",
		MessagePair: 0,
		MIC:         strings.Repeat("11", 16),
		ANonce:      strings.Repeat("A1", 32),
		EAPOL:       strings.Repeat("22", 99),
	}

	line, err := h.Hashcat22000()
	if err != nil {
		t.Fatalf("Hashcat22000: %v", err)
	}

	parts := strings.Split(line, "*")
	if len(parts) != 9 {
		t.Fatalf("field count = %d, want 9 (%q)", len(parts), line)
	}
	if parts[0] != "WPA" || parts[1] != "02" {
		t.Fatalf("prefix = %q, want WPA*02", strings.Join(parts[:2], "*"))
	}
	if parts[2] != strings.Repeat("11", 16) {
		t.Fatalf("mic = %q", parts[2])
	}
	if parts[3] != "aabbccddeeff" || parts[4] != "020000beef02" {
		t.Fatalf("macs = %q/%q", parts[3], parts[4])
	}
	if parts[5] != "6c6162" {
		t.Fatalf("essid = %q, want 6c6162", parts[5])
	}
	if parts[6] != strings.Repeat("a1", 32) {
		t.Fatalf("anonce = %q", parts[6])
	}
	if parts[7] != strings.Repeat("22", 99) {
		t.Fatalf("eapol length = %d, want 198", len(parts[7]))
	}
	if parts[8] != "00" {
		t.Fatalf("message pair = %q, want 00", parts[8])
	}
}

// An unknown ESSID cannot be turned into a crackable line.
func TestHandshakeMissingESSID(t *testing.T) {
	h := Handshake{
		BSSID:       "AA:BB:CC:DD:EE:FF",
		STA:         "02:00:00:BE:EF:02",
		MessagePair: 0,
		MIC:         strings.Repeat("11", 16),
		ANonce:      strings.Repeat("a1", 32),
		EAPOL:       strings.Repeat("22", 99),
	}

	if _, err := h.Hashcat22000(); err == nil {
		t.Fatal("expected an error for a unit with no ESSID")
	}
}

// ssid_hex must win over the printable SSID so binary ESSIDs stay exact.
func TestHandshakeBinaryESSID(t *testing.T) {
	h := Handshake{
		BSSID:   "AA:BB:CC:DD:EE:FF",
		STA:     "02:00:00:BE:EF:02",
		SSID:    "ab",     // printable form loses the NUL byte
		SSIDHex: "610062", // a\0b
		PMKID:   strings.Repeat("ab", 16),
	}

	line, err := h.Hashcat22000()
	if err != nil {
		t.Fatalf("Hashcat22000: %v", err)
	}
	if !strings.Contains(line, "*610062*") {
		t.Fatalf("line = %q, want the binary ESSID 610062", line)
	}
}

// The daemon payload must decode into the Go structs unchanged.
func TestHandshakesDataDecode(t *testing.T) {
	raw := []byte(`{"count":1,"tracked":2,"offset":0,"returned":1,` +
		`"truncated":false,"handshakes":[{"bssid":"02:00:00:DE:AD:01",` +
		`"sta":"02:00:00:BE:EF:02","ssid":"mock-lab","ssid_len":8,` +
		`"ssid_hex":"6d6f636b2d6c6162","message_pair":0,"frames":2,` +
		`"anonce":"a1","mic":"11","pmkid":"","eapol":"22","eapol_len":99}]}`)

	var data HandshakesData
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if data.Count != 1 || data.Tracked != 2 || data.Truncated {
		t.Fatalf("header = %+v", data)
	}
	if len(data.Handshakes) != 1 {
		t.Fatalf("handshakes = %d, want 1", len(data.Handshakes))
	}
	h := data.Handshakes[0]
	if h.SSID != "mock-lab" || h.SSIDHex != "6d6f636b2d6c6162" || h.MessagePair != 0 {
		t.Fatalf("unit = %+v", h)
	}
}
