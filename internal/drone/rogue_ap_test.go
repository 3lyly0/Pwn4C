package drone

import (
	"encoding/json"
	"strings"
	"testing"
)

// The daemon payload must decode field-for-field, including the monitor flag
// and the DHCP status.
func TestRogueAPDataDecode(t *testing.T) {
	raw := []byte(`{"active":true,"ssid":"mock-lab","bssid":"02:00:00:DE:AD:01",` +
		`"channel":6,"hidden":false,"security":"wpa2-psk","interface":"pwn4c-ap",` +
		`"ip":"192.168.66.1","clients":2,"uptime_sec":12,"hostapd":true,` +
		`"dnsmasq":true,"monitor_active":true}`)

	var data RogueAPData
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !data.Active || data.SSID != "mock-lab" || data.Channel != 6 {
		t.Fatalf("header = %+v", data)
	}
	if data.Security != "wpa2-psk" || !data.IsWPA() {
		t.Errorf("security = %q", data.Security)
	}
	if data.Interface != "pwn4c-ap" || data.IP != "192.168.66.1" {
		t.Errorf("interface/ip = %q/%q", data.Interface, data.IP)
	}
	if data.Clients != 2 || data.UptimeSec != 12 {
		t.Errorf("clients/uptime = %d/%d", data.Clients, data.UptimeSec)
	}
	if !data.Hostapd || !data.Dnsmasq || !data.MonitorActive {
		t.Errorf("flags = %+v", data)
	}
	if data.DisplayBSSID() != "02:00:00:de:ad:01" {
		t.Errorf("DisplayBSSID = %q", data.DisplayBSSID())
	}
}

// A stopped twin is just {"active":false}; every other field must stay zero.
func TestRogueAPDataInactive(t *testing.T) {
	var data RogueAPData
	if err := json.Unmarshal([]byte(`{"active":false}`), &data); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if data.Active || data.IsWPA() || data.DisplayBSSID() != "" {
		t.Fatalf("inactive payload = %+v", data)
	}
}

func TestRogueAPDataOpen(t *testing.T) {
	data := RogueAPData{Security: "open"}
	if data.IsWPA() {
		t.Fatal("an open twin must not report WPA")
	}
}

func TestValidateRogueAPParams(t *testing.T) {
	base := RogueAPParams{
		SSID:    "mock-lab",
		BSSID:   "02:00:00:de:ad:01",
		Channel: 6,
	}

	ok := []struct {
		name string
		p    RogueAPParams
	}{
		{"open", base},
		{"wpa2", RogueAPParams{SSID: base.SSID, BSSID: base.BSSID, Channel: 6, Passphrase: "supersecret"}},
		{"hidden", RogueAPParams{SSID: base.SSID, BSSID: base.BSSID, Channel: 13, Hidden: true}},
		{"32-byte ssid", RogueAPParams{SSID: strings.Repeat("a", 32), BSSID: base.BSSID, Channel: 1}},
		{"63-char pass", RogueAPParams{SSID: base.SSID, BSSID: base.BSSID, Channel: 1, Passphrase: strings.Repeat("p", 63)}},
	}
	for _, tc := range ok {
		if err := ValidateRogueAPParams(tc.p); err != nil {
			t.Errorf("%s: unexpected error: %v", tc.name, err)
		}
	}

	bad := []struct {
		name string
		p    RogueAPParams
	}{
		{"empty ssid", RogueAPParams{SSID: "", BSSID: base.BSSID, Channel: 6}},
		{"33-byte ssid", RogueAPParams{SSID: strings.Repeat("a", 33), BSSID: base.BSSID, Channel: 6}},
		{"bad bssid", RogueAPParams{SSID: base.SSID, BSSID: "nope", Channel: 6}},
		{"broadcast bssid", RogueAPParams{SSID: base.SSID, BSSID: "ff:ff:ff:ff:ff:ff", Channel: 6}},
		{"multicast bssid", RogueAPParams{SSID: base.SSID, BSSID: "01:00:5e:00:00:01", Channel: 6}},
		{"channel 0", RogueAPParams{SSID: base.SSID, BSSID: base.BSSID, Channel: 0}},
		{"channel 14", RogueAPParams{SSID: base.SSID, BSSID: base.BSSID, Channel: 14}},
		{"short passphrase", RogueAPParams{SSID: base.SSID, BSSID: base.BSSID, Channel: 6, Passphrase: "short"}},
		{"64-char passphrase", RogueAPParams{SSID: base.SSID, BSSID: base.BSSID, Channel: 6, Passphrase: strings.Repeat("p", 64)}},
	}
	for _, tc := range bad {
		if err := ValidateRogueAPParams(tc.p); err == nil {
			t.Errorf("%s: expected an error", tc.name)
		}
	}
}
