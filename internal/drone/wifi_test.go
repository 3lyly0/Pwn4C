package drone

import (
	"encoding/json"
	"testing"
)

// WIFI_CONNECT must always carry an explicit share flag: the daemon defaults
// to sharing when the key is absent, so omitting it would make --no-share a
// no-op against newer firmware.
func TestWifiConnectParams(t *testing.T) {
	p := wifiConnectParams("TestNet", "", "", "", true)
	if p["ssid"] != "TestNet" {
		t.Fatalf("ssid = %v", p["ssid"])
	}
	if p["share"] != true {
		t.Fatalf("share = %v, want true", p["share"])
	}
	for _, absent := range []string{"psk", "bssid", "encryption"} {
		if _, ok := p[absent]; ok {
			t.Fatalf("%s should be omitted when empty", absent)
		}
	}

	p = wifiConnectParams("TestNet", "p@ssw0rd!", "aa:bb:cc:dd:ee:ff", "sae-mixed", false)
	if p["share"] != false {
		t.Fatalf("share = %v, want false", p["share"])
	}
	if p["psk"] != "p@ssw0rd!" || p["bssid"] != "aa:bb:cc:dd:ee:ff" || p["encryption"] != "sae-mixed" {
		t.Fatalf("optional fields not forwarded: %+v", p)
	}
}

// Older firmware omits "sharing"; the zero value must read as "not sharing"
// so the CLI does not claim NAT that is not installed.
func TestWifiLinkStatusSharing(t *testing.T) {
	var legacy WifiLinkStatus
	if err := json.Unmarshal([]byte(`{"connected":true,"ssid":"TestNet"}`), &legacy); err != nil {
		t.Fatalf("legacy status: %v", err)
	}
	if legacy.Sharing {
		t.Fatal("legacy Sharing = true, want false")
	}

	var current WifiLinkStatus
	if err := json.Unmarshal([]byte(`{"connected":true,"sharing":true}`), &current); err != nil {
		t.Fatalf("current status: %v", err)
	}
	if !current.Sharing {
		t.Fatal("Sharing = false, want true")
	}
}
