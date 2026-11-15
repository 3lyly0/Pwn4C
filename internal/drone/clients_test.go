package drone

import (
	"encoding/json"
	"testing"
)

// The daemon payload must decode into the Go structs unchanged, and the
// display helpers must normalise the uppercase MACs the daemon sends.
func TestClientsDataDecode(t *testing.T) {
	raw := []byte(`{"count":2,"tracked":2,"offset":0,"returned":2,` +
		`"truncated":false,"clients":[` +
		`{"sta":"02:00:00:BE:EF:02","bssid":"02:00:00:DE:AD:01",` +
		`"associated":true,"probed":true,"ssid":"mock-lab","ssid_len":8,` +
		`"ssid_hex":"6d6f636b2d6c6162","rssi":-42,"has_rssi":true,` +
		`"frames":3,"age_ms":120},` +
		`{"sta":"02:00:00:BE:EF:03","bssid":"","associated":false,` +
		`"probed":true,"ssid":"other-net","ssid_len":9,` +
		`"ssid_hex":"6f746865722d6e6574","rssi":0,"has_rssi":false,` +
		`"frames":1,"age_ms":80}]}`)

	var data ClientsData
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if data.Count != 2 || data.Tracked != 2 || data.Truncated {
		t.Fatalf("header = %+v", data)
	}
	if len(data.Clients) != 2 {
		t.Fatalf("clients = %d, want 2", len(data.Clients))
	}

	assoc := data.Clients[0]
	if assoc.DisplaySTA() != "02:00:00:be:ef:02" {
		t.Errorf("DisplaySTA = %q", assoc.DisplaySTA())
	}
	if assoc.DisplayBSSID() != "02:00:00:de:ad:01" {
		t.Errorf("DisplayBSSID = %q", assoc.DisplayBSSID())
	}
	if !assoc.Associated || !assoc.Probed || !assoc.HasRSSI || assoc.RSSI != -42 {
		t.Errorf("associated client = %+v", assoc)
	}
	if assoc.ProbeSSID() != "mock-lab" {
		t.Errorf("ProbeSSID = %q", assoc.ProbeSSID())
	}

	probeOnly := data.Clients[1]
	if probeOnly.DisplayBSSID() != "" {
		t.Errorf("probe-only BSSID should be empty, got %q", probeOnly.DisplayBSSID())
	}
	if probeOnly.Associated {
		t.Error("probe-only client must not be associated")
	}
	if probeOnly.ProbeSSID() != "other-net" {
		t.Errorf("ProbeSSID = %q", probeOnly.ProbeSSID())
	}
}

// A binary SSID has an empty printable form; the hex fallback must still show
// something usable instead of a blank column.
func TestClientProbeSSIDBinaryFallback(t *testing.T) {
	c := Client{STA: "02:00:00:BE:EF:02", Probed: true, SSIDHex: "610062"}
	if got := c.ProbeSSID(); got != "0x610062" {
		t.Fatalf("ProbeSSID = %q, want 0x610062", got)
	}
}

// A wildcard probe has neither a printable nor a hex SSID.
func TestClientProbeSSIDWildcard(t *testing.T) {
	c := Client{STA: "02:00:00:BE:EF:02", Probed: true}
	if got := c.ProbeSSID(); got != "" {
		t.Fatalf("ProbeSSID = %q, want empty", got)
	}
}
