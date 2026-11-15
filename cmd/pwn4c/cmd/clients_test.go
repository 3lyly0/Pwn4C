package cmd

import (
	"testing"

	"github.com/3lyly0/Pwn4C/internal/drone"
)

func TestFormatAge(t *testing.T) {
	cases := []struct {
		ms   int64
		want string
	}{
		{-5, "0ms"},
		{0, "0ms"},
		{999, "999ms"},
		{1500, "1.5s"},
		{59_900, "59.9s"},
		{60_000, "1m00s"},
		{184_000, "3m04s"},
		{3_600_000, "1h00m"},
		{3_780_000, "1h03m"},
	}

	for _, tc := range cases {
		if got := formatAge(tc.ms); got != tc.want {
			t.Errorf("formatAge(%d) = %q, want %q", tc.ms, got, tc.want)
		}
	}
}

func TestClientSummary(t *testing.T) {
	assoc := drone.Client{
		STA:        "02:00:00:BE:EF:02",
		BSSID:      "02:00:00:DE:AD:01",
		Associated: true,
		Probed:     true,
		SSID:       "lab",
		HasRSSI:    true,
		RSSI:       -42,
	}
	got := clientSummary(assoc)
	want := `associated 02:00:00:de:ad:01 · pnl="lab" · -42 dBm`
	if got != want {
		t.Errorf("clientSummary = %q, want %q", got, want)
	}

	probe := drone.Client{STA: "02:00:00:BE:EF:03", Probed: true, SSID: "other"}
	if got := clientSummary(probe); got != `probing · pnl="other"` {
		t.Errorf("probe summary = %q", got)
	}

	seen := drone.Client{STA: "02:00:00:BE:EF:04"}
	if got := clientSummary(seen); got != "seen" {
		t.Errorf("seen summary = %q", got)
	}
}

// filterClients must apply the three filters and order associated stations
// first, then by descending signal.
func TestFilterClients(t *testing.T) {
	stations := []drone.Client{
		{STA: "02:00:00:00:00:01", BSSID: "02:00:00:DE:AD:01", Probed: true, HasRSSI: true, RSSI: -80},
		{STA: "02:00:00:00:00:02", BSSID: "02:00:00:DE:AD:01", Associated: true, HasRSSI: true, RSSI: -70},
		{STA: "02:00:00:00:00:03", BSSID: "02:00:00:DE:AD:02", Associated: true, HasRSSI: true, RSSI: -50},
		{STA: "02:00:00:00:00:04", BSSID: "02:00:00:DE:AD:01", Associated: true},
	}

	// No filters: associated first (strongest first), then the probe.
	defer func() {
		clientsBSSID, clientsAssoc, clientsMinRSSI = "", false, 0
	}()

	got := filterClients(stations)
	if len(got) != 4 {
		t.Fatalf("unfiltered count = %d, want 4", len(got))
	}
	if got[0].STA != "02:00:00:00:00:03" || got[1].STA != "02:00:00:00:00:02" {
		t.Errorf("associated order = %q, %q", got[0].STA, got[1].STA)
	}
	if got[3].STA != "02:00:00:00:00:01" {
		t.Errorf("probe should sort last, got %q", got[3].STA)
	}

	clientsAssoc = true
	if got = filterClients(stations); len(got) != 3 {
		t.Errorf("assoc-only count = %d, want 3", len(got))
	}

	clientsAssoc = false
	clientsBSSID = "02:00:00:de:ad:01"
	if got = filterClients(stations); len(got) != 3 {
		t.Errorf("bssid filter count = %d, want 3", len(got))
	}

	clientsBSSID = ""
	clientsMinRSSI = -60
	if got = filterClients(stations); len(got) != 1 || got[0].STA != "02:00:00:00:00:03" {
		t.Errorf("min-rssi filter = %+v", got)
	}
}
