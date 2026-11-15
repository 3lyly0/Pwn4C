package cmd

import (
	"testing"
)

// validateEvilTwinFlags must reject a twin that cannot work before a control
// connection is opened. Globals are restored after the test.
func TestValidateEvilTwinFlags(t *testing.T) {
	origBSSID, origSSID, origChannel := eviltwinBSSID, eviltwinSSID, eviltwinChannel
	origPass, origDuration := eviltwinPassphrase, eviltwinDuration
	origKick := eviltwinKickCount
	defer func() {
		eviltwinBSSID, eviltwinSSID, eviltwinChannel = origBSSID, origSSID, origChannel
		eviltwinPassphrase, eviltwinDuration = origPass, origDuration
		eviltwinKickCount = origKick
	}()

	cases := []struct {
		name    string
		bssid   string
		ssid    string
		channel int
		pass    string
		dur     int
		kick    int
		wantErr bool
	}{
		{"valid wpa2", "02:00:00:de:ad:01", "mock-lab", 6, "supersecret", 0, 8, false},
		{"valid open", "02:00:00:de:ad:01", "mock-lab", 1, "", 120, 8, false},
		{"missing bssid", "", "mock-lab", 6, "", 0, 8, true},
		{"missing ssid", "02:00:00:de:ad:01", "", 6, "", 0, 8, true},
		{"bad bssid", "nope", "mock-lab", 6, "", 0, 8, true},
		{"broadcast bssid", "ff:ff:ff:ff:ff:ff", "mock-lab", 6, "", 0, 8, true},
		{"channel 0", "02:00:00:de:ad:01", "mock-lab", 0, "", 0, 8, true},
		{"channel 14", "02:00:00:de:ad:01", "mock-lab", 14, "", 0, 8, true},
		{"short passphrase", "02:00:00:de:ad:01", "mock-lab", 6, "short", 0, 8, true},
		{"negative duration", "02:00:00:de:ad:01", "mock-lab", 6, "", -1, 8, true},
		{"huge duration", "02:00:00:de:ad:01", "mock-lab", 6, "", 86_401, 8, true},
		{"zero kick count", "02:00:00:de:ad:01", "mock-lab", 6, "", 0, 0, true},
		{"huge kick count", "02:00:00:de:ad:01", "mock-lab", 6, "", 0, 1001, true},
	}

	for _, tc := range cases {
		eviltwinBSSID = tc.bssid
		eviltwinSSID = tc.ssid
		eviltwinChannel = tc.channel
		eviltwinPassphrase = tc.pass
		eviltwinDuration = tc.dur
		eviltwinKickCount = tc.kick

		err := validateEvilTwinFlags()
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", tc.name, err, tc.wantErr)
		}
	}
}
