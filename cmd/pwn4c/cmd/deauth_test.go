package cmd

import "testing"

func TestIsBroadcastMAC(t *testing.T) {
	cases := []struct {
		mac  string
		want bool
	}{
		{"", true},
		{"ff:ff:ff:ff:ff:ff", true},
		{"FF:FF:FF:FF:FF:FF", true},
		{"ff-ff-ff-ff-ff-ff", true},
		{"11:22:33:44:55:66", false},
		{"ff:ff:ff:ff:ff:00", false},
		{"not-a-mac", false},
		{"ff:ff:ff:ff:ff", false},
	}

	for _, tc := range cases {
		if got := isBroadcastMAC(tc.mac); got != tc.want {
			t.Errorf("isBroadcastMAC(%q) = %v, want %v", tc.mac, got, tc.want)
		}
	}
}

func TestClientLabel(t *testing.T) {
	if got := clientLabel("ff:ff:ff:ff:ff:ff"); got != "Broadcast (All Clients)" {
		t.Errorf("broadcast label = %q", got)
	}
	if got := clientLabel("12:22:33:44:55:66"); got != "12:22:33:44:55:66" {
		t.Errorf("unicast label = %q", got)
	}
}

func TestIsGroupMAC(t *testing.T) {
	cases := []struct {
		mac  string
		want bool
	}{
		{"ff:ff:ff:ff:ff:ff", true},
		{"11:22:33:44:55:66", true},  // I/G bit set
		{"01:00:5e:00:00:01", true},  // IPv4 multicast
		{"12:22:33:44:55:66", false}, // locally administered unicast
		{"aa:bb:cc:dd:ee:ff", false}, // unicast
		{"not-a-mac", false},
	}
	for _, tc := range cases {
		if got := isGroupMAC(tc.mac); got != tc.want {
			t.Errorf("isGroupMAC(%q) = %v, want %v", tc.mac, got, tc.want)
		}
	}
}
