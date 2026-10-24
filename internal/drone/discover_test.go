package drone

import (
	"net"
	"testing"
	"time"
)

func TestSubnetBroadcast(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		mask net.IPMask
		want string
	}{
		{
			name: "slash24",
			ip:   "192.168.4.185",
			mask: net.CIDRMask(24, 32),
			want: "192.168.4.255",
		},
		{
			name: "slash8",
			ip:   "10.1.2.3",
			mask: net.CIDRMask(8, 32),
			want: "10.255.255.255",
		},
		{
			name: "slash20_hyperv",
			ip:   "172.18.0.1",
			mask: net.CIDRMask(20, 32),
			want: "172.18.15.255",
		},
		{
			// A /32 has no directed broadcast; the caller must skip it
			// because it equals the interface address.
			name: "slash32",
			ip:   "192.168.4.1",
			mask: net.CIDRMask(32, 32),
			want: "192.168.4.1",
		},
		{
			name: "ipv6_mask_is_trimmed",
			ip:   "192.168.4.185",
			mask: net.CIDRMask(120, 128),
			want: "192.168.4.255",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := subnetBroadcast(net.ParseIP(tc.ip), tc.mask)
			if got == nil {
				t.Fatalf("subnetBroadcast(%s) = nil, want %s", tc.ip, tc.want)
			}
			if got.String() != tc.want {
				t.Fatalf("subnetBroadcast(%s) = %s, want %s", tc.ip, got, tc.want)
			}
		})
	}

	if got := subnetBroadcast(net.ParseIP("2001:db8::1"), net.CIDRMask(64, 128)); got != nil {
		t.Fatalf("subnetBroadcast(IPv6) = %s, want nil", got)
	}
	if got := subnetBroadcast(net.ParseIP("192.168.4.1"), nil); got != nil {
		t.Fatalf("subnetBroadcast(nil mask) = %s, want nil", got)
	}
}

func TestProbeTargetsUnknownInterface(t *testing.T) {
	if _, err := probeTargets("pwn4c-no-such-interface"); err == nil {
		t.Fatal("probeTargets accepted a non-existent interface")
	}
}

func TestProbeTargetsSkipsLoopback(t *testing.T) {
	targets, err := probeTargets("")
	if err != nil {
		t.Fatalf("probeTargets: %v", err)
	}

	for _, target := range targets {
		if target.Interface == "" {
			t.Error("target has an empty interface name")
		}
		if target.IP == nil || target.IP.To4() == nil {
			t.Errorf("%s: target IP %v is not IPv4", target.Interface, target.IP)
		}
		if target.IP.IsLoopback() {
			t.Errorf("%s: loopback address %s was not filtered", target.Interface, target.IP)
		}
		if target.IP.IsLinkLocalUnicast() {
			t.Errorf("%s: link-local address %s was not filtered", target.Interface, target.IP)
		}
	}
}

func TestDiscoverRejectsUnknownInterface(t *testing.T) {
	if _, err := Discover(time.Second, "pwn4c-no-such-interface"); err == nil {
		t.Fatal("Discover accepted a non-existent interface")
	}
}

func TestParseAnnounce(t *testing.T) {
	from := &net.UDPAddr{IP: net.ParseIP("192.168.4.1"), Port: DefaultDiscoveryPort}

	t.Run("valid", func(t *testing.T) {
		drone, ok := parseAnnounce(datagram{
			from: from,
			data: []byte(`{"type":"ANNOUNCE","version":1,"drone_id":"pwn4c-89db",` +
				`"firmware_version":"1.0.0","hardware":"mi-router-4c","uptime_seconds":42,` +
				`"capabilities":["monitor"],"radio":{"chipset":"mt7628","band":"2.4","state":"idle"},` +
				`"control_port":4444,"stream_port":5555}`),
		})
		if !ok {
			t.Fatal("valid ANNOUNCE was rejected")
		}
		if drone.IP != "192.168.4.1" {
			t.Errorf("IP = %q, want 192.168.4.1", drone.IP)
		}
		if drone.Port != 4444 {
			t.Errorf("Port = %d, want 4444", drone.Port)
		}
		if drone.Announce.DroneID != "pwn4c-89db" {
			t.Errorf("DroneID = %q", drone.Announce.DroneID)
		}
	})

	t.Run("missing_control_port_defaults", func(t *testing.T) {
		drone, ok := parseAnnounce(datagram{
			from: from,
			data: []byte(`{"type":"ANNOUNCE","version":1,"drone_id":"x"}`),
		})
		if !ok {
			t.Fatal("ANNOUNCE without control_port was rejected")
		}
		if drone.Port != DefaultControlPort {
			t.Errorf("Port = %d, want %d", drone.Port, DefaultControlPort)
		}
	})

	t.Run("wrong_type", func(t *testing.T) {
		if _, ok := parseAnnounce(datagram{from: from, data: []byte(`{"type":"ERROR"}`)}); ok {
			t.Fatal("non-ANNOUNCE packet was accepted")
		}
	})

	t.Run("garbage", func(t *testing.T) {
		if _, ok := parseAnnounce(datagram{from: from, data: []byte("not json")}); ok {
			t.Fatal("garbage was accepted")
		}
	})
}
