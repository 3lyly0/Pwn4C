package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateFloodFlags(t *testing.T) {
	cases := []struct {
		name                          string
		channel, count, interval, dur int
		rate                          float64
		wantErr                       bool
	}{
		{"defaults", 6, 1000, 0, 0, 1, false},
		{"until ctrl+c", 1, 0, 0, 0, 1, false},
		{"duration only", 11, 0, 0, 60, 1, false},
		{"channel 0", 0, 10, 0, 0, 1, true},
		{"channel 14", 14, 10, 0, 0, 1, true},
		{"negative count", 6, -1, 0, 0, 1, true},
		{"huge count", 6, 10_000_001, 0, 0, 1, true},
		{"negative interval", 6, 10, -1, 0, 1, true},
		{"interval too long", 6, 10, 5001, 0, 1, true},
		{"negative duration", 6, 10, 0, -1, 1, true},
		{"zero rate", 6, 10, 0, 0, 0, true},
		{"rate too high", 6, 10, 0, 0, 55, true},
	}

	for _, tc := range cases {
		err := validateFloodFlags(tc.channel, tc.count, tc.interval, tc.dur, tc.rate)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", tc.name, err, tc.wantErr)
		}
	}
}

func TestLoadSSIDFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "names.txt")

	content := "TP-LINK_1\n\n# a comment\nFree WiFi\r\n" + "0123456789012345678901234567890123456789\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	ssids, err := loadSSIDFile(path)
	if err != nil {
		t.Fatalf("loadSSIDFile: %v", err)
	}
	if len(ssids) != 3 {
		t.Fatalf("got %d SSIDs, want 3 (%q)", len(ssids), ssids)
	}
	if ssids[0] != "TP-LINK_1" {
		t.Errorf("ssids[0] = %q", ssids[0])
	}
	if ssids[1] != "Free WiFi" {
		t.Errorf("ssids[1] = %q (CR not trimmed?)", ssids[1])
	}
	if len(ssids[2]) != 32 {
		t.Errorf("over-long SSID should be truncated to 32 bytes, got %d", len(ssids[2]))
	}
}

func TestLoadSSIDFileErrors(t *testing.T) {
	if _, err := loadSSIDFile(filepath.Join(t.TempDir(), "missing.txt")); err == nil {
		t.Error("missing file should fail")
	}

	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(empty, []byte("# nothing here\n\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := loadSSIDFile(empty); err == nil {
		t.Error("a file with no SSIDs should fail")
	}
}
