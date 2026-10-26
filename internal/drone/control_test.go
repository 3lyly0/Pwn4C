package drone

import (
	"encoding/json"
	"testing"
)

// Older firmware reported only tx_frames (the stream sequence) and no
// inject_frames; InjectFrames must stay nil so callers do not print a bogus
// injection delta.
func TestStatusDataInjectFrames(t *testing.T) {
	legacy := []byte(`{"rx_frames":12054,"tx_frames":11980}`)
	var old StatusData
	if err := json.Unmarshal(legacy, &old); err != nil {
		t.Fatalf("legacy status: %v", err)
	}
	if old.InjectFrames != nil {
		t.Fatalf("legacy InjectFrames = %d, want nil", *old.InjectFrames)
	}
	if old.TxFrames != 11980 {
		t.Fatalf("legacy TxFrames = %d, want 11980", old.TxFrames)
	}

	current := []byte(`{"rx_frames":12054,"tx_frames":11980,"inject_frames":25}`)
	var st StatusData
	if err := json.Unmarshal(current, &st); err != nil {
		t.Fatalf("current status: %v", err)
	}
	if st.InjectFrames == nil || *st.InjectFrames != 25 {
		t.Fatalf("InjectFrames = %v, want 25", st.InjectFrames)
	}
}
