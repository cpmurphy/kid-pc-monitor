package format

import (
	"testing"
	"time"
)

func TestSnapshotDayLabel(t *testing.T) {
	now := time.Date(2026, 11, 8, 10, 0, 0, 0, time.FixedZone("", -6*3600))
	cases := []struct{ in, want string }{
		{"2026-11-08T07:15:00-06:00", "Today"},
		{"2026-11-07T18:13:27-06:00", "Yesterday"},
		{"2026-11-04T18:13:27-06:00", "Nov 4"},
		{"2026-11-08T02:00:00+00:00", "Yesterday"}, // 8pm Nov 7 at -06:00
		{"2026-11-04T18:13:27", "Nov 4"},
		{"", ""},
		{"not a time", ""},
	}
	for _, c := range cases {
		if got := SnapshotDayLabel(c.in, now); got != c.want {
			t.Errorf("SnapshotDayLabel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
