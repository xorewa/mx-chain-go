package ntp

import (
	"testing"
	"time"
)

// The formatter accepts a supplied time value. No clock or synchronization is used.
func TestQualSP281COrdinaryTimeDisplay(t *testing.T) {
	t.Parallel()

	formatter := &syncTime{}
	for _, tc := range []struct {
		name  string
		input time.Time
		want  string
	}{
		{"zero_fraction", time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC), "2030-01-02 03:04:05.000000000 "},
		{"leading_fraction_zeroes", time.Date(2030, time.January, 2, 3, 4, 5, 7, time.UTC), "2030-01-02 03:04:05.000000007 "},
		{"full_fraction", time.Date(2024, time.December, 31, 23, 59, 58, 987654321, time.UTC), "2024-12-31 23:59:58.987654321 "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatter.formatTime(tc.input); got != tc.want {
				t.Fatalf("formatTime(%v) = %q; want %q", tc.input, got, tc.want)
			}
		})
	}
}
