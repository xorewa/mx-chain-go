package common_test

import (
	"testing"
	"time"

	"github.com/multiversx/mx-chain-go/common"
)

// These supplied calendar values check rollover, without reading a clock.
func TestQualSP281COrdinaryCalendarRounding(t *testing.T) {
	t.Parallel()

	input := time.Date(2030, time.December, 31, 23, 59, 30, 0, time.UTC)
	want := time.Date(2031, time.January, 1, 0, 1, 0, 0, time.UTC)
	if got := common.RoundToNearestMinute(input); !got.Equal(want) {
		t.Fatalf("rounded calendar time = %v; want %v", got, want)
	}
}
