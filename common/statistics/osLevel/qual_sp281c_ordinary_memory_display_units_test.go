package osLevel

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryMemoryDisplayUnits(t *testing.T) {
	t.Parallel()

	const (
		kib = 1024
		mib = kib * 1024
		gib = mib * 1024
	)
	// These values are synthetic DTO fields, not observed memory statistics.
	stats := &MemStats{
		VmPeak:   0,
		VmSize:   1,
		VmLck:    kib - 1,
		VmPin:    kib,
		VmHWM:    kib + kib/2,
		VmRSS:    mib,
		RssAnon:  mib + mib/2,
		RssFile:  gib,
		RssShmem: gib + gib/2,
		VmData:   2 * kib,
		VmStk:    2 * mib,
		VmExe:    2 * gib,
		VmLib:    10,
		VmPTE:    512,
		VmSwap:   3 * gib,
	}

	want := "VmPeak: 0 B, VmSize: 1 B, VmLck: 1023 B, VmPin: 1.00 KB, VmHWM: 1.50 KB, VmRSS: 1.00 MB, " +
		"RssAnon: 1.50 MB, RssFile: 1.00 GB, RssShmem: 1.50 GB, VmData: 2.00 KB, VmStk: 2.00 MB, " +
		"VmExe: 2.00 GB, VmLib: 10 B, VmPTE: 512 B, VmSwap: 3.00 GB"
	require.Equal(t, want, stats.String())
}
