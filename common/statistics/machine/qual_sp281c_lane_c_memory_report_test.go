package machine

import "testing"

// Exercise the supplied DTO's label order and formatting, not memory acquisition.
func TestQualSP281COrdinaryMachineMemoryReport(t *testing.T) {
	t.Parallel()

	stats := &MemStatistics{
		Total:        3 * 1024 * 1024 * 1024,
		PercentUsed:  42,
		UsedByGolang: 1536,
		UsedBySystem: 2 * 1024 * 1024,
		HeapInUse:    321,
		StackInUse:   2560,
	}
	const want = "total:3.00 GB, percent:42%, go:1.50 KB, sys:2.00 MB, heap:321 B, stack:2.50 KB"
	if got := stats.String(); got != want {
		t.Fatalf("memory report = %q; want %q", got, want)
	}
}
