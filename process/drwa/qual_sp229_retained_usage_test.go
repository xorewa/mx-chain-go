package drwa

import "testing"

// expectedToyUsage is independent arithmetic for small, fictional objects.
// It uses prospective totals rather than the production charge sequence.
// No state, storage, identity, enrollment or transaction is involved.
func expectedToyUsage(u retainedUsage, limits scopedAdmissionLimits, key, old, item int, growth bool) (retainedUsage, bool) {
	if u.count > limits.records || u.size > limits.retainedBytes || u.rate > limits.newRecordsPerEpoch {
		return u, false
	}
	count, size, rate := int(u.count), int(u.size), int(u.rate)
	if old == 0 {
		count, size, rate = count+1, size+key+item, rate+1
	} else {
		if item < old || (item != old && !growth) {
			return u, false
		}
		size += item - old
	}
	if count > int(limits.records) || size > int(limits.retainedBytes) || rate > int(limits.newRecordsPerEpoch) {
		return u, false
	}
	return retainedUsage{count: uint64(count), size: uint64(size), rate: uint64(rate)}, true
}

func TestQualSP229RetainedUsageArithmetic(t *testing.T) {
	// These are arbitrary experimental units, not proposed network limits.
	limits := scopedAdmissionLimits{records: 5, retainedBytes: 30, newRecordsPerEpoch: 4, recordBytes: 10}
	for _, tt := range []struct {
		name           string
		usage          retainedUsage
		key, old, item int
		growth         bool
	}{
		{"nominal object", retainedUsage{1, 9, 1}, 2, 0, 3, false},
		{"unchanged size", retainedUsage{2, 14, 2}, 2, 3, 3, false},
		{"positive growth", retainedUsage{2, 14, 2}, 2, 3, 5, true},
		{"count equal", retainedUsage{4, 12, 2}, 2, 0, 3, false},
		{"count over", retainedUsage{5, 12, 2}, 2, 0, 3, false},
		{"rate equal", retainedUsage{3, 12, 3}, 2, 0, 3, false},
		{"rate over", retainedUsage{3, 12, 4}, 2, 0, 3, false},
		{"size equal", retainedUsage{3, 25, 2}, 2, 0, 3, false},
		{"size over", retainedUsage{3, 26, 2}, 2, 0, 3, false},
		{"size contribution exceeds remaining", retainedUsage{3, 29, 2}, 2, 0, 3, false},
		{"growth at size", retainedUsage{3, 28, 2}, 2, 3, 5, true},
		{"growth exceeds size", retainedUsage{3, 29, 2}, 2, 3, 5, true},
		{"fixed size change", retainedUsage{3, 14, 2}, 2, 3, 4, false},
		{"size reduction", retainedUsage{3, 14, 2}, 2, 3, 2, true},
		{"invalid aggregate count", retainedUsage{6, 14, 2}, 2, 0, 3, false},
		{"invalid aggregate units", retainedUsage{3, 31, 2}, 2, 0, 3, false},
		{"invalid aggregate rate", retainedUsage{3, 14, 5}, 2, 0, 3, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			want, accepted := expectedToyUsage(tt.usage, limits, tt.key, tt.old, tt.item, tt.growth)
			got, err := chargeRetainedUsage(tt.usage, limits,
				uint64(tt.key), uint64(tt.old), uint64(tt.item), tt.growth)
			if (err == nil) != accepted || got != want {
				t.Fatalf("aggregate model mismatch: got %#v (accepted=%t), want %#v (accepted=%t)", got, err == nil, want, accepted)
			}
		})
	}
}
