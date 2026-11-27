package compatibility

import (
	"slices"
	"sort"
	"testing"
)

func TestQualSP281COrdinarySortStringMultiplicity(t *testing.T) {
	input := []string{"pear", "apple", "pear", "lime", "apple", "plum", "lime", "pear"}
	want := []string{"apple", "apple", "lime", "lime", "pear", "pear", "pear", "plum"}

	Sort(sort.StringSlice(input))

	if !slices.Equal(input, want) {
		t.Fatalf("sorted labels: got %q, want %q", input, want)
	}
}
