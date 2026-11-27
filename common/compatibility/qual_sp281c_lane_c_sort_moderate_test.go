package compatibility

import (
	"slices"
	"sort"
	"testing"
)

func TestQualSP281COrdinarySortModerateStringList(t *testing.T) {
	input := []string{
		"plum", "apple", "pear", "lime", "peach", "cherry",
		"pear", "mango", "apple", "plum", "fig", "lime",
		"melon", "peach", "fig", "apple", "mango", "plum",
		"cherry", "pear", "melon", "lime", "fig", "peach",
	}
	want := slices.Clone(input)
	slices.Sort(want)

	Sort(sort.StringSlice(input))

	if !slices.Equal(input, want) {
		t.Fatalf("sorted labels: got %q, want %q", input, want)
	}
}
