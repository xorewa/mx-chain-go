package accounts

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryUserViewLabelSizes(t *testing.T) {
	t.Parallel()

	// These are opaque presentation labels, not real account identifiers.
	cases := []struct {
		view *UserAccountData
		size int
	}{
		{&UserAccountData{CodeHash: []byte("a")}, 9},
		{&UserAccountData{RootHash: []byte("bb")}, 10},
		{&UserAccountData{Address: []byte("ccc")}, 11},
		{&UserAccountData{OwnerAddress: []byte("dddd")}, 12},
		{&UserAccountData{CodeMetadata: []byte("eeeee")}, 13},
	}
	for _, tc := range cases {
		require.Equal(t, tc.size, tc.view.Size())
	}
}
