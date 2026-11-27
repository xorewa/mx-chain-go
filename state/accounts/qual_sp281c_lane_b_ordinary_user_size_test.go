package accounts

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryUserViewEncodedSize(t *testing.T) {
	t.Parallel()

	cases := []struct {
		view *UserAccountData
		size int
	}{
		{nil, 0},
		{&UserAccountData{}, 6},
		{&UserAccountData{Nonce: 17, UserName: []byte("toy")}, 13},
		{&UserAccountData{Nonce: 128, UserName: []byte("toy")}, 14},
	}
	for _, tc := range cases {
		require.Equal(t, tc.size, tc.view.Size())
		require.Equal(t, tc.size, tc.view.XXX_Size())
	}
}
