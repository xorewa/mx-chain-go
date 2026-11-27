package accounts

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryUserViewDTOGetters(t *testing.T) {
	addressDisplay := bytes.Repeat([]byte{0x42}, 32)
	value := &UserAccountData{Address: addressDisplay, Nonce: 7}
	require.Equal(t, addressDisplay, value.GetAddress())
	require.Equal(t, uint64(7), value.GetNonce())

	var absent *UserAccountData
	require.Nil(t, absent.GetAddress())
	require.Zero(t, absent.GetNonce())
}
