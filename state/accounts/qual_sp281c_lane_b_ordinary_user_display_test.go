package accounts

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryUserViewDisplay(t *testing.T) {
	t.Parallel()

	view := &UserAccountData{Nonce: 17, UserName: []byte("toy")}
	require.Equal(t, "&UserAccountData{Nonce:17,Balance:<nil>,CodeHash:[],RootHash:[],Address:[],DeveloperReward:<nil>,OwnerAddress:[],UserName:[116 111 121],CodeMetadata:[],}", view.String())
	require.Equal(t, "&accounts.UserAccountData{Nonce: 0x11,\nBalance: <nil>,\nCodeHash: []byte(nil),\nRootHash: []byte(nil),\nAddress: []byte(nil),\nDeveloperReward: <nil>,\nOwnerAddress: []byte(nil),\nUserName: []byte{0x74, 0x6f, 0x79},\nCodeMetadata: []byte(nil),\n}", view.GoString())

	var absent *UserAccountData
	require.Equal(t, "nil", absent.String())
	require.Equal(t, "nil", absent.GoString())
}
