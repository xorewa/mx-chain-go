package accounts

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryUserViewLabelGetters(t *testing.T) {
	t.Parallel()

	// Opaque invented labels for presentation only, not account identifiers.
	view := &UserAccountData{
		CodeHash:     []byte("code-label"),
		RootHash:     []byte("root-label"),
		OwnerAddress: []byte("owner-label"),
		CodeMetadata: []byte("display-metadata"),
	}
	require.Equal(t, "code-label", string(view.GetCodeHash()))
	require.Equal(t, "root-label", string(view.GetRootHash()))
	require.Equal(t, "owner-label", string(view.GetOwnerAddress()))
	require.Equal(t, "display-metadata", string(view.GetCodeMetadata()))

	var absent *UserAccountData
	require.Nil(t, absent.GetCodeHash())
	require.Nil(t, absent.GetRootHash())
	require.Nil(t, absent.GetOwnerAddress())
	require.Nil(t, absent.GetCodeMetadata())
}
