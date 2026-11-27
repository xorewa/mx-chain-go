package accounts

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryUserReportingDTOGetters(t *testing.T) {
	value := &UserAccountData{
		Balance: new(big.Int).Lsh(big.NewInt(1), 70), DeveloperReward: big.NewInt(25), UserName: []byte("ordinary-display"),
	}
	require.Equal(t, "1180591620717411303424", value.GetBalance().String())
	require.Equal(t, "25", value.GetDeveloperReward().String())
	require.Equal(t, []byte("ordinary-display"), value.GetUserName())

	var absent *UserAccountData
	require.Nil(t, absent.GetBalance())
	require.Nil(t, absent.GetDeveloperReward())
	require.Nil(t, absent.GetUserName())
}
