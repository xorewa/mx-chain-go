package peer

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/sharding/nodesCoordinator"
	"github.com/multiversx/mx-chain-go/testscommon/shardingMocks"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Experimental byte-boundary inputs extend the inherited nine-validator check
// with assertions that malformed input causes no account access or write.
func TestQualPartialsG14BitmapRejectsBeforeAccounts(t *testing.T) {
	for _, size := range []int{1, 2, 8} {
		t.Run(fmt.Sprintf("bytes=%d", size), func(t *testing.T) {
			loads, saves := 0, 0
			accountError := errors.New("experimental G14 account lookup")
			vs := &validatorStatistics{peerAdapter: &stateMock.AccountsStub{
				LoadAccountCalled: func([]byte) (vmcommon.AccountHandler, error) {
					loads++
					return nil, accountError
				},
				SaveAccountCalled: func(vmcommon.AccountHandler) error { saves++; return nil },
			}}
			validators := make([]nodesCoordinator.Validator, size*8+1)
			for i := range validators {
				validators[i] = shardingMocks.NewValidatorMock([]byte(fmt.Sprintf("validator%d", i)), 1, uint32(i))
			}
			err := vs.updateValidatorInfoOnSuccessfulBlock(validators[0], validators, make([]byte, size), big.NewInt(0), 0, 0)
			require.ErrorIs(t, err, process.ErrInvalidPubKeysBitmap, "short bitmap guard")
			require.Zero(t, loads, "short bitmap must not load accounts")
			require.Zero(t, saves, "short bitmap must not save accounts")
			// Exactly enough bits must reach the real account-load boundary.
			err = vs.updateValidatorInfoOnSuccessfulBlock(validators[0], validators[:size*8], make([]byte, size), big.NewInt(0), 0, 0)
			require.ErrorIs(t, err, accountError, "equal bitmap boundary reaches account lookup")
			require.Equal(t, 1, loads)
			require.Zero(t, saves)
		})
	}
}
