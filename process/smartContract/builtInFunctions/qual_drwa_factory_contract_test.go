package builtInFunctions

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/testscommon"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	vmcommonBuiltins "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// Deliberately incomplete, test-only wrapper. A future protected wrapper must
// not conceal an optional interface required by the native factory.
type qualDRWABaseOnlyBuiltin struct {
	vmcommon.BuiltinFunction
}

// Part B 16.2 requires preservation of optional native interfaces. This observes
// the upstream factory; it does not implement or qualify a DRWA wrapper.
func TestQualDRWAFactoryOptionalInterfaces(t *testing.T) {
	for _, name := range []string{
		core.BuiltInFunctionESDTTransfer,
		core.BuiltInFunctionESDTNFTTransfer,
		core.BuiltInFunctionMultiESDTNFTTransfer,
	} {
		t.Run("payment/"+name, func(t *testing.T) {
			factory, err := CreateBuiltInFunctionsFactory(createMockArguments())
			require.NoError(t, err)
			container := factory.BuiltInFunctionContainer()
			original, err := container.Get(name)
			require.NoError(t, err)
			_, acceptsPayment := original.(vmcommon.AcceptPayableChecker)
			require.True(t, acceptsPayment)
			require.NoError(t, container.Replace(name, &qualDRWABaseOnlyBuiltin{original}))
			require.ErrorIs(t, factory.SetPayableHandler(&testscommon.BlockChainHookStub{}), vmcommonBuiltins.ErrWrongTypeAssertion)
			require.NoError(t, container.Replace(name, original))
			require.NoError(t, factory.SetPayableHandler(&testscommon.BlockChainHookStub{}))
		})
	}
	for _, name := range []string{
		core.BuiltInFunctionESDTNFTAddURI,
		core.BuiltInFunctionESDTNFTUpdateAttributes,
		core.ESDTMetaDataRecreate,
		core.ESDTMetaDataUpdate,
		core.ESDTSetNewURIs,
		core.ESDTModifyRoyalties,
		core.ESDTModifyCreator,
	} {
		t.Run("time/"+name, func(t *testing.T) {
			factory, err := CreateBuiltInFunctionsFactory(createMockArguments())
			require.NoError(t, err)
			container := factory.BuiltInFunctionContainer()
			original, err := container.Get(name)
			require.NoError(t, err)
			provider, suppliesTime := original.(vmcommon.BlockchainDataProvider)
			require.True(t, suppliesTime)
			require.NoError(t, factory.SetBlockchainHook(&testscommon.BlockChainHookStub{
				CurrentRoundCalled: func() uint64 { return 17 },
			}))
			require.Equal(t, uint64(17), provider.CurrentRound())
			require.NoError(t, container.Replace(name, &qualDRWABaseOnlyBuiltin{original}))
			later := &testscommon.BlockChainHookStub{CurrentRoundCalled: func() uint64 { return 29 }}
			// Native injection silently skips an object that no longer exposes
			// BlockchainDataProvider. A nil error alone is not sufficient proof.
			require.NoError(t, factory.SetBlockchainHook(later))
			require.Equal(t, uint64(17), provider.CurrentRound())
			require.NoError(t, container.Replace(name, original))
			require.NoError(t, factory.SetBlockchainHook(later))
			require.Equal(t, uint64(29), provider.CurrentRound())
		})
	}
}
