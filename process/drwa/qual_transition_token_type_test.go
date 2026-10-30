package drwa

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// Native admission only. No shard classifier/guard is installed here; SP2-25/68 retain that restriction.
func TestQualTransitionR17TokenTypeNative(t *testing.T) {
	for _, mode := range []string{"ordinary", "direct ordinary", "nil input", "nil value", "nonzero value", "short arity", "long arity", "caller", "recipient", "late save"} {
		t.Run(mode+" should admit before settings write", func(t *testing.T) {
			store := qualRegistrationStore(t, 0)
			marshaller := &marshal.GogoProtoMarshalizer{}
			settings, err := builtInFunctions.NewESDTGlobalSettingsFunc(store, marshaller, true, core.BuiltInFunctionESDTPause, func() bool { return true })
			require.NoError(t, err)
			function, err := builtInFunctions.NewESDTSetTokenTypeFunc(store, settings, marshaller, func() bool { return true })
			require.NoError(t, err)
			coordinator, err := sharding.NewMultiShardCoordinator(3, 1)
			require.NoError(t, err)
			recipient := bytes.Clone(core.SystemAccountAddress)
			recipient[len(recipient)-1] = byte(coordinator.SelfId())
			require.Equal(t, uint32(1), coordinator.ComputeId(recipient))
			require.Equal(t, uint32(core.MetachainShardId), coordinator.ComputeId(core.ESDTSCAddress))
			require.True(t, vmcommon.IsSystemAccountAddress(recipient))
			require.NotEqual(t, core.SystemAccountAddress, recipient)
			tokenID := []byte("TOKEN-abcdef")
			key := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), tokenID...)
			prior := (&builtInFunctions.ESDTGlobalMetadata{Paused: true, LimitedTransfer: true}).ToBytes()
			account, err := store.LoadAccount(core.SystemAccountAddress)
			require.NoError(t, err)
			require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(key, prior))
			require.NoError(t, store.SaveAccount(account))
			caller, err := store.LoadAccount(core.ESDTSCAddress)
			require.NoError(t, err)
			require.NoError(t, store.SaveAccount(caller))
			root, err := store.Commit()
			require.NoError(t, err)
			input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(core.ESDTSCAddress), CallValue: big.NewInt(0), Arguments: [][]byte{tokenID, []byte(core.NonFungibleESDTv2)}}, RecipientAddr: recipient, Function: core.ESDTSetTokenType}
			var expected error
			switch mode {
			case "nil input":
				input = nil
				expected = builtInFunctions.ErrNilVmInput
			case "nil value":
				input.CallValue = nil
				expected = builtInFunctions.ErrNilValue
			case "nonzero value":
				input.CallValue = big.NewInt(1)
				expected = builtInFunctions.ErrBuiltInFunctionCalledWithValue
			case "short arity":
				input.Arguments = input.Arguments[:1]
				expected = builtInFunctions.ErrInvalidArguments
			case "long arity":
				input.Arguments = append(input.Arguments, []byte("extra"))
				expected = builtInFunctions.ErrInvalidArguments
			case "caller":
				input.CallerAddr = bytes.Clone(qualContainmentAddress)
				expected = builtInFunctions.ErrAddressIsNotESDTSystemSC
			case "recipient":
				input.RecipientAddr = bytes.Clone(qualContainmentAddress)
				expected = builtInFunctions.ErrOnlySystemAccountAccepted
			}
			var out *vmcommon.VMOutput
			if mode == "late save" || mode == "ordinary" {
				hook, _ := qualT42Hook(t, store, 1, false, coordinator)
				require.NoError(t, hook.GetBuiltinFunctionsContainer().Add(core.ESDTSetTokenType, function))
				if mode == "late save" {
					expected = errors.New("qualification token settings save")
					store.saveErr = expected
				}
				out, err = hook.ProcessBuiltInFunction(input)
				store.saveErr = nil
			} else {
				out, err = function.ProcessBuiltinFunction(nil, nil, input)
			}
			if expected != nil {
				require.Nil(t, out)
				require.ErrorIs(t, err, expected)
				after, e := store.RootHash()
				require.NoError(t, e)
				require.Equal(t, root, after, "admission must precede any write")
				require.Zero(t, store.JournalLen())
			} else {
				require.NoError(t, err)
				require.Equal(t, &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, out)
			}
			committed, e := store.Commit()
			require.NoError(t, e)
			if expected != nil {
				require.Equal(t, root, committed)
			}
			require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(committed)))
			actual := qualRegistryValue(t, store, string(key))
			if expected != nil {
				require.Equal(t, prior, actual)
			} else {
				// Pinned global settings maps NonFungibleV2 to its storage discriminator 3.
				require.Equal(t, (&builtInFunctions.ESDTGlobalMetadata{Paused: true, LimitedTransfer: true, TokenType: 3}).ToBytes(), actual)
				tokenType, e := settings.GetTokenType(key)
				require.NoError(t, e)
				require.Equal(t, uint32(core.NonFungibleV2), tokenType)
			}
		})
	}
}
