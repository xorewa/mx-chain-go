package core

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	nativeCore "github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process/smartContract/builtInFunctions"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	nativeBuiltins "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// T09-M32: ordinary direct native effects against loaded, test-owned state.
// The caller is synthetic; configuration does not confer regulated authority.
// This does not establish transaction authentication or complete route coverage.
func TestQualDRWACandidateCrawlerStateEffects(t *testing.T) {
	for _, shard := range []uint32{0, 1, 2, nativeCore.MetachainShardId} {
		t.Run(fmt.Sprint(shard), func(t *testing.T) {
			args := qualDRWACandidateDataArgs(t, 0, shard)
			handler, dataHandler := qualDRWACandidateStateComponents(t, args)
			accounts := handler.AccountsAdapter()
			builtArgs, _, _, _ := qualDRWACandidateBuiltInArgs(t, shard)
			builtArgs.Accounts = accounts
			builtArgs.Marshalizer = args.Core.InternalMarshalizer()
			builtArgs.EpochNotifier = args.Core.EpochNotifier()
			builtArgs.EnableEpochsHandler = args.Core.EnableEpochsHandler()
			factory, err := builtInFunctions.CreateBuiltInFunctionsFactory(builtArgs)
			require.NoError(t, err)
			allowed, err := builtInFunctions.GetAllowedAddress(args.ShardCoordinator, builtArgs.AutomaticCrawlerAddresses)
			require.NoError(t, err)
			functions := make(map[string]vmcommon.BuiltinFunction)
			for _, name := range []string{vmcommon.ESDTAddMetadata, vmcommon.ESDTDeleteMetadata} {
				functions[name], err = factory.BuiltInFunctionContainer().Get(name)
				require.NoError(t, err)
				require.False(t, functions[name].IsActive())
			}
			require.False(t, args.Core.EnableEpochsHandler().IsFlagEnabled(common.SendAlwaysFlag))
			// Storage was constructed at epoch0. Only generic epoch activation changes;
			// no epoch-start storage notification or canonical transition is claimed.
			args.Core.EpochNotifier().CheckEpoch(&block.Header{Epoch: 3, Round: 440})
			require.True(t, args.Core.EnableEpochsHandler().IsFlagEnabled(common.SendAlwaysFlag))
			for name, function := range functions {
				require.True(t, function.IsActive())
				for _, fault := range []string{"caller", "recipient", "value"} {
					t.Run(name+"_"+fault, func(t *testing.T) {
						input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(allowed), CallValue: big.NewInt(0)}, RecipientAddr: bytes.Clone(allowed), Function: name}
						want := nativeBuiltins.ErrAddressIsNotAllowed
						switch fault {
						case "caller":
							input.CallerAddr = bytes.Repeat([]byte{0x17}, len(allowed))
						case "recipient":
							input.RecipientAddr = bytes.Repeat([]byte{0x17}, len(allowed))
							want = nativeBuiltins.ErrInvalidRcvAddr
						case "value":
							input.CallValue = big.NewInt(1)
							want = nativeBuiltins.ErrBuiltInFunctionCalledWithValue
						}
						output, err := function.ProcessBuiltinFunction(nil, nil, input)
						require.ErrorIs(t, err, want)
						require.Nil(t, output)
						system, err := accounts.GetExistingAccount(nativeCore.SystemAccountAddress)
						require.ErrorIs(t, err, state.ErrAccNotFound)
						require.Nil(t, system, "native pre-effect denial must precede system-account creation")
					})
				}
			}
			token := []byte("QUAL-ababab")
			input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(allowed), CallValue: big.NewInt(0)}, RecipientAddr: bytes.Clone(allowed), Function: vmcommon.ESDTAddMetadata}
			for nonce := uint64(1); nonce <= 2; nonce++ {
				metadata, err := builtArgs.Marshalizer.Marshal(&esdt.MetaData{Nonce: nonce, Name: []byte(fmt.Sprintf("public nonce %d", nonce))})
				require.NoError(t, err)
				input.Arguments = append(input.Arguments, bytes.Clone(token), big.NewInt(0).SetUint64(nonce).Bytes(), metadata)
			}
			output, err := functions[vmcommon.ESDTAddMetadata].ProcessBuiltinFunction(nil, nil, input)
			require.NoError(t, err)
			require.Equal(t, &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, output)
			root, err := accounts.Commit()
			require.NoError(t, err)
			system, err := accounts.GetExistingAccount(nativeCore.SystemAccountAddress)
			require.NoError(t, err)
			user := system.(state.UserAccountHandler)
			keys := make([][]byte, 2)
			saved := make([][]byte, 2)
			for nonce := uint64(1); nonce <= 2; nonce++ {
				keys[nonce-1] = append([]byte(nativeCore.ProtectedKeyPrefix+nativeCore.ESDTKeyIdentifier), token...)
				keys[nonce-1] = append(keys[nonce-1], big.NewInt(0).SetUint64(nonce).Bytes()...)
				saved[nonce-1], _, err = user.RetrieveValue(keys[nonce-1])
				require.NoError(t, err)
				decoded := &esdt.ESDigitalToken{}
				require.NoError(t, builtArgs.Marshalizer.Unmarshal(decoded, saved[nonce-1]))
				require.Equal(t, uint32(nativeCore.NonFungible), decoded.Type)
				require.Zero(t, decoded.Value.Sign())
				require.Equal(t, nonce, decoded.TokenMetaData.Nonce)
				require.Equal(t, []byte(fmt.Sprintf("public nonce %d", nonce)), decoded.TokenMetaData.Name)
			}
			output, err = functions[vmcommon.ESDTAddMetadata].ProcessBuiltinFunction(nil, nil, input)
			require.ErrorIs(t, err, nativeBuiltins.ErrTokenHasValidMetadata)
			require.Nil(t, output)
			unchanged, err := accounts.Commit()
			require.NoError(t, err)
			require.Equal(t, root, unchanged, "duplicate native add must not change committed state")
			input.Function = vmcommon.ESDTDeleteMetadata
			input.Arguments = [][]byte{token, {1}, {1}, {1}}
			output, err = functions[vmcommon.ESDTDeleteMetadata].ProcessBuiltinFunction(nil, nil, input)
			require.NoError(t, err)
			require.Equal(t, &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, output)
			_, err = accounts.Commit()
			require.NoError(t, err)
			system, err = accounts.GetExistingAccount(nativeCore.SystemAccountAddress)
			require.NoError(t, err)
			user = system.(state.UserAccountHandler)
			removed, _, err := user.RetrieveValue(keys[0])
			require.NoError(t, err)
			require.Empty(t, removed)
			retained, _, err := user.RetrieveValue(keys[1])
			require.NoError(t, err)
			require.Equal(t, saved[1], retained)
			require.NoError(t, handler.Close())
			require.NoError(t, dataHandler.Close())
		})
	}
}
