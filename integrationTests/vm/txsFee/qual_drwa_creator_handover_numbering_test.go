package txsFee

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/integrationTests/vm"
	"github.com/multiversx/mx-chain-go/integrationTests/vm/txsFee/utils"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// Native feasibility only: direct hook calls, fixture roles/System-SC caller,
// upstream unit gas, no guest WASM. No governed lifecycle, protected origin,
// DRWA SupplyState, actual fees/funding, canonicality or profile admission.
// The final bare-native replay is an explicit upstream limitation witness;
// it is prohibited without the independent protected carrier identity guard.
func TestQualDRWACreatorHandoverNativeNumbering(t *testing.T) {
	for _, family := range []string{core.NonFungibleESDTv2, core.SemiFungibleESDT, core.MetaESDT,
		core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT} {
		for _, used := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/used_%t", family, used), func(t *testing.T) {
				coordinator, err := sharding.NewMultiShardCoordinator(3, 1)
				require.NoError(t, err)
				ctx, err := vm.CreatePreparedTxProcessorWithVMsWithShardCoordinator(config.EnableEpochs{}, coordinator, 1)
				require.NoError(t, err)
				t.Cleanup(ctx.Close)
				old := bytes.Repeat([]byte{1}, 32)
				var next []byte
				for value := byte(2); value < 255; value++ {
					candidate := bytes.Repeat([]byte{value}, 32)
					if coordinator.ComputeId(candidate) == coordinator.SelfId() {
						next = candidate
						break
					}
				}
				require.Len(t, next, 32)
				require.Equal(t, coordinator.SelfId(), coordinator.ComputeId(old))
				require.Equal(t, core.MetachainShardId, coordinator.ComputeId(core.ESDTSCAddress))
				token, other := []byte("TOKEN-abcdef"), []byte("OTHER-abcdef")
				for _, address := range [][]byte{old, next} {
					createAccWithBalance(t, ctx.Accounts, address, big.NewInt(1000))
				}
				utils.SetESDTRoles(t, ctx.Accounts, old, token, [][]byte{[]byte(core.ESDTRoleNFTCreate)})
				// The system-only setter ignores account arguments and owns its
				// SystemAccount save. Use that native primitive for fixture setup.
				typeSetter, err := ctx.BlockchainHook.(process.BlockChainHookHandler).GetBuiltinFunctionsContainer().Get(core.ESDTSetTokenType)
				require.NoError(t, err)
				setType := func(id []byte) {
					output, e := typeSetter.ProcessBuiltinFunction(nil, nil, &vmcommon.ContractCallInput{
						VMInput:       vmcommon.VMInput{CallerAddr: core.ESDTSCAddress, CallValue: big.NewInt(0), Arguments: [][]byte{id, []byte(family)}},
						RecipientAddr: core.SystemAccountAddress, Function: core.ESDTSetTokenType,
					})
					require.NoError(t, e)
					require.Equal(t, vmcommon.Ok, output.ReturnCode)
				}
				setType(token)
				create := func(address, id []byte) (*vmcommon.VMOutput, error) {
					return ctx.BlockchainHook.ProcessBuiltInFunction(&vmcommon.ContractCallInput{
						VMInput: vmcommon.VMInput{CallerAddr: address, CallValue: big.NewInt(0), GasProvided: 100000,
							Arguments: [][]byte{id, {1}, []byte("name"), {}, []byte("hash"), []byte("attributes"), []byte("uri")}},
						RecipientAddr: address, Function: core.BuiltInFunctionESDTNFTCreate,
					})
				}
				if used {
					utils.SetESDTRoles(t, ctx.Accounts, next, other, [][]byte{[]byte(core.ESDTRoleNFTCreate)})
					setType(other)
					out, e := create(next, other)
					require.NoError(t, e)
					require.Equal(t, [][]byte{{1}}, out.ReturnData)
				}
				for nonce := int64(1); nonce <= 7; nonce++ {
					out, e := create(old, token)
					require.NoError(t, e)
					require.Equal(t, [][]byte{big.NewInt(nonce).Bytes()}, out.ReturnData)
				}
				counter := func(address, id []byte) uint64 {
					a, e := ctx.Accounts.GetExistingAccount(address)
					require.NoError(t, e)
					key := []byte(core.ProtectedKeyPrefix + core.ESDTNFTLatestNonceIdentifier + string(id))
					v, _, e := a.(state.UserAccountHandler).RetrieveValue(key)
					require.NoError(t, e)
					return new(big.Int).SetBytes(v).Uint64()
				}
				require.Equal(t, uint64(7), counter(old, token))
				if used {
					require.Zero(t, counter(next, token))
				} else {
					a, e := ctx.Accounts.GetExistingAccount(next)
					require.NoError(t, e)
					user := a.(state.UserAccountHandler)
					require.Nil(t, user.DataTrie())
					value, _, e := user.RetrieveValue([]byte(core.ProtectedKeyPrefix + core.ESDTNFTLatestNonceIdentifier + string(token)))
					require.ErrorIs(t, e, state.ErrNilTrie)
					require.Empty(t, value)
				}
				input := &vmcommon.ContractCallInput{
					VMInput:       vmcommon.VMInput{CallerAddr: core.ESDTSCAddress, CallValue: big.NewInt(0), Arguments: [][]byte{token, next}},
					RecipientAddr: old, Function: core.BuiltInFunctionESDTNFTCreateRoleTransfer,
				}
				out, err := ctx.BlockchainHook.ProcessBuiltInFunction(input)
				require.NoError(t, err)
				require.Len(t, out.Logs, 2)
				require.Zero(t, counter(old, token))
				require.Equal(t, uint64(7), counter(next, token))
				root, err := ctx.Accounts.Commit()
				require.NoError(t, err)
				require.NoError(t, ctx.Accounts.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
				journal := ctx.Accounts.JournalLen()
				denied, err := create(old, token)
				require.ErrorIs(t, err, builtInFunctions.ErrActionNotAllowed)
				require.Nil(t, denied)
				current, err := ctx.Accounts.RootHash()
				require.NoError(t, err)
				require.Equal(t, root, current)
				require.Equal(t, journal, ctx.Accounts.JournalLen())
				out, err = create(next, token)
				require.NoError(t, err)
				require.Equal(t, [][]byte{{8}}, out.ReturnData)
				require.Equal(t, uint64(8), counter(next, token))
				readItems := func() {
					for nonce := uint64(1); nonce <= 8; nonce++ {
						address := old
						if nonce == 8 {
							address = next
						}
						item, e := ctx.BlockchainHook.GetESDTToken(address, token, nonce)
						require.NoError(t, e)
						wantType := map[string]uint32{
							core.NonFungibleESDTv2: uint32(core.NonFungibleV2), core.SemiFungibleESDT: uint32(core.SemiFungible),
							core.MetaESDT: uint32(core.MetaFungible), core.DynamicNFTESDT: uint32(core.DynamicNFT),
							core.DynamicSFTESDT: uint32(core.DynamicSFT), core.DynamicMetaESDT: uint32(core.DynamicMeta),
						}
						require.Equal(t, wantType[family], item.Type)
						require.Equal(t, big.NewInt(1), item.Value)
						require.Equal(t, &esdt.MetaData{Nonce: nonce, Name: []byte("name"), Creator: address,
							Hash: []byte("hash"), Attributes: []byte("attributes"), URIs: [][]byte{[]byte("uri")}}, item.TokenMetaData)
					}
				}
				readItems()
				root, err = ctx.Accounts.Commit()
				require.NoError(t, err)
				require.NoError(t, ctx.Accounts.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
				require.Equal(t, uint64(8), counter(next, token))
				// Bare native calls have no applied-leg identity: this resets the
				// successor counter. It is a limitation, not DRWA-authorized work.
				_, err = ctx.BlockchainHook.ProcessBuiltInFunction(input)
				require.NoError(t, err)
				require.Zero(t, counter(next, token))
				readItems() // replay resets numbering but does not transfer existing holdings
				for _, address := range [][]byte{old, next} {
					a, e := ctx.Accounts.GetExistingAccount(address)
					require.NoError(t, e)
					require.Equal(t, big.NewInt(1000), a.(state.UserAccountHandler).GetBalance())
					require.Zero(t, a.GetNonce())
				}
				if used {
					require.Equal(t, uint64(1), counter(next, other))
					item, e := ctx.BlockchainHook.GetESDTToken(next, other, 1)
					require.NoError(t, e)
					require.Equal(t, big.NewInt(1), item.Value)
				}
			})
		}
	}
}
