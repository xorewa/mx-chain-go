package drwa

import (
	"bytes"
	"math"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/config"
	factoryDisabled "github.com/multiversx/mx-chain-go/factory/disabled"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// Literal prices are independent gas-unit examples, NOT measured/admitted costs.
func TestQualDRWAOutcomeGasArithmetic(t *testing.T) {
	for _, c := range []struct {
		name                                                                                    string
		available, source, destination, success, refund, completion, total, outcome, unreserved uint64
		err                                                                                     error
	}{
		{name: "exact", available: 48, source: 11, destination: 7, success: 5, refund: 13, completion: 17, total: 48, outcome: 13},
		{name: "one_below", available: 47, source: 11, destination: 7, success: 5, refund: 13, completion: 17, err: core.ErrSubtractionOverflow},
		{name: "one_above", available: 49, source: 11, destination: 7, success: 5, refund: 13, completion: 17, total: 48, outcome: 13, unreserved: 1},
		{name: "success_larger", available: 48, source: 11, destination: 7, success: 13, refund: 5, completion: 17, total: 48, outcome: 13},
		{name: "equal_outcome", available: 40, source: 11, destination: 7, success: 5, refund: 5, completion: 17, total: 40, outcome: 5},
		{name: "zero_applicable_work", available: 1, total: 0, unreserved: 1},
		{name: "max_exact", available: math.MaxUint64, source: math.MaxUint64 - 3, destination: 1, success: 1, refund: 1, completion: 1, total: math.MaxUint64, outcome: 1},
		{name: "overflow_destination", available: math.MaxUint64, source: math.MaxUint64, destination: 1, err: core.ErrAdditionOverflow},
		{name: "overflow_outcome", available: math.MaxUint64, source: math.MaxUint64, success: 1, err: core.ErrAdditionOverflow},
		{name: "overflow_completion", available: math.MaxUint64, source: math.MaxUint64, completion: 1, err: core.ErrAdditionOverflow},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, err := reserveOutcomeGas(c.available, c.source, c.destination, c.success, c.refund, c.completion)
			if c.err != nil {
				require.ErrorIs(t, err, c.err)
				require.Equal(t, outcomeGasReservation{}, p)
				return
			}
			require.NoError(t, err)
			require.Equal(t, c.total, p.total)
			require.Equal(t, c.outcome, p.outcome)
			require.Equal(t, c.unreserved, p.unreserved)
			require.Equal(t, c.source, p.source)
			require.Equal(t, c.destination, p.destination)
			require.Equal(t, c.completion, p.completion)
			before := p
			remaining, err := p.destinationRemaining(c.destination)
			require.NoError(t, err)
			require.Zero(t, remaining)
			if c.destination != math.MaxUint64 {
				_, err = p.destinationRemaining(c.destination + 1)
				require.ErrorIs(t, err, core.ErrSubtractionOverflow)
			}
			require.Equal(t, before, p, "arithmetic overrun cannot alter outcome/completion partitions")
		})
	}
}

// Native ordinary capability probes only; synthetic coordinates/non-gate
// dependencies and diagnostic native gas7. No regulated context/funding proof.
func TestQualDRWAOutcomeNativeFungibleCarrier(t *testing.T) {
	for _, mode := range []string{"EOA_source", "SC_source", "same_shard", "destination_zero_gas", "source_underfunded", "native_cost_update"} {
		t.Run(mode, func(t *testing.T) {
			s := qualRegistrationStore(t, 0)
			codec := &marshal.GogoProtoMarshalizer{}
			senderAddress := bytes.Repeat([]byte{1}, 32)
			receiverAddress := bytes.Repeat([]byte{2}, 32)
			if mode == "SC_source" {
				senderAddress = make([]byte, 32)
				senderAddress[8] = 5
				senderAddress[31] = 1
				require.True(t, vmcommon.IsSmartContractAddress(senderAddress))
			} else {
				require.False(t, vmcommon.IsSmartContractAddress(senderAddress))
			}
			token := []byte("TOKEN-abcdef")
			key := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), token...)
			sender, err := s.LoadAccount(senderAddress)
			require.NoError(t, err)
			receiver, err := s.LoadAccount(receiverAddress)
			require.NoError(t, err)
			snd := sender.(state.UserAccountHandler)
			dst := receiver.(state.UserAccountHandler)
			// Independent literal native protobuf Value=100 with omitted Type=Fungible.
			require.NoError(t, snd.SaveKeyValue(key, []byte{0x12, 2, 0, 100}))
			require.NoError(t, dst.SaveKeyValue([]byte("fixture/T25/unrelated"), []byte{1}))
			require.NoError(t, s.SaveAccount(snd))
			require.NoError(t, s.SaveAccount(dst))
			_, err = s.Commit()
			require.NoError(t, err)
			flags := qualCandidateFlags(t, &config.EpochConfig{}, 0)
			roles, err := builtInFunctions.NewESDTRolesFunc(codec, true)
			require.NoError(t, err)
			native, err := builtInFunctions.NewESDTTransferFunc(7, codec, factoryDisabled.NewDisabledGlobalSettingHandler(), &testscommon.ShardsCoordinatorMock{NoShards: 3, CurrentShard: 0}, roles, flags)
			require.NoError(t, err)
			// Native EOA-only hook branch reads no fields; no full configured hook,
			// SC receiver, node or native routing factory is constructed here.
			require.False(t, vmcommon.IsSmartContractAddress(receiverAddress))
			payable, err := builtInFunctions.NewPayableCheckFunc(&hooks.BlockChainHookImpl{}, flags)
			require.NoError(t, err)
			require.NoError(t, native.SetPayableChecker(payable))
			gas := uint64(100)
			charge := uint64(7)
			if mode == "source_underfunded" {
				gas = 6
			}
			if mode == "destination_zero_gas" {
				gas = 0
			}
			if mode == "native_cost_update" {
				native.SetNewGasConfig(&vmcommon.GasCost{BuiltInCost: vmcommon.BuiltInCost{ESDTTransfer: 9}})
				charge = 9
			}
			input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: senderAddress, CallValue: big.NewInt(0), Arguments: [][]byte{token, {30}}, GasProvided: gas, GasLocked: 13}, RecipientAddr: receiverAddress, Function: core.BuiltInFunctionESDTTransfer}
			owner, err := NewRollbackContainment(s)
			require.NoError(t, err)
			var out *vmcommon.VMOutput
			source, ok := sender.(vmcommon.UserAccountHandler)
			require.True(t, ok)
			nativeDestination, ok := receiver.(vmcommon.UserAccountHandler)
			require.True(t, ok)
			destination := vmcommon.UserAccountHandler(nil)
			if mode == "same_shard" {
				destination = nativeDestination
			}
			if mode == "destination_zero_gas" {
				source = nil
				destination = nativeDestination
			}
			root, err := s.RootHash()
			require.NoError(t, err)
			err = owner.Execute(func() (*vmcommon.VMOutput, error) {
				var e error
				out, e = native.ProcessBuiltinFunction(source, destination, input)
				if e != nil {
					return nil, e
				}
				if source != nil {
					if e = s.SaveAccount(source); e != nil {
						return nil, e
					}
				}
				if destination != nil {
					if e = s.SaveAccount(destination); e != nil {
						return nil, e
					}
				}
				return out, nil
			})
			if mode == "source_underfunded" {
				require.ErrorIs(t, err, builtInFunctions.ErrNotEnoughGas)
				after, e := s.RootHash()
				require.NoError(t, e)
				require.Equal(t, root, after)
				return
			}
			require.NoError(t, err)
			require.Equal(t, vmcommon.Ok, out.ReturnCode)
			if mode == "SC_source" {
				require.Len(t, out.OutputAccounts, 1)
				account := out.OutputAccounts[string(receiverAddress)]
				require.NotNil(t, account)
				require.Len(t, account.OutputTransfers, 1)
				transfer := account.OutputTransfers[0]
				require.Equal(t, []byte("ESDTTransfer@544f4b454e2d616263646566@1e"), transfer.Data)
				require.Equal(t, uint64(93), transfer.GasLimit)
				require.Equal(t, uint64(13), transfer.GasLocked)
				require.Zero(t, out.GasRemaining)
			} else {
				require.Empty(t, out.OutputAccounts)
				remaining := gas
				if source != nil {
					remaining -= charge
				}
				require.Equal(t, remaining, out.GasRemaining)
			}
			// Read from reloaded actual native storage, not mutated local account aliases.
			read := func(address []byte) int64 {
				a, e := s.GetExistingAccount(address)
				require.NoError(t, e)
				v, _, e := a.(state.UserAccountHandler).RetrieveValue(key)
				require.NoError(t, e)
				if len(v) == 0 {
					return 0
				}
				record := &esdt.ESDigitalToken{}
				require.NoError(t, codec.Unmarshal(record, v))
				return record.Value.Int64()
			}
			if source != nil {
				require.Equal(t, int64(70), read(senderAddress))
			} else {
				require.Equal(t, int64(100), read(senderAddress))
			}
			if destination != nil {
				require.Equal(t, int64(30), read(receiverAddress))
			} else {
				require.Zero(t, read(receiverAddress))
			}
			_, outputs, err := owner.Commit()
			require.NoError(t, err)
			require.Len(t, outputs, 1)
		})
	}
}
