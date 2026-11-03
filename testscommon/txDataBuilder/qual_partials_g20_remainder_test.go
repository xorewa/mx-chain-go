package txDataBuilder

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-core-go/data/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/multiversx/mx-chain-vm-common-go/mock"
	"github.com/stretchr/testify/require"
)

type qualG20AccountFault struct {
	vmcommon.UserAccountHandler
	read, write error
	prefix      []byte
}

func (a *qualG20AccountFault) AccountDataHandler() vmcommon.AccountDataHandler {
	original := a.UserAccountHandler.AccountDataHandler()
	return &mock.DataTrieTrackerStub{
		RetrieveValueCalled: func(k []byte) ([]byte, uint32, error) {
			if a.read != nil && bytes.HasPrefix(k, a.prefix) {
				return nil, 0, a.read
			}
			return original.RetrieveValue(k)
		},
		SaveKeyValueCalled: func(k, v []byte) error {
			if a.write != nil && bytes.HasPrefix(k, a.prefix) {
				return a.write
			}
			return original.SaveKeyValue(k, v)
		},
	}
}

func TestQualPartialsG20RemainingSimpleFailures(t *testing.T) {
	t.Run("burn exact arity", func(t *testing.T) {
		f := qualG20Event(t, core.BuiltInFunctionESDTBurn)
		f.input.Arguments = append(f.input.Arguments, nil)
		out, err := f.fn.ProcessBuiltinFunction(f.sender, f.destination, f.input)
		require.ErrorIs(t, err, builtInFunctions.ErrInvalidArguments)
		require.Nil(t, out)
	})
	t.Run("freeze storage write", func(t *testing.T) {
		f := qualG20Event(t, core.BuiltInFunctionESDTFreeze)
		fault := errors.New("qualification freeze write")
		out, err := f.fn.ProcessBuiltinFunction(nil, &qualG20AccountFault{UserAccountHandler: f.destination, write: fault}, f.input)
		require.ErrorIs(t, err, fault)
		require.Nil(t, out)
	})
	for _, name := range []string{core.BuiltInFunctionESDTNFTAddURI, core.BuiltInFunctionESDTNFTUpdateAttributes} {
		t.Run(name+" missing metadata", func(t *testing.T) {
			f := qualG20Event(t, name)
			f.token.TokenMetaData = nil
			out, err := f.fn.ProcessBuiltinFunction(f.sender, f.destination, f.input)
			require.ErrorIs(t, err, builtInFunctions.ErrNFTDoesNotHaveMetadata)
			require.Nil(t, out)
		})
	}
	t.Run("NFT burn liquidity", func(t *testing.T) {
		f := qualG20Event(t, core.BuiltInFunctionESDTNFTBurn)
		fault := errors.New("qualification burn liquidity")
		f.storage.AddToLiquiditySystemAccCalled = func([]byte, uint32, uint64, *big.Int, bool) error { return fault }
		out, err := f.fn.ProcessBuiltinFunction(f.sender, f.destination, f.input)
		require.ErrorIs(t, err, fault)
		require.Nil(t, out)
	})
	for _, mode := range []string{"role read", "nonce read", "nonce write"} {
		t.Run(mode, func(t *testing.T) {
			f := qualG20Event(t, core.BuiltInFunctionSetESDTRole)
			fault := fmt.Errorf("qualification %s: %s", mode, core.GetNodeFromDBErrorString)
			account := &qualG20AccountFault{UserAccountHandler: f.destination, read: fault}
			if mode != "role read" {
				f.input.Arguments[1] = []byte(core.ESDTRoleNFTCreateMultiShard)
				account.prefix = []byte(core.ProtectedKeyPrefix + core.ESDTNFTLatestNonceIdentifier)
			}
			if mode == "nonce write" {
				account.read = nil
				account.write = fault
			}
			out, err := f.fn.ProcessBuiltinFunction(nil, account, f.input)
			require.ErrorIs(t, err, fault)
			require.Nil(t, out)
		})
	}
}

func TestQualPartialsG20NFTCreateFailureEvents(t *testing.T) {
	for _, mode := range []string{"nonce read", "gas", "royalties", "zero quantity", "quantity role", "wide quantity", "type read", "token save", "liquidity", "nonce save"} {
		t.Run(mode, func(t *testing.T) {
			f := qualG20Event(t, core.BuiltInFunctionESDTNFTCreate)
			fault := fmt.Errorf("qualification %s: %s", mode, core.GetNodeFromDBErrorString)
			expected := error(fault)
			switch mode {
			case "nonce read":
				f.sender = &qualG20AccountFault{UserAccountHandler: f.sender, read: fault}
			case "gas":
				f.input.GasProvided = 7
				expected = builtInFunctions.ErrNotEnoughGas
			case "royalties":
				f.input.Arguments[3] = bytes.Repeat([]byte{255}, 9)
				expected = builtInFunctions.ErrInvalidArguments
			case "zero quantity":
				f.input.Arguments[1] = nil
				expected = builtInFunctions.ErrInvalidArguments
			case "quantity role":
				f.roles.CheckAllowedToExecuteCalled = func(_ vmcommon.UserAccountHandler, _ []byte, role []byte) error {
					if bytes.Equal(role, []byte(core.ESDTRoleNFTAddQuantity)) {
						return fault
					}
					return nil
				}
			case "wide quantity":
				f.input.Arguments[1] = bytes.Repeat([]byte{1}, 33)
				expected = builtInFunctions.ErrInvalidArguments
			case "type read":
				f.global.GetTokenTypeCalled = func([]byte) (uint32, error) { return 0, fault }
			case "token save":
				f.storage.SaveESDTNFTTokenCalled = func([]byte, vmcommon.UserAccountHandler, []byte, uint64, *esdt.ESDigitalToken, vmcommon.NftSaveArgs) ([]byte, error) {
					return nil, fault
				}
			case "liquidity":
				f.storage.AddToLiquiditySystemAccCalled = func([]byte, uint32, uint64, *big.Int, bool) error { return fault }
			case "nonce save":
				f.sender = &qualG20AccountFault{UserAccountHandler: f.sender, write: fault}
			}
			out, err := f.fn.ProcessBuiltinFunction(f.sender, f.destination, f.input)
			require.ErrorIs(t, err, expected)
			require.Nil(t, out)
		})
	}
	// The pinned common input checker rejects this call type before NFTCreate's
	// later ExecOnDestByCaller branches. These are admission controls, not claims
	// that the dominated branches executed.
	for _, rolesAddress := range [][]byte{nil, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)} {
		t.Run(fmt.Sprintf("dominating ExecOnDestByCaller %x", rolesAddress), func(t *testing.T) {
			f := qualG20Event(t, core.BuiltInFunctionESDTNFTCreate)
			f.input.CallType = vm.ExecOnDestByCaller
			f.input.Arguments = append(f.input.Arguments, rolesAddress)
			out, err := f.fn.ProcessBuiltinFunction(f.sender, f.destination, f.input)
			require.ErrorIs(t, err, builtInFunctions.ErrActionNotAllowed)
			require.Nil(t, out)
		})
	}
}

func TestQualPartialsG20TransferFailureEvents(t *testing.T) {
	for _, mode := range []string{"zero fungible", "fungible payable", "nonnull receiving sender", "receiver decode", "receiver payable", "receiver save", "short destination", "self destination", "load", "load type", "sender save", "sender payable", "output tracking", "account save"} {
		t.Run(mode, func(t *testing.T) {
			name := core.BuiltInFunctionESDTNFTTransfer
			if mode == "zero fungible" || mode == "fungible payable" {
				name = core.BuiltInFunctionESDTTransfer
			}
			f := qualG20Event(t, name)
			fault := errors.New("qualification " + mode)
			expected := error(fault)
			other := mock.NewUserAccount(bytes.Repeat([]byte{2}, 32))
			f.accounts.LoadAccountCalled = func([]byte) (vmcommon.AccountHandler, error) { return other, nil }
			if mode == "nonnull receiving sender" || mode == "receiver decode" || mode == "receiver payable" || mode == "receiver save" {
				f.input.CallerAddr = other.AddressBytes()
				f.input.Arguments[3] = []byte{0}
				if mode != "nonnull receiving sender" {
					f.sender = nil
				}
			}
			switch mode {
			case "zero fungible":
				f.input.Arguments[1] = nil
				expected = builtInFunctions.ErrNegativeValue
			case "fungible payable", "receiver payable", "sender payable":
				f.payable.CheckPayableCalled = func(*vmcommon.ContractCallInput, []byte, int) error { return fault }
			case "nonnull receiving sender":
				expected = builtInFunctions.ErrInvalidRcvAddr
			case "receiver decode":
				f.input.Arguments[3] = []byte{9}
				f.mar.decode = fault
			case "receiver save", "sender save":
				f.storage.SaveESDTNFTTokenCalled = func([]byte, vmcommon.UserAccountHandler, []byte, uint64, *esdt.ESDigitalToken, vmcommon.NftSaveArgs) ([]byte, error) {
					return nil, fault
				}
			case "short destination":
				f.input.Arguments[3] = []byte{2}
				expected = builtInFunctions.ErrInvalidArguments
			case "self destination":
				f.input.Arguments[3] = f.input.CallerAddr
				expected = builtInFunctions.ErrInvalidArguments
			case "load":
				f.accounts.LoadAccountCalled = func([]byte) (vmcommon.AccountHandler, error) { return nil, fault }
			case "load type":
				f.accounts.LoadAccountCalled = func([]byte) (vmcommon.AccountHandler, error) { return nil, nil }
				expected = builtInFunctions.ErrWrongTypeAssertion
			case "output tracking":
				f.storage.WasAlreadySentToDestinationShardAndUpdateStateCalled = func([]byte, uint64, []byte) (bool, error) { return false, fault }
			case "account save":
				f.accounts.SaveAccountCalled = func(vmcommon.AccountHandler) error { return fault }
			}
			out, err := f.fn.ProcessBuiltinFunction(f.sender, f.destination, f.input)
			require.ErrorIs(t, err, expected)
			require.Nil(t, out)
		})
	}
}

func TestQualPartialsG20MultiTransferFailureEvents(t *testing.T) {
	for _, mode := range []string{"nonnull receiving sender", "receiver arity", "receiver decode", "receiver save", "short destination", "self destination", "sender arity", "load", "payable", "fatal token read", "output tracking", "account save"} {
		t.Run(mode, func(t *testing.T) {
			f := qualG20Event(t, core.BuiltInFunctionMultiESDTNFTTransfer)
			fault := fmt.Errorf("qualification %s: %s", mode, core.GetNodeFromDBErrorString)
			expected := error(fault)
			other := mock.NewUserAccount(bytes.Repeat([]byte{2}, 32))
			f.accounts.LoadAccountCalled = func([]byte) (vmcommon.AccountHandler, error) { return other, nil }
			if mode == "nonnull receiving sender" || mode == "receiver arity" || mode == "receiver decode" || mode == "receiver save" {
				f.input.CallerAddr = other.AddressBytes()
				f.input.Arguments = [][]byte{{1}, []byte("TEST-123456"), {1}, {2}}
				if mode != "nonnull receiving sender" {
					f.sender = nil
				}
			}
			switch mode {
			case "nonnull receiving sender":
				expected = builtInFunctions.ErrInvalidRcvAddr
			case "receiver arity":
				f.input.Arguments = [][]byte{{2}, []byte("TEST-123456"), {1}, {2}, nil, nil}
				expected = builtInFunctions.ErrInvalidArguments
			case "receiver decode":
				f.input.Arguments[3] = bytes.Repeat([]byte{9}, 33)
				f.mar.decode = fault
			case "receiver save":
				f.storage.SaveESDTNFTTokenCalled = func([]byte, vmcommon.UserAccountHandler, []byte, uint64, *esdt.ESDigitalToken, vmcommon.NftSaveArgs) ([]byte, error) {
					return nil, fault
				}
			case "short destination":
				f.input.Arguments[0] = []byte{2}
				expected = builtInFunctions.ErrInvalidArguments
			case "self destination":
				f.input.Arguments[0] = f.input.CallerAddr
				expected = builtInFunctions.ErrInvalidArguments
			case "sender arity":
				f.input.Arguments = append(f.input.Arguments, nil)
				f.input.Arguments[1] = []byte{2}
				expected = builtInFunctions.ErrInvalidArguments
			case "load":
				f.accounts.LoadAccountCalled = func([]byte) (vmcommon.AccountHandler, error) { return nil, fault }
			case "payable":
				f.payable.CheckPayableCalled = func(*vmcommon.ContractCallInput, []byte, int) error { return fault }
			case "fatal token read":
				f.storage.GetESDTNFTTokenOnSenderCalled = func(vmcommon.UserAccountHandler, []byte, uint64) (*esdt.ESDigitalToken, error) { return nil, fault }
			case "output tracking":
				f.storage.WasAlreadySentToDestinationShardAndUpdateStateCalled = func([]byte, uint64, []byte) (bool, error) { return false, fault }
			case "account save":
				f.accounts.SaveAccountCalled = func(vmcommon.AccountHandler) error { return fault }
			}
			out, err := f.fn.ProcessBuiltinFunction(f.sender, f.destination, f.input)
			require.ErrorIs(t, err, expected)
			require.Nil(t, out)
		})
	}
}

func TestQualPartialsG20CrossShardMetadataRoleReadFailure(t *testing.T) {
	f := qualG20Event(t, core.BuiltInFunctionESDTNFTTransfer)
	fault := fmt.Errorf("qualification metadata role: %s", core.GetNodeFromDBErrorString)
	f.sender = &qualG20AccountFault{UserAccountHandler: f.sender, read: fault, prefix: []byte(core.ProtectedKeyPrefix + core.ESDTRoleIdentifier + core.ESDTKeyIdentifier)}
	compute := func(address []byte) uint32 {
		if bytes.Equal(address, f.input.CallerAddr) {
			return 0
		}
		return 1
	}
	coordinator := &mock.ShardCoordinatorStub{NumberOfShardsCalled: func() uint32 { return 2 }, SelfIdCalled: func() uint32 { return 0 }, ComputeIdCalled: compute, SameShardCalled: func(a, b []byte) bool { return compute(a) == compute(b) }}
	flags := &mock.EnableEpochsHandlerStub{IsFlagEnabledCalled: func(core.EnableEpochFlag) bool { return true }}
	fn, err := builtInFunctions.NewESDTNFTTransferFunc(7, f.mar, f.global, f.accounts, coordinator, vmcommon.BaseOperationCost{}, f.roles, f.storage, flags)
	require.NoError(t, err)
	require.NoError(t, fn.SetPayableChecker(f.payable))
	out, err := fn.ProcessBuiltinFunction(f.sender, nil, f.input)
	require.ErrorIs(t, err, fault)
	require.Nil(t, out)
}
