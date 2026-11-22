package txDataBuilder

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-core-go/marshal"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/multiversx/mx-chain-vm-common-go/mock"
	"github.com/stretchr/testify/require"
)

// This fixture exercises public builtins; its coordinates are experimental.
// Complete native-hook assertions already in TestQualTransitionR09-R19 are reused.
type qualG20EventFixture struct {
	fn                  vmcommon.BuiltinFunction
	sender, destination vmcommon.UserAccountHandler
	input               *vmcommon.ContractCallInput
	expected            []*vmcommon.LogEntry
	storage             *mock.ESDTNFTStorageHandlerStub
	global              *mock.GlobalSettingsHandlerStub
	roles               *mock.ESDTRoleHandlerStub
	token               *esdt.ESDigitalToken
	mar                 *qualG20MarshalFault
	accounts            *mock.AccountsStub
	payable             *mock.PayableHandlerStub
}

type qualG20MarshalFault struct {
	marshal.Marshalizer
	encode, decode error
}

func (m *qualG20MarshalFault) Marshal(obj interface{}) ([]byte, error) {
	if m.encode != nil {
		return nil, m.encode
	}
	return m.Marshalizer.Marshal(obj)
}
func (m *qualG20MarshalFault) Unmarshal(obj interface{}, data []byte) error {
	if m.decode != nil {
		return m.decode
	}
	return m.Marshalizer.Unmarshal(obj, data)
}

func qualG20Event(t *testing.T, name string) qualG20EventFixture {
	t.Helper()
	caller := bytes.Repeat([]byte{1}, 32)
	token := []byte("TEST-123456")
	mar := &qualG20MarshalFault{Marshalizer: &marshal.GogoProtoMarshalizer{}}
	flags := &mock.EnableEpochsHandlerStub{IsFlagEnabledCalled: func(core.EnableEpochFlag) bool { return true }}
	global := &mock.GlobalSettingsHandlerStub{GetTokenTypeCalled: func([]byte) (uint32, error) { return uint32(core.DynamicNFT), nil }}
	roles := &mock.ESDTRoleHandlerStub{}
	tokenData := &esdt.ESDigitalToken{Value: big.NewInt(5), Type: uint32(core.DynamicNFT), TokenMetaData: &esdt.MetaData{Nonce: 1, URIs: [][]byte{[]byte("old")}}}
	storage := &mock.ESDTNFTStorageHandlerStub{
		GetESDTNFTTokenOnSenderCalled: func(vmcommon.UserAccountHandler, []byte, uint64) (*esdt.ESDigitalToken, error) {
			return tokenData, nil
		},
		GetESDTNFTTokenOnDestinationCalled: func(vmcommon.UserAccountHandler, []byte, uint64) (*esdt.ESDigitalToken, bool, error) {
			return tokenData, false, nil
		},
	}
	user := mock.NewUserAccount(caller)
	key := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), token...)
	encoded, err := mar.Marshal(&esdt.ESDigitalToken{Value: big.NewInt(5)})
	require.NoError(t, err)
	require.NoError(t, user.SaveKeyValue(key, encoded))
	accounts := &mock.AccountsStub{}
	f := qualG20EventFixture{sender: user, destination: user, input: &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: caller, CallValue: big.NewInt(0), GasProvided: 1000, Arguments: [][]byte{token, {2}}}, RecipientAddr: caller, Function: name}}
	f.storage = storage
	f.global = global
	f.roles = roles
	f.token = tokenData
	f.mar = mar
	f.accounts = accounts
	f.payable = &mock.PayableHandlerStub{}
	expected := &vmcommon.LogEntry{Identifier: []byte(name), Address: caller, Topics: [][]byte{token, {}, {2}}}
	switch name {
	case core.BuiltInFunctionESDTFreeze:
		f.fn, err = builtInFunctions.NewESDTFreezeWipeFunc(storage, flags, mar, true, false)
		f.sender = nil
		f.input.CallerAddr = core.ESDTSCAddress
		f.input.Arguments = [][]byte{token}
	case core.BuiltInFunctionSetESDTRole:
		f.fn, err = builtInFunctions.NewESDTRolesFunc(mar, true)
		f.sender = nil
		f.input.CallerAddr = core.ESDTSCAddress
		f.input.Arguments = [][]byte{token, []byte(core.ESDTRoleLocalMint)}
	case core.BuiltInFunctionESDTNFTBurn:
		f.fn, err = builtInFunctions.NewESDTNFTBurnFunc(7, storage, global, roles)
		f.input.Arguments = [][]byte{token, {1}, {2}}
	case core.BuiltInFunctionESDTNFTCreate:
		f.fn, err = builtInFunctions.NewESDTNFTCreateFunc(7, vmcommon.BaseOperationCost{StorePerByte: 1}, mar, global, roles, storage, accounts, flags)
		f.input.Arguments = [][]byte{token, {2}, []byte("name"), {2}, []byte("hash"), []byte("attrs"), []byte("uri")}
	case core.BuiltInFunctionESDTTransfer:
		var fn interface {
			SetPayableChecker(vmcommon.PayableChecker) error
		}
		native, e := builtInFunctions.NewESDTTransferFunc(7, mar, global, &mock.ShardCoordinatorStub{SameShardCalled: func(_, _ []byte) bool { return true }}, roles, flags)
		err = e
		f.fn = native
		fn = native
		if err == nil {
			require.NoError(t, fn.SetPayableChecker(f.payable))
		}
		f.input.RecipientAddr = bytes.Repeat([]byte{2}, 32)
	case core.BuiltInFunctionESDTNFTTransfer:
		native, e := builtInFunctions.NewESDTNFTTransferFunc(7, mar, global, accounts, &mock.ShardCoordinatorStub{SameShardCalled: func(_, _ []byte) bool { return true }}, vmcommon.BaseOperationCost{}, roles, storage, flags)
		err = e
		f.fn = native
		if err == nil {
			require.NoError(t, native.SetPayableChecker(f.payable))
		}
		f.input.Arguments = [][]byte{token, {1}, {2}, bytes.Repeat([]byte{2}, 32)}
	case core.BuiltInFunctionMultiESDTNFTTransfer:
		native, e := builtInFunctions.NewESDTNFTMultiTransferFunc(7, mar, global, accounts, &mock.ShardCoordinatorStub{SameShardCalled: func(_, _ []byte) bool { return true }}, vmcommon.BaseOperationCost{}, flags, roles, storage)
		err = e
		f.fn = native
		if err == nil {
			require.NoError(t, native.SetPayableChecker(f.payable))
		}
		f.input.Arguments = [][]byte{bytes.Repeat([]byte{2}, 32), {1}, token, {1}, {2}}
	case core.BuiltInFunctionESDTBurn:
		f.fn, err = builtInFunctions.NewESDTBurnFunc(7, mar, global, flags)
		f.input.RecipientAddr = core.ESDTSCAddress
	case core.BuiltInFunctionESDTLocalMint:
		f.fn, err = builtInFunctions.NewESDTLocalMintFunc(7, mar, global, roles, flags)
	case core.BuiltInFunctionESDTLocalBurn:
		f.fn, err = builtInFunctions.NewESDTLocalBurnFunc(7, mar, global, roles, flags)
	case core.BuiltInFunctionESDTNFTAddQuantity:
		f.fn, err = builtInFunctions.NewESDTNFTAddQuantityFunc(7, storage, global, roles, flags)
		f.input.Arguments = [][]byte{token, {1}, {2}}
		expected.Topics = [][]byte{token, {1}, {2}}
	case core.ESDTModifyCreator:
		f.fn, err = builtInFunctions.NewESDTModifyCreatorFunc(7, accounts, global, storage, roles, flags, mar)
		f.input.Arguments = [][]byte{token, {1}}
		expected.Topics = [][]byte{token, {1}, {}}
	case core.ESDTModifyRoyalties:
		f.fn, err = builtInFunctions.NewESDTModifyRoyaltiesFunc(7, accounts, global, storage, roles, flags, mar)
		f.input.Arguments = [][]byte{token, {1}, {2}}
	case core.ESDTMetaDataUpdate:
		f.fn, err = builtInFunctions.NewESDTMetaDataUpdateFunc(7, vmcommon.BaseOperationCost{StorePerByte: 1}, accounts, global, storage, roles, flags, mar)
		f.input.Arguments = [][]byte{token, {1}, []byte("name"), {2}, []byte("hash"), []byte("attributes"), []byte("uri")}
	case core.ESDTMetaDataRecreate:
		f.fn, err = builtInFunctions.NewESDTMetaDataRecreateFunc(7, vmcommon.BaseOperationCost{StorePerByte: 1}, accounts, global, storage, roles, flags, mar)
		f.input.Arguments = [][]byte{token, {1}, []byte("name"), {2}, []byte("hash"), []byte("attributes"), []byte("uri")}
	case core.BuiltInFunctionESDTNFTUpdateAttributes:
		f.fn, err = builtInFunctions.NewESDTNFTUpdateAttributesFunc(7, vmcommon.BaseOperationCost{StorePerByte: 1}, storage, global, roles, flags, mar)
		f.input.Arguments = [][]byte{token, {1}, {0, 64, 255}}
		expected.Topics = [][]byte{token, {1}, {}, {0, 64, 255}}
	case core.BuiltInFunctionESDTNFTAddURI:
		f.fn, err = builtInFunctions.NewESDTNFTAddUriFunc(7, vmcommon.BaseOperationCost{StorePerByte: 1}, storage, global, roles, flags, mar)
		f.input.Arguments = [][]byte{token, {1}, nil, {0, 64, 255}}
		expected.Topics = [][]byte{token, {1}, {}, nil, {0, 64, 255}}
	case core.ESDTSetNewURIs:
		f.fn, err = builtInFunctions.NewESDTSetNewURIsFunc(7, vmcommon.BaseOperationCost{StorePerByte: 1}, accounts, global, storage, roles, flags, mar)
		f.input.Arguments = [][]byte{token, {1}, nil, {0, 64, 255}}
		expected.Topics = [][]byte{token, {1}, {}, nil, {0, 64, 255}}
	case vmcommon.BuiltInFunctionESDTTransferRoleAddAddress, vmcommon.BuiltInFunctionESDTTransferRoleDeleteAddress:
		system := mock.NewUserAccount(core.SystemAccountAddress)
		accounts.LoadAccountCalled = func([]byte) (vmcommon.AccountHandler, error) { return system, nil }
		f.fn, err = builtInFunctions.NewESDTTransferRoleAddressFunc(accounts, mar, 4, name == vmcommon.BuiltInFunctionESDTTransferRoleAddAddress, flags)
		f.sender = nil
		f.destination = nil
		f.input.CallerAddr = core.ESDTSCAddress
		f.input.RecipientAddr = core.SystemAccountAddress
		f.input.Arguments = [][]byte{token, caller}
		expected.Address = core.SystemAccountAddress
		expected.Topics = [][]byte{token, {}, {}, caller}
	case core.BuiltInFunctionESDTNFTCreateRoleTransfer:
		other := mock.NewUserAccount(bytes.Repeat([]byte{2}, 32))
		accounts.LoadAccountCalled = func([]byte) (vmcommon.AccountHandler, error) { return other, nil }
		f.fn, err = builtInFunctions.NewESDTNFTCreateRoleTransfer(mar, accounts, &mock.ShardCoordinatorStub{SameShardCalled: func(_, _ []byte) bool { return true }})
		f.sender = nil
		f.input.CallerAddr = core.ESDTSCAddress
		f.input.Arguments = [][]byte{token, other.AddressBytes()}
		expected.Address = caller
		expected.Topics = [][]byte{token, {}, {}, []byte("false")}
		f.expected = []*vmcommon.LogEntry{expected, {Identifier: []byte(name), Address: other.AddressBytes(), Topics: [][]byte{token, {}, {}, []byte("true")}}}
	default:
		t.Fatalf("unknown fixture %s", name)
	}
	require.NoError(t, err)
	if f.expected == nil {
		f.expected = []*vmcommon.LogEntry{expected}
	}
	return f
}

func TestQualPartialsG20ExactAdditionalEvents(t *testing.T) {
	for _, name := range []string{core.BuiltInFunctionESDTBurn, core.BuiltInFunctionESDTLocalMint, core.BuiltInFunctionESDTLocalBurn, core.BuiltInFunctionESDTNFTAddQuantity, core.ESDTModifyCreator, core.BuiltInFunctionESDTNFTUpdateAttributes, core.BuiltInFunctionESDTNFTAddURI, core.ESDTSetNewURIs, core.BuiltInFunctionESDTNFTCreateRoleTransfer, vmcommon.BuiltInFunctionESDTTransferRoleAddAddress, vmcommon.BuiltInFunctionESDTTransferRoleDeleteAddress} {
		t.Run(name, func(t *testing.T) {
			f := qualG20Event(t, name)
			out, err := f.fn.ProcessBuiltinFunction(f.sender, f.destination, f.input)
			require.NoError(t, err)
			require.NotNil(t, out)
			require.Equal(t, vmcommon.Ok, out.ReturnCode)
			require.Equal(t, f.expected, out.Logs)
		})
	}
}

func TestQualPartialsG20NoEventOnBasicFailures(t *testing.T) {
	for _, name := range []string{core.BuiltInFunctionESDTBurn, core.BuiltInFunctionESDTLocalMint, core.BuiltInFunctionESDTLocalBurn, core.BuiltInFunctionESDTNFTAddQuantity, core.ESDTModifyCreator, core.BuiltInFunctionESDTNFTUpdateAttributes, core.BuiltInFunctionESDTNFTAddURI, core.ESDTSetNewURIs, core.BuiltInFunctionESDTNFTCreateRoleTransfer, vmcommon.BuiltInFunctionESDTTransferRoleAddAddress, vmcommon.BuiltInFunctionESDTTransferRoleDeleteAddress, core.BuiltInFunctionESDTFreeze, core.BuiltInFunctionSetESDTRole, core.BuiltInFunctionESDTNFTBurn, core.BuiltInFunctionESDTNFTCreate, core.BuiltInFunctionESDTTransfer, core.BuiltInFunctionESDTNFTTransfer, core.BuiltInFunctionMultiESDTNFTTransfer, core.ESDTModifyRoyalties, core.ESDTMetaDataUpdate, core.ESDTMetaDataRecreate} {
		for _, failure := range []string{"nil input", "nil value", "nonzero value", "arity"} {
			t.Run(name+"/"+failure, func(t *testing.T) {
				f := qualG20Event(t, name)
				switch failure {
				case "nil input":
					f.input = nil
				case "nil value":
					f.input.CallValue = nil
				case "nonzero value":
					f.input.CallValue = big.NewInt(1)
				case "arity":
					f.input.Arguments = nil
				}
				out, err := f.fn.ProcessBuiltinFunction(f.sender, f.destination, f.input)
				require.Error(t, err)
				require.Nil(t, out, "a failed operation must not expose an event")
			})
		}
	}
}

func TestQualPartialsG20RawCallbackData(t *testing.T) {
	require.Equal(t, [][]byte{{}, []byte("callBack"), {}, {0, 64, 255}}, vmcommon.FormatLogDataForCall("", "callBack", [][]byte{{}, {0, 64, 255}}))
	require.Equal(t, [][]byte{[]byte("asyncCall"), []byte("f")}, vmcommon.FormatLogDataForCall("asyncCall", "f", nil))
}

func TestQualPartialsG20MetadataFailureEvents(t *testing.T) {
	for _, name := range []string{core.ESDTModifyCreator, core.ESDTModifyRoyalties, core.ESDTMetaDataUpdate, core.ESDTMetaDataRecreate, core.ESDTSetNewURIs, core.BuiltInFunctionESDTNFTAddURI, core.BuiltInFunctionESDTNFTUpdateAttributes, core.BuiltInFunctionESDTNFTAddQuantity} {
		failures := []string{"role", "storage read", "storage save", "gas", "nonce"}
		if name != core.BuiltInFunctionESDTNFTAddQuantity {
			failures = append(failures, "version encode")
		}
		if name != core.ESDTMetaDataRecreate && name != core.BuiltInFunctionESDTNFTAddQuantity {
			failures = append(failures, "version decode")
		}
		if name == core.ESDTModifyCreator || name == core.ESDTModifyRoyalties || name == core.ESDTMetaDataUpdate || name == core.ESDTMetaDataRecreate || name == core.ESDTSetNewURIs {
			failures = append(failures, "token type read")
		}
		if name == core.ESDTModifyRoyalties || name == core.ESDTMetaDataUpdate || name == core.ESDTMetaDataRecreate {
			failures = append(failures, "royalties")
		}
		if name == core.BuiltInFunctionESDTNFTAddQuantity {
			failures = append(failures, "wide quantity", "liquidity")
		}
		for _, failure := range failures {
			t.Run(name+"/"+failure, func(t *testing.T) {
				f := qualG20Event(t, name)
				fault := errors.New("qualification " + failure)
				expected := fault
				switch failure {
				case "role":
					f.roles.CheckAllowedToExecuteCalled = func(vmcommon.UserAccountHandler, []byte, []byte) error { return fault }
				case "storage read":
					f.storage.GetESDTNFTTokenOnSenderCalled = func(vmcommon.UserAccountHandler, []byte, uint64) (*esdt.ESDigitalToken, error) { return nil, fault }
					f.storage.GetESDTNFTTokenOnDestinationCalled = func(vmcommon.UserAccountHandler, []byte, uint64) (*esdt.ESDigitalToken, bool, error) {
						return nil, false, fault
					}
				case "storage save":
					f.storage.SaveESDTNFTTokenCalled = func([]byte, vmcommon.UserAccountHandler, []byte, uint64, *esdt.ESDigitalToken, vmcommon.NftSaveArgs) ([]byte, error) {
						return nil, fault
					}
				case "token type read":
					f.global.GetTokenTypeCalled = func([]byte) (uint32, error) { return 0, fault }
				case "version encode":
					f.mar.encode = fault
				case "version decode":
					f.token.Reserved = []byte{2, 3}
					f.mar.decode = fault
				case "gas":
					f.input.GasProvided = 0
					expected = builtInFunctions.ErrNotEnoughGas
					if name == core.BuiltInFunctionESDTNFTAddURI || name == core.BuiltInFunctionESDTNFTUpdateAttributes {
						f.input.GasProvided = 7
					}
				case "nonce":
					f.input.Arguments[1] = nil
					expected = builtInFunctions.ErrInvalidArguments
					if name == core.BuiltInFunctionESDTNFTAddURI || name == core.BuiltInFunctionESDTNFTUpdateAttributes || name == core.BuiltInFunctionESDTNFTAddQuantity {
						expected = builtInFunctions.ErrNFTDoesNotHaveMetadata
					}
				case "royalties":
					index := 2
					if name == core.ESDTMetaDataUpdate || name == core.ESDTMetaDataRecreate {
						index = 3
					}
					f.input.Arguments[index] = bytes.Repeat([]byte{255}, 9)
					expected = builtInFunctions.ErrInvalidArguments
				case "wide quantity":
					f.input.Arguments[2] = bytes.Repeat([]byte{1}, 33)
					expected = builtInFunctions.ErrInvalidArguments
				case "liquidity":
					f.storage.AddToLiquiditySystemAccCalled = func([]byte, uint32, uint64, *big.Int, bool) error { return fault }
				}
				out, err := f.fn.ProcessBuiltinFunction(f.sender, f.destination, f.input)
				require.ErrorIs(t, err, expected, "must reach the named failure family")
				require.Nil(t, out, "a failed operation must not expose an event")
			})
		}
	}
}

func TestQualPartialsG20BurnFailureEvents(t *testing.T) {
	for _, failure := range []string{"zero", "wrong recipient"} {
		t.Run(failure, func(t *testing.T) {
			f := qualG20Event(t, core.BuiltInFunctionESDTBurn)
			expected := builtInFunctions.ErrNegativeValue
			if failure == "zero" {
				f.input.Arguments[1] = nil
			} else {
				f.input.RecipientAddr = f.input.CallerAddr
				expected = builtInFunctions.ErrAddressIsNotESDTSystemSC
			}
			out, err := f.fn.ProcessBuiltinFunction(f.sender, f.destination, f.input)
			require.ErrorIs(t, err, expected)
			require.Nil(t, out)
		})
	}
}
