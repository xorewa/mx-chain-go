package process

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/hashingMocks"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/mock"
	"github.com/multiversx/mx-chain-go/vm/systemSmartContracts"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
	"github.com/stretchr/testify/require"
)

type qualFA01OrdinarySupplyClassifier struct{ calls int }

func (c *qualFA01OrdinarySupplyClassifier) IsInterfaceNil() bool { return c == nil }
func (c *qualFA01OrdinarySupplyClassifier) ValidateAccounts(state.AccountsAdapter, state.AccountsAdapter) error {
	return nil
}
func (c *qualFA01OrdinarySupplyClassifier) WithTokenClassification(_ state.AccountsAdapter, _ []byte, execute func(bool) (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
	c.calls++
	return execute(false)
}

// INV-0: exercise the real System-VM, context and ESDT contract together.
// The backing state and ordinary classification are explicit fixtures, not
// canonical native-owner admission. Native error outputs discard context
// storage/transfers and remaining gas; successful outputs retain them.
func TestQualFA01OrdinarySupplySystemVM(t *testing.T) {
	for _, function := range []string{"mint", core.BuiltInFunctionESDTBurn} {
		for _, scenario := range []string{"success", "disabled", "zero", "gas", "callValue"} {
			t.Run(function+"/"+scenario, func(t *testing.T) {
				var baseline *vmcommon.VMOutput
				for _, configured := range []bool{false, true} {
					owner, id := bytes.Repeat([]byte{1}, 32), []byte("ORD-abcdef")
					marshaller := &mock.MarshalizerMock{}
					token := &systemSmartContracts.ESDTDataV2{OwnerAddress: owner, TokenType: []byte(core.FungibleESDT), Mintable: true, Burnable: true, MintedValue: big.NewInt(100), BurntValue: big.NewInt(0)}
					prestate, err := marshaller.Marshal(token)
					require.NoError(t, err)
					classifier := &qualFA01OrdinarySupplyClassifier{}
					contextArgs := systemSmartContracts.VMContextArgs{
						BlockChainHook: &mock.BlockChainHookStub{GetStorageDataCalled: func(address, key []byte) ([]byte, uint32, error) {
							if bytes.Equal(address, core.ESDTSCAddress) && bytes.Equal(key, id) {
								return bytes.Clone(prestate), 0, nil
							}
							return nil, 0, nil
						}},
						CryptoHook: hooks.NewVMCryptoHook(), InputParser: parsers.NewCallArgsParser(),
						ValidatorAccountsDB: &stateMock.AccountsStub{}, UserAccountsDB: &stateMock.AccountsStub{},
						ChanceComputer: &mock.RaterMock{}, EnableEpochsHandler: enableEpochsHandlerMock.NewEnableEpochsHandlerStub(),
					}
					if configured {
						contextArgs.DRWAClassifier = classifier
					}
					host, err := systemSmartContracts.NewVMContext(contextArgs)
					require.NoError(t, err)
					flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.ESDTFlag, common.GlobalMintBurnFlag, common.ESDTNFTCreateOnMultiShardFlag)
					if scenario == "disabled" {
						flags.RemoveActiveFlags(common.GlobalMintBurnFlag)
					}
					contract, err := systemSmartContracts.NewESDTSmartContract(systemSmartContracts.ArgsNewESDTSmartContract{
						Eei: host, Marshalizer: marshaller, Hasher: &hashingMocks.HasherMock{},
						GasCost:       vm.GasCost{MetaChainSystemSCsCost: vm.MetaChainSystemSCsCost{ESDTOperations: 7}},
						ESDTSCConfig:  config.ESDTSystemSCConfig{BaseIssuingCost: "1000"},
						ESDTSCAddress: core.ESDTSCAddress, EndOfEpochSCAddress: vm.EndOfEpochAddress,
						AddressPubKeyConverter: testscommon.NewPubkeyConverterMock(32), EnableEpochsHandler: flags,
					})
					require.NoError(t, err)
					container := &mock.SystemSCContainerStub{GetCalled: func(key []byte) (vm.SystemSmartContract, error) {
						require.Equal(t, core.ESDTSCAddress, key)
						return contract, nil
					}}
					require.NoError(t, host.SetSystemSCContainer(container))
					args := createMockArguments()
					args.SystemEI, args.SystemContracts = host, container
					runtime, err := NewSystemVM(args)
					require.NoError(t, err)
					input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: owner, CallValue: big.NewInt(0), GasProvided: 100, Arguments: [][]byte{id, {7}}}, RecipientAddr: core.ESDTSCAddress, Function: function}
					wantCode, wantMessage := vmcommon.Ok, ""
					wantGas, wantMinted, wantBurnt := uint64(0), int64(100), int64(7)
					if function == "mint" {
						wantGas, wantMinted, wantBurnt = 93, 107, 0
					}
					switch scenario {
					case "disabled":
						wantCode = vmcommon.UserError
						if function == "mint" {
							wantMessage = "global mint is no more enabled, use local mint"
						} else {
							wantMessage = "global burn is no more enabled, use local burn"
						}
					case "zero":
						input.Arguments[1], wantCode = nil, vmcommon.UserError
						if function == "mint" {
							wantMessage = "negative or zero mint value"
						} else {
							wantMessage = "negative or 0 value to burn"
						}
					case "gas":
						input.GasProvided = 6
						if function == "mint" {
							wantCode, wantMessage = vmcommon.OutOfGas, "not enough gas"
						}
					case "callValue":
						input.CallValue, wantCode, wantMessage = big.NewInt(1), vmcommon.OutOfFunds, "callValue must be 0"
					}
					output, err := runtime.RunSmartContractCall(input)
					require.NoError(t, err)
					require.Equal(t, wantCode, output.ReturnCode)
					require.Equal(t, wantMessage, output.ReturnMessage)
					require.Zero(t, output.GasRefund.Sign())
					require.Empty(t, output.ReturnData)
					require.Empty(t, output.Logs)
					if wantCode != vmcommon.Ok {
						require.Zero(t, output.GasRemaining)
						require.Empty(t, output.OutputAccounts)
					} else {
						require.Equal(t, wantGas, output.GasRemaining)
						updates := output.OutputAccounts[string(core.ESDTSCAddress)].StorageUpdates
						require.Len(t, updates, 1)
						current := &systemSmartContracts.ESDTDataV2{}
						require.NoError(t, marshaller.Unmarshal(current, updates[string(id)].Data))
						expected := *token
						expected.MintedValue, expected.BurntValue = big.NewInt(wantMinted), big.NewInt(wantBurnt)
						require.Equal(t, &expected, current)
						if function == "mint" {
							require.Len(t, output.OutputAccounts, 2)
							transfers := output.OutputAccounts[string(owner)].OutputTransfers
							require.Len(t, transfers, 1)
							require.Equal(t, []byte("ESDTTransfer@4f52442d616263646566@07"), transfers[0].Data)
							require.Zero(t, transfers[0].GasLimit)
							require.Zero(t, transfers[0].Value.Sign())
						} else {
							require.Len(t, output.OutputAccounts, 1)
						}
						for address, account := range output.OutputAccounts {
							require.Zero(t, account.BalanceDelta.Sign())
							if function != "mint" || address != string(owner) {
								require.Empty(t, account.OutputTransfers)
							}
						}
					}
					if configured {
						require.Equal(t, 2, classifier.calls)
						require.Equal(t, baseline, output)
					} else {
						require.Zero(t, classifier.calls)
						baseline = output
					}
				}
			})
		}
	}
}

type qualFA01ReplacementContext struct {
	*mock.SystemEIStub
	replaced bool
}

func (c *qualFA01ReplacementContext) ReplaceDRWAClassifier(vm.DRWATokenClassifier) error {
	c.replaced = true
	return nil
}

func TestQualFA01SystemVMHandoffLock(t *testing.T) {
	ctx := &qualFA01ReplacementContext{SystemEIStub: &mock.SystemEIStub{}}
	args := createMockArguments()
	args.SystemEI = ctx
	runtime, err := NewSystemVM(args)
	require.NoError(t, err)
	runtime.criticalSection.Lock()
	err = runtime.ReplaceDRWAClassifier(nil)
	runtime.criticalSection.Unlock()
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.False(t, ctx.replaced, "VM boundary must refuse before reaching the context")
}
