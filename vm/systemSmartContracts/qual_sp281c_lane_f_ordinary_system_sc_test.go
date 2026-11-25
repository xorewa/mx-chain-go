package systemSmartContracts

import (
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/marshallerMock"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestQualSP281CLaneFOrdinaryGovernanceVoteRecords(t *testing.T) {
	args := createMockArgumentsForDelegation()
	contextArgs := createDefaultEeiArgs()
	contextArgs.BlockChainHook = &mock.BlockChainHookStub{
		CurrentEpochCalled: func() uint32 { return 5 },
	}
	host, err := NewVMContext(contextArgs)
	require.NoError(t, err)
	args.Eei = host
	d, err := NewDelegationSystemSC(args)
	require.NoError(t, err)

	owner := []byte("ordinary-delegator")
	gov := args.GovernanceSCAddress
	missing := uint64(1)
	unreadable := uint64(2)
	active := uint64(3)
	list := &OngoingVotedListV2{
		Direct: []uint64{missing, unreadable, unreadable},
		DelegatedWithAddress: []*DelegatedWithAddress{
			{Nonce: active}, {Nonce: unreadable}, nil,
		},
	}
	host.SetStorageForAddress(gov, owner, []byte("vote list"))
	host.SetStorageForAddress(gov, append([]byte(noncePrefix), byte(missing)), []byte("missing"))
	host.SetStorageForAddress(gov, append([]byte(noncePrefix), byte(unreadable)), []byte("unreadable"))
	host.SetStorageForAddress(gov, append([]byte(noncePrefix), byte(active)), []byte("active"))
	host.SetStorageForAddress(gov, []byte(proposalPrefix+"unreadable"), []byte("unreadable proposal"))
	host.SetStorageForAddress(gov, []byte(proposalPrefix+"active"), []byte("active proposal"))

	readErr := errors.New("fixture read error")
	proposalReads := []string{}
	d.marshalizer = &marshallerMock.MarshalizerStub{UnmarshalCalled: func(value interface{}, data []byte) error {
		switch value := value.(type) {
		case *OngoingVotedListV2:
			require.Equal(t, "vote list", string(data))
			value.Direct = list.Direct
			value.DelegatedWithAddress = list.DelegatedWithAddress
			return nil
		case *GeneralProposal:
			proposalReads = append(proposalReads, string(data))
			if string(data) == "active proposal" {
				value.EndVoteEpoch = 5
				return nil
			}
		}
		return readErr
	}}
	require.True(t, d.hasActiveGovernanceVote(owner))
	require.Equal(t, []string{"unreadable proposal", "active proposal"}, proposalReads)
	require.False(t, d.isProposalActive(missing, 5))
	require.False(t, d.isProposalActive(active, 6))

	d.marshalizer = &marshallerMock.MarshalizerStub{UnmarshalCalled: func(interface{}, []byte) error { return readErr }}
	require.False(t, d.hasActiveGovernanceVote(owner))
}

func TestQualSP281CLaneFOrdinaryOwnerChangeLogsSkipMissingFund(t *testing.T) {
	args := createMockArgumentsForDelegation()
	args.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub).AddActiveFlags(common.FixCorrectSmallIntAndGasLimitsFlag)
	host := createDefaultEei()
	args.Eei = host
	d, err := NewDelegationSystemSC(args)
	require.NoError(t, err)

	recipient := []byte("ordinary-delegation-contract")
	oldOwner := []byte("ordinary-old-owner")
	newOwner := []byte("ordinary-new-owner")
	host.SetSCAddress(recipient)
	valid := []byte("pending-fund")
	data, err := args.Marshalizer.Marshal(&Fund{Value: big.NewInt(25)})
	require.NoError(t, err)
	host.SetStorage(valid, data)
	input := CreateVmContractCallInput()
	input.Function, input.CallerAddr, input.RecipientAddr = "changeOwner", oldOwner, recipient
	input.Arguments = [][]byte{newOwner}

	d.createLogEventsForChangeOwner(input, &DelegatorData{UnStakedFunds: [][]byte{[]byte("missing-fund"), valid}})
	logs := host.GetLogs()
	require.Len(t, logs, 4)
	require.Equal(t, "delegate", string(logs[0].Identifier))
	require.Equal(t, newOwner, logs[0].Address)
	require.Equal(t, "withdraw", string(logs[1].Identifier))
	require.Equal(t, oldOwner, logs[1].Address)
	require.Equal(t, &vmcommon.LogEntry{
		Identifier: []byte("unDelegate"),
		Address:    newOwner,
		Topics:     [][]byte{{25}, {}, {}, {}, valid},
	}, logs[2])
	require.Equal(t, &vmcommon.LogEntry{
		Identifier: []byte(core.BuiltInFunctionChangeOwnerAddress),
		Address:    recipient,
		Topics:     [][]byte{newOwner},
	}, logs[3])
}

func TestQualSP281CLaneFOrdinaryMissingBalanceAndNestedInit(t *testing.T) {
	address := []byte("ordinary-balance-account")
	args := createDefaultEeiArgs()
	args.BlockChainHook = &mock.BlockChainHookStub{GetUserAccountCalled: func(got []byte) (vmcommon.UserAccountHandler, error) {
		require.Equal(t, address, got)
		return &stateMock.UserAccountStub{}, nil
	}}
	host, err := NewVMContext(args)
	require.NoError(t, err)
	require.Equal(t, big.NewInt(0), host.GetBalance(address))

	host = createDefaultEei()
	parent, key := []byte("ordinary-parent"), []byte("parent-key")
	host.SetSCAddress(parent)
	host.SetStorage(key, []byte("parent-value"))
	require.NoError(t, host.SetSystemSCContainer(&mock.SystemSCContainerStub{GetCalled: func(got []byte) (vm.SystemSmartContract, error) {
		require.Equal(t, core.ESDTSCAddress, got)
		return &mock.SystemSCStub{ExecuteCalled: func(*vmcommon.ContractCallInput) vmcommon.ReturnCode {
			t.Fatal("nested init reached the contract")
			return vmcommon.ExecutionFailed
		}}, nil
	}}))
	output, err := host.ExecuteOnDestContext(core.ESDTSCAddress, parent, big.NewInt(0), []byte(core.SCDeployInitFunctionName))
	require.NoError(t, err)
	require.Equal(t, vmcommon.UserError, output.ReturnCode)
	require.Equal(t, "cannot call smart contract init function", output.ReturnMessage)
	require.Empty(t, output.OutputAccounts)
	require.Equal(t, []byte("parent-value"), host.GetStorage(key))

	output, err = host.ExecuteDRWASystemCall(&vmcommon.ContractCallInput{RecipientAddr: core.ESDTSCAddress, Function: "getTokenProperties"},
		func() (*vmcommon.VMOutput, error) {
			return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 37}, nil
		})
	require.NoError(t, err)
	require.Equal(t, &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 37}, output)
	require.NoError(t, host.DRWAExecutionError())
}

func TestQualSP281CLaneFOrdinaryTokenIDUpdateOutput(t *testing.T) {
	for _, tc := range []struct {
		name        string
		fixed       bool
		failMarshal bool
	}{
		{name: "fixed success", fixed: true},
		{name: "fixed marshal error", fixed: true, failMarshal: true},
		{name: "legacy marshal error", failMarshal: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			contextArgs := createDefaultEeiArgs()
			classifier := &publicClassifier{}
			contextArgs.DRWAClassifier = classifier
			contextArgs.BlockChainHook = &mock.BlockChainHookStub{NumberOfShardsCalled: func() uint32 { return 2 }}
			host, err := NewVMContext(contextArgs)
			require.NoError(t, err)
			host.SetSCAddress(core.ESDTSCAddress)
			args := createMockArgumentsForESDT()
			args.Eei = host
			flags := args.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub)
			flags.AddActiveFlags(common.DynamicESDTFlag)
			flags.RemoveActiveFlags(common.FixCorrectSmallIntAndGasLimitsFlag)
			if tc.fixed {
				flags.AddActiveFlags(common.FixCorrectSmallIntAndGasLimitsFlag)
			}
			contract, err := NewESDTSmartContract(args)
			require.NoError(t, err)
			tokenID := []byte("TOKEN-abcdef")
			input := getDefaultVmInputForFunc("updateTokenID", [][]byte{tokenID})
			input.RecipientAddr = core.ESDTSCAddress
			require.NoError(t, contract.saveToken(tokenID, &ESDTDataV2{
				TokenType: []byte(core.NonFungibleESDT), OwnerAddress: input.CallerAddr,
			}))

			writeErr := errors.New("fixture marshal error")
			if tc.failMarshal {
				contract.marshalizer = &marshallerMock.MarshalizerStub{
					UnmarshalCalled: contract.marshalizer.Unmarshal,
					MarshalCalled:   func(interface{}) ([]byte, error) { return nil, writeErr },
				}
			}
			host.gasRemaining = 1_000_000
			code := contract.Execute(input)
			require.Equal(t, 1, classifier.calls)
			stored, err := contract.getExistingToken(tokenID)
			require.NoError(t, err)

			if tc.failMarshal {
				require.Equal(t, vmcommon.UserError, code)
				require.Equal(t, writeErr.Error(), host.returnMessage)
				require.Equal(t, []byte(core.NonFungibleESDT), stored.TokenType)
				require.Empty(t, host.outputAccounts)
				require.Empty(t, host.logs)
				return
			}
			tokenType := []byte(core.NonFungibleESDTv2)
			require.Equal(t, vmcommon.Ok, code)
			require.Equal(t, tokenType, stored.TokenType)
			require.Equal(t, []*vmcommon.LogEntry{{
				Identifier: []byte(core.ESDTSetTokenType), Address: input.CallerAddr,
				Topics: [][]byte{tokenID, tokenType},
			}}, host.logs)
			require.Len(t, host.outputAccounts, 2)
			payload := core.ESDTSetTokenType + "@" + hex.EncodeToString(tokenID) + "@" + hex.EncodeToString(tokenType)
			for shard := byte(0); shard < 2; shard++ {
				shardAddress := append([]byte(nil), core.SystemAccountAddress...)
				shardAddress[len(shardAddress)-1] = shard
				account := host.outputAccounts[string(shardAddress)]
				require.NotNil(t, account)
				require.Equal(t, shardAddress, account.Address)
				require.Len(t, account.OutputTransfers, 1)
				require.Equal(t, big.NewInt(0), account.OutputTransfers[0].Value)
				require.Equal(t, []byte(payload), account.OutputTransfers[0].Data)
			}
		})
	}
}

func TestQualSP281CLaneFOrdinaryDecimalBoundary(t *testing.T) {
	args := createMockArgumentsForESDT()
	args.EnableEpochsHandler.(*enableEpochsHandlerMock.EnableEpochsHandlerStub).AddActiveFlags(common.FixCorrectSmallIntAndGasLimitsFlag)
	contract, err := NewESDTSmartContract(args)
	require.NoError(t, err)
	decimals, err := contract.getNumOfDecimals([]byte{18})
	require.NoError(t, err)
	require.EqualValues(t, 18, decimals)
	decimals, err = contract.getNumOfDecimals([]byte{19})
	require.ErrorIs(t, err, vm.ErrInvalidNumberOfDecimals)
	require.Zero(t, decimals)
}

func TestQualSP281CLaneFOrdinaryReadBypassesTokenClassification(t *testing.T) {
	args := createDefaultEeiArgs()
	classifier := &publicClassifier{}
	args.DRWAClassifier = classifier
	host, err := NewVMContext(args)
	require.NoError(t, err)

	input := getDefaultVmInputForFunc("getTokenProperties", [][]byte{[]byte("TOKEN-abcdef")})
	input.RecipientAddr = core.ESDTSCAddress
	expected := &vmcommon.VMOutput{
		ReturnCode:   vmcommon.Ok,
		GasRemaining: 61,
		ReturnData:   [][]byte{[]byte("ordinary properties")},
	}
	output, err := host.ExecuteDRWASystemCall(input, func() (*vmcommon.VMOutput, error) {
		return expected, nil
	})
	require.NoError(t, err)
	require.Same(t, expected, output)
	require.Zero(t, classifier.calls)
}

func TestQualSP281CLaneFOrdinaryContextRefusesMissingAccountBinding(t *testing.T) {
	args := createDefaultEeiArgs()
	var missing *publicClassifier
	args.DRWAClassifier = missing
	host, err := NewVMContext(args)
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.Nil(t, host)

	refused := errors.New("fixture account binding refused")
	args.DRWAClassifier = &publicClassifier{accountsErr: refused}
	host, err = NewVMContext(args)
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.ErrorIs(t, err, refused)
	require.Nil(t, host)
}
