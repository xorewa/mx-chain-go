package builtInFunctions

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/common"
	processMock "github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwa"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	trieMock "github.com/multiversx/mx-chain-go/testscommon/trie"
	"github.com/multiversx/mx-chain-go/testscommon/vmcommonMocks"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestDRWADestinationSuccessProducesOneReceiptWithExactGas(t *testing.T) {
	destination, input, account, artifacts := newDRWADestinationFixture(t, true)
	output, err := destination.ProcessBuiltinFunction(nil, account, input)
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, output.ReturnCode)
	require.Equal(t, vmcommon.ProtocolExecutionOutcomeSettlementReceipt, output.ProtocolExecution.Outcome)
	require.Equal(t, uint64(25), output.ProtocolExecution.LocalGasUsed)
	require.Equal(t, uint64(75), output.ProtocolExecution.ForwardedGas)
	require.Zero(t, output.GasRemaining)
	require.Len(t, output.OutputAccounts, 1)
	outAccount := output.OutputAccounts[string(artifacts.Envelope.Context.SourceHolder[:])]
	require.NotNil(t, outAccount)
	require.Len(t, outAccount.OutputTransfers, 1)
	carrier := outAccount.OutputTransfers[0]
	require.Equal(t, uint64(75), carrier.GasLimit)
	require.Equal(t, vmData.ProtocolMessageKindDRWA, carrier.ProtocolMessageKind)
	require.Equal(t, vmData.DirectCall, carrier.CallType)
	prefix := []byte(DRWASettlementReceiptFunction + "@")
	require.True(t, bytes.HasPrefix(carrier.Data, prefix))
}

func TestDRWADestinationReceiverDenialProducesTypedSingleRefund(t *testing.T) {
	destination, input, account, artifacts := newDRWADestinationFixture(t, false)
	output, err := destination.ProcessBuiltinFunction(nil, account, input)
	require.NoError(t, err)
	require.Equal(t, vmcommon.UserError, output.ReturnCode)
	require.Equal(t, vmcommon.ProtocolExecutionOutcomeRefundEnvelope, output.ProtocolExecution.Outcome)
	require.Equal(t, uint64(40), output.ProtocolExecution.LocalGasUsed)
	require.Equal(t, uint64(60), output.ProtocolExecution.ForwardedGas)
	carrier := output.OutputAccounts[string(artifacts.Envelope.Context.SourceHolder[:])].OutputTransfers[0]
	encoded := carrier.Data[len(DRWARefundEnvelopeFunction)+1:]
	refundBytes := make([]byte, hex.DecodedLen(len(encoded)))
	_, err = hex.Decode(refundBytes, encoded)
	require.NoError(t, err)
	refund, err := drwa.DecodeRefundEnvelope(refundBytes)
	require.NoError(t, err)
	require.Equal(t, artifacts.Envelope.Context.EffectID, refund.EffectID)
	require.Equal(t, artifacts.ContextHash, refund.ContextHash)
	require.Equal(t, artifacts.Envelope.Context.SourceHolder, refund.RefundTo)
}

func TestDRWADestinationPostCreditFailureCarriesRefundForProcessorRollback(t *testing.T) {
	destination, input, account, _ := newDRWADestinationFixture(t, true)
	destination.delegate = &processMock.BuiltInFunctionStub{ProcessBuiltinFunctionCalled: func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
		return nil, errors.New("injected baseline credit failure")
	}}
	output, err := destination.ProcessBuiltinFunction(nil, account, input)
	require.NoError(t, err)
	require.Equal(t, vmcommon.UserError, output.ReturnCode)
	require.Equal(t, vmcommon.ProtocolExecutionOutcomeRefundEnvelope, output.ProtocolExecution.Outcome)
	require.Contains(t, output.ReturnMessage, ErrDRWADestinationMutation.Error())
}

func TestDRWADestinationUntrustedIngressCannotRequestRefund(t *testing.T) {
	destination, input, account, _ := newDRWADestinationFixture(t, true)
	input.NativeCallOrigin = vmcommon.NativeCallOriginOriginalUserTransaction
	output, err := destination.ProcessBuiltinFunction(nil, account, input)
	require.Nil(t, output)
	require.ErrorIs(t, err, ErrDRWADestinationDenied)
}

func TestDRWADestinationAdmissionRejectsEveryRuledPredicateBeforeMutation(t *testing.T) {
	tests := []struct {
		name           string
		inputNil       bool
		senderPresent  bool
		destinationNil bool
		mutate         func(*drwaDestination, *vmcommon.ContractCallInput, *vmcommonMocks.UserAccountStub)
	}{
		{name: "nil input", inputNil: true},
		{name: "sender account present", senderPresent: true},
		{name: "destination account absent", destinationNil: true},
		{name: "activation disabled", mutate: func(destination *drwaDestination, _ *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub) {
			destination.enableEpochsHandler = enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
		}},
		{name: "short source address", mutate: func(_ *drwaDestination, input *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub) {
			input.CallerAddr = []byte{1}
		}},
		{name: "short destination address", mutate: func(_ *drwaDestination, input *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub) {
			input.RecipientAddr = []byte{1}
		}},
		{name: "smart contract source", mutate: func(_ *drwaDestination, input *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub) {
			input.CallerAddr = make([]byte, drwaAddressLength)
		}},
		{name: "smart contract destination", mutate: func(_ *drwaDestination, input *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub) {
			input.RecipientAddr = make([]byte, drwaAddressLength)
		}},
		{name: "source is local", mutate: func(destination *drwaDestination, _ *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub) {
			destination.shardCoordinator = &testscommon.ShardsCoordinatorMock{CurrentShard: 1, ComputeIdCalled: func(_ []byte) uint32 { return 1 }}
		}},
		{name: "destination is remote", mutate: func(destination *drwaDestination, _ *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub) {
			destination.shardCoordinator = &testscommon.ShardsCoordinatorMock{CurrentShard: 1, ComputeIdCalled: func(_ []byte) uint32 { return 0 }}
		}},
		{name: "account address mismatch", mutate: func(_ *drwaDestination, _ *vmcommon.ContractCallInput, account *vmcommonMocks.UserAccountStub) {
			account.AddressBytesCalled = func() []byte { return bytes.Repeat([]byte{0x44}, drwaAddressLength) }
		}},
		{name: "wrong origin", mutate: func(_ *drwaDestination, input *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub) {
			input.NativeCallOrigin = vmcommon.NativeCallOriginUnknown
		}},
		{name: "wrong call type", mutate: func(_ *drwaDestination, input *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub) {
			input.CallType = vmData.AsynchronousCall
		}},
		{name: "wrong function", mutate: func(_ *drwaDestination, input *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub) {
			input.Function = core.BuiltInFunctionESDTTransfer
		}},
		{name: "nil call value", mutate: func(_ *drwaDestination, input *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub) {
			input.CallValue = nil
		}},
		{name: "nonzero call value", mutate: func(_ *drwaDestination, input *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub) {
			input.CallValue = big.NewInt(1)
		}},
		{name: "gas lock", mutate: func(_ *drwaDestination, input *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub) {
			input.GasLocked = 1
		}},
		{name: "return after error", mutate: func(_ *drwaDestination, input *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub) {
			input.ReturnCallAfterError = true
		}},
		{name: "async metadata", mutate: func(_ *drwaDestination, input *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub) {
			input.AsyncArguments = &vmcommon.AsyncArguments{CallID: []byte{1}}
		}},
		{name: "parsed ESDT transfer", mutate: func(_ *drwaDestination, input *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub) {
			input.ESDTTransfers = []*vmcommon.ESDTTransfer{{ESDTValue: big.NewInt(1)}}
		}},
		{name: "wrong argument count", mutate: func(_ *drwaDestination, input *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub) {
			input.Arguments = nil
		}},
		{name: "short current hash", mutate: func(_ *drwaDestination, input *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub) {
			input.CurrentTxHash = []byte{1}
		}},
		{name: "zero current hash", mutate: func(_ *drwaDestination, input *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub) {
			input.CurrentTxHash = make([]byte, drwaHashLength)
		}},
		{name: "short original hash", mutate: func(_ *drwaDestination, input *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub) {
			input.OriginalTxHash = []byte{1}
		}},
		{name: "zero original hash", mutate: func(_ *drwaDestination, input *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub) {
			input.OriginalTxHash = make([]byte, drwaHashLength)
		}},
		{name: "short previous hash", mutate: func(_ *drwaDestination, input *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub) {
			input.PrevTxHash = []byte{1}
		}},
		{name: "original previous mismatch", mutate: func(_ *drwaDestination, input *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub) {
			input.PrevTxHash = bytes.Repeat([]byte{0x55}, drwaHashLength)
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			destination, input, account, _ := newDRWADestinationFixture(t, true)
			delegateCalled := false
			destination.delegate = &processMock.BuiltInFunctionStub{ProcessBuiltinFunctionCalled: func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
				delegateCalled = true
				return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
			}}
			if test.mutate != nil {
				test.mutate(destination, input, account)
			}

			var actualInput *vmcommon.ContractCallInput
			if !test.inputNil {
				actualInput = input
			}
			var sender vmcommon.UserAccountHandler
			if test.senderPresent {
				sender = account
			}
			var receiver vmcommon.UserAccountHandler = account
			if test.destinationNil {
				receiver = nil
			}

			output, err := destination.ProcessBuiltinFunction(sender, receiver, actualInput)
			require.Nil(t, output)
			require.ErrorIs(t, err, ErrDRWADestinationDenied)
			require.False(t, delegateCalled)
		})
	}
}

func TestDRWADestinationReDerivationRejectsEveryRuledBindingBeforeMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *vmcommon.ContractCallInput)
	}{
		{name: "source binding", mutate: func(t *testing.T, input *vmcommon.ContractCallInput) {
			rewriteDRWADestinationEnvelope(t, input, func(envelope *drwa.ValueEnvelope) { envelope.Context.SourceHolder = [32]byte{0x31} })
		}},
		{name: "destination binding", mutate: func(t *testing.T, input *vmcommon.ContractCallInput) {
			rewriteDRWADestinationEnvelope(t, input, func(envelope *drwa.ValueEnvelope) { envelope.Context.DestinationHolder = [32]byte{0x32} })
		}},
		{name: "origin binding", mutate: func(t *testing.T, input *vmcommon.ContractCallInput) {
			rewriteDRWADestinationEnvelope(t, input, func(envelope *drwa.ValueEnvelope) { envelope.Context.OriginExecutionIdentity = [32]byte{0x33} })
		}},
		{name: "original transfer payload", mutate: func(t *testing.T, input *vmcommon.ContractCallInput) {
			rewriteDRWADestinationEnvelope(t, input, func(envelope *drwa.ValueEnvelope) {
				envelope.OriginalTransferPayload = append(envelope.OriginalTransferPayload, '0')
			})
		}},
		{name: "effect id", mutate: func(t *testing.T, input *vmcommon.ContractCallInput) {
			rewriteDRWADestinationEnvelope(t, input, func(envelope *drwa.ValueEnvelope) { envelope.Context.EffectID = [32]byte{0x34} })
		}},
		{name: "semantic context", mutate: func(t *testing.T, input *vmcommon.ContractCallInput) {
			rewriteDRWADestinationEnvelope(t, input, func(envelope *drwa.ValueEnvelope) { envelope.Context.Quantity = []byte{3} })
		}},
		{name: "invalid semantic token", mutate: func(t *testing.T, input *vmcommon.ContractCallInput) {
			rewriteDRWADestinationEnvelope(t, input, func(envelope *drwa.ValueEnvelope) {
				envelope.Context.RegulatedTokenID = []byte("invalid token")
			})
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			destination, input, account, _ := newDRWADestinationFixture(t, true)
			delegateCalled := false
			destination.delegate = &processMock.BuiltInFunctionStub{ProcessBuiltinFunctionCalled: func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
				delegateCalled = true
				return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
			}}
			test.mutate(t, input)

			output, err := destination.ProcessBuiltinFunction(nil, account, input)
			require.Nil(t, output)
			require.ErrorIs(t, err, ErrDRWADestinationDenied)
			require.False(t, delegateCalled)
		})
	}
}

func TestDRWADestinationProgramDenialsAreFailClosedAndDoNotCredit(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*testing.T, *drwaDestination, *vmcommon.ContractCallInput, *vmcommonMocks.UserAccountStub, *drwa.DirectValueArtifacts)
		wantRefund bool
		wantFatal  bool
	}{
		{name: "zero network domain", mutate: func(_ *testing.T, destination *drwaDestination, _ *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub, _ *drwa.DirectValueArtifacts) {
			destination.networkDomain = [32]byte{}
		}},
		{name: "zero CEB configuration", mutate: func(_ *testing.T, destination *drwaDestination, _ *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub, _ *drwa.DirectValueArtifacts) {
			destination.cebEpoch = 0
		}},
		{name: "unavailable round", mutate: func(_ *testing.T, destination *drwaDestination, _ *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub, _ *drwa.DirectValueArtifacts) {
			destination.blockchainHook = nil
		}},
		{name: "settlement expired", wantRefund: true, mutate: func(t *testing.T, destination *drwaDestination, _ *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub, _ *drwa.DirectValueArtifacts) {
			require.NoError(t, destination.setBlockchainHook(&testscommon.BlockChainHookStub{CurrentRoundCalled: func() uint64 { return 101 }}))
		}},
		{name: "CEB mismatch", wantRefund: true, mutate: func(_ *testing.T, destination *drwaDestination, _ *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub, _ *drwa.DirectValueArtifacts) {
			destination.cebEpoch++
		}},
		{name: "classifier error", wantRefund: true, mutate: func(_ *testing.T, destination *drwaDestination, _ *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub, _ *drwa.DirectValueArtifacts) {
			destination.classifier = func(_ []byte) (bool, error) { return false, errors.New("classifier unavailable") }
		}},
		{name: "token not regulated", wantRefund: true, mutate: func(_ *testing.T, destination *drwaDestination, _ *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub, _ *drwa.DirectValueArtifacts) {
			destination.classifier = func(_ []byte) (bool, error) { return false, nil }
		}},
		{name: "retained identity absent", wantRefund: true, mutate: func(_ *testing.T, destination *drwaDestination, _ *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub, _ *drwa.DirectValueArtifacts) {
			destination.retainedWorkBudgetsProvider = func([32]byte) (drwa.WorkBudgets, uint64, error) {
				return drwa.WorkBudgets{}, 0, errors.New("identity not retained")
			}
		}},
		{name: "destination budget mismatch", wantRefund: true, mutate: func(_ *testing.T, destination *drwaDestination, _ *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub, _ *drwa.DirectValueArtifacts) {
			destination.retainedWorkBudgetsProvider = func([32]byte) (drwa.WorkBudgets, uint64, error) {
				return drwa.WorkBudgets{DestinationGate: 11, SuccessReceipt: 20, RefundGeneration: 30, SourceCompletion: 40}, 101, nil
			}
		}},
		{name: "success budget mismatch", wantRefund: true, mutate: func(_ *testing.T, destination *drwaDestination, _ *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub, _ *drwa.DirectValueArtifacts) {
			destination.retainedWorkBudgetsProvider = func([32]byte) (drwa.WorkBudgets, uint64, error) {
				return drwa.WorkBudgets{DestinationGate: 10, SuccessReceipt: 21, RefundGeneration: 30, SourceCompletion: 40}, 101, nil
			}
		}},
		{name: "refund budget mismatch", wantRefund: true, mutate: func(_ *testing.T, destination *drwaDestination, _ *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub, _ *drwa.DirectValueArtifacts) {
			destination.retainedWorkBudgetsProvider = func([32]byte) (drwa.WorkBudgets, uint64, error) {
				return drwa.WorkBudgets{DestinationGate: 10, SuccessReceipt: 20, RefundGeneration: 31, SourceCompletion: 40}, 101, nil
			}
		}},
		{name: "completion budget mismatch", wantRefund: true, mutate: func(_ *testing.T, destination *drwaDestination, _ *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub, _ *drwa.DirectValueArtifacts) {
			destination.retainedWorkBudgetsProvider = func([32]byte) (drwa.WorkBudgets, uint64, error) {
				return drwa.WorkBudgets{DestinationGate: 10, SuccessReceipt: 20, RefundGeneration: 30, SourceCompletion: 41}, 101, nil
			}
		}},
		{name: "incoming excess gas", wantRefund: true, mutate: func(_ *testing.T, _ *drwaDestination, input *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub, _ *drwa.DirectValueArtifacts) {
			input.GasProvided = 101
		}},
		{name: "incoming insufficient total but refundable gas", wantRefund: true, mutate: func(_ *testing.T, _ *drwaDestination, input *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub, _ *drwa.DirectValueArtifacts) {
			input.GasProvided = 99
		}},
		{name: "incoming gas cannot carry truthful refund", mutate: func(_ *testing.T, _ *drwaDestination, input *vmcommon.ContractCallInput, _ *vmcommonMocks.UserAccountStub, _ *drwa.DirectValueArtifacts) {
			input.GasProvided = 59
		}},
		{name: "nil data handler", wantRefund: true, mutate: func(_ *testing.T, _ *drwaDestination, _ *vmcommon.ContractCallInput, account *vmcommonMocks.UserAccountStub, _ *drwa.DirectValueArtifacts) {
			account.AccountDataHandlerCalled = func() vmcommon.AccountDataHandler { return nil }
		}},
		{name: "receiver record absent", wantRefund: true, mutate: receiverGateRetrieveMutation(nil, nil)},
		{name: "receiver record malformed", wantRefund: true, mutate: receiverGateRetrieveMutation([]byte{1}, nil)},
		{name: "receiver storage error", wantRefund: true, mutate: receiverGateRetrieveMutation(nil, errors.New("storage unavailable"))},
		{name: "receiver database closing", wantFatal: true, mutate: receiverGateRetrieveMutation(nil, core.ErrDBIsClosed)},
		{name: "receiver holder mismatch", wantRefund: true, mutate: receiverGateRecordMutation(func(record *drwa.ReceiverGateRecord) { record.Holder = [32]byte{0x41} })},
		{name: "receiver CEB mismatch", wantRefund: true, mutate: receiverGateRecordMutation(func(record *drwa.ReceiverGateRecord) { record.CEBEpoch++ })},
		{name: "receiver not admitted", wantRefund: true, mutate: receiverGateRecordMutation(func(record *drwa.ReceiverGateRecord) { record.Admitted = false })},
		{name: "receiver record expired", wantRefund: true, mutate: receiverGateRecordMutation(func(record *drwa.ReceiverGateRecord) { record.ValidThroughRound = 6 })},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			destination, input, account, artifacts := newDRWADestinationFixture(t, true)
			delegateCalled := false
			destination.delegate = &processMock.BuiltInFunctionStub{ProcessBuiltinFunctionCalled: func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
				delegateCalled = true
				return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
			}}
			test.mutate(t, destination, input, account, artifacts)

			output, err := destination.ProcessBuiltinFunction(nil, account, input)
			require.False(t, delegateCalled)
			switch {
			case test.wantRefund:
				require.NoError(t, err)
				requireDRWASingleRefund(t, output, artifacts.Envelope.Context.SourceHolder)
			case test.wantFatal:
				require.Nil(t, output)
				require.Error(t, err)
				require.True(t, core.IsClosingError(err))
			default:
				require.Nil(t, output)
				require.ErrorIs(t, err, ErrDRWADestinationDenied)
			}
		})
	}
}

func TestDRWADestinationAcceptsExactRetainedOldScheduleIdentity(t *testing.T) {
	destination, input, account, originalArtifacts := newDRWADestinationFixture(t, true)
	first := fillGasMapInternal(make(map[string]map[string]uint64), 1)
	first[drwa.DRWAWorkBudgetSection] = drwaBudgetSection(10, 20, 30, 40)
	second := fillGasMapInternal(make(map[string]map[string]uint64), 2)
	second[drwa.DRWAWorkBudgetSection] = drwaBudgetSection(9, 19, 29, 39)
	catalog, err := drwa.SealGasScheduleCatalog([]drwa.GasScheduleProfile{
		{StartEpoch: 0, Schedule: first},
		{StartEpoch: 7, Schedule: second},
	})
	require.NoError(t, err)
	oldIdentity, err := drwa.GasScheduleIdentity(first)
	require.NoError(t, err)

	context := originalArtifacts.Envelope.Context
	artifacts, err := drwa.BuildDirectValueArtifacts(
		destination.networkDomain,
		context.OriginExecutionIdentity,
		drwa.DirectValueIntent{
			RegulatedTokenID:         context.RegulatedTokenID,
			Quantity:                 context.Quantity,
			SourceHolder:             context.SourceHolder,
			DestinationHolder:        context.DestinationHolder,
			CEBEpoch:                 context.CEBEpoch,
			SettlementExpiry:         context.SettlementExpiry,
			GasScheduleIdentity:      oldIdentity,
			DestinationGateGasLimit:  context.DestinationGateGasLimit,
			SuccessReceiptGasLimit:   context.SuccessReceiptGasLimit,
			RefundGenerationGasLimit: context.RefundGenerationGasLimit,
			SourceCompletionGasLimit: context.SourceCompletionGasLimit,
		},
	)
	require.NoError(t, err)
	input.Arguments[0], err = drwa.EncodeValueEnvelope(artifacts.Envelope)
	require.NoError(t, err)
	destination.retainedWorkBudgetsProvider = func(identity [32]byte) (drwa.WorkBudgets, uint64, error) {
		require.Equal(t, oldIdentity, identity)
		return retainedDRWAWorkBudgets(identity, catalog)
	}

	output, err := destination.ProcessBuiltinFunction(nil, account, input)
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, output.ReturnCode)
	require.Equal(t, vmcommon.ProtocolExecutionOutcomeSettlementReceipt, output.ProtocolExecution.Outcome)
}

func rewriteDRWADestinationEnvelope(
	t *testing.T,
	input *vmcommon.ContractCallInput,
	mutate func(*drwa.ValueEnvelope),
) {
	t.Helper()
	envelope, err := drwa.DecodeValueEnvelope(input.Arguments[0])
	require.NoError(t, err)
	mutate(envelope)
	input.Arguments[0], err = drwa.EncodeValueEnvelope(*envelope)
	require.NoError(t, err)
}

func receiverGateRetrieveMutation(encoded []byte, retrieveErr error) func(*testing.T, *drwaDestination, *vmcommon.ContractCallInput, *vmcommonMocks.UserAccountStub, *drwa.DirectValueArtifacts) {
	return func(_ *testing.T, _ *drwaDestination, _ *vmcommon.ContractCallInput, account *vmcommonMocks.UserAccountStub, _ *drwa.DirectValueArtifacts) {
		account.AccountDataHandlerCalled = func() vmcommon.AccountDataHandler {
			return &trieMock.DataTrieTrackerStub{RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
				return encoded, 0, retrieveErr
			}}
		}
	}
}

func receiverGateRecordMutation(mutate func(*drwa.ReceiverGateRecord)) func(*testing.T, *drwaDestination, *vmcommon.ContractCallInput, *vmcommonMocks.UserAccountStub, *drwa.DirectValueArtifacts) {
	return func(t *testing.T, _ *drwaDestination, _ *vmcommon.ContractCallInput, account *vmcommonMocks.UserAccountStub, artifacts *drwa.DirectValueArtifacts) {
		record := &drwa.ReceiverGateRecord{
			Holder:            artifacts.Envelope.Context.DestinationHolder,
			CEBEpoch:          artifacts.Envelope.Context.CEBEpoch,
			Admitted:          true,
			ValidThroughRound: 100,
		}
		mutate(record)
		encoded, err := drwa.EncodeReceiverGateRecord(*record)
		require.NoError(t, err)
		receiverGateRetrieveMutation(encoded, nil)(t, nil, nil, account, artifacts)
	}
}

func requireDRWASingleRefund(t *testing.T, output *vmcommon.VMOutput, source [32]byte) {
	t.Helper()
	require.NotNil(t, output)
	require.Equal(t, vmcommon.UserError, output.ReturnCode)
	require.NotNil(t, output.ProtocolExecution)
	require.Equal(t, vmcommon.ProtocolExecutionOutcomeRefundEnvelope, output.ProtocolExecution.Outcome)
	require.Len(t, output.OutputAccounts, 1)
	require.Len(t, output.OutputAccounts[string(source[:])].OutputTransfers, 1)
}

func newDRWADestinationFixture(
	t *testing.T,
	admitted bool,
) (*drwaDestination, *vmcommon.ContractCallInput, *vmcommonMocks.UserAccountStub, *drwa.DirectValueArtifacts) {
	t.Helper()
	source := [32]byte{}
	destinationHolder := [32]byte{}
	for index := range source {
		source[index] = 0x11
		destinationHolder[index] = 0x22
	}
	networkDomain := [32]byte{1}
	originIdentity := [32]byte{3}
	gasIdentity := [32]byte{2}
	budgets := drwa.WorkBudgets{DestinationGate: 10, SuccessReceipt: 20, RefundGeneration: 30, SourceCompletion: 40}
	artifacts, err := drwa.BuildDirectValueArtifacts(networkDomain, originIdentity, drwa.DirectValueIntent{
		RegulatedTokenID:         []byte("TOKEN-abcdef"),
		Quantity:                 []byte{2},
		SourceHolder:             source,
		DestinationHolder:        destinationHolder,
		CEBEpoch:                 9,
		SettlementExpiry:         100,
		GasScheduleIdentity:      gasIdentity,
		DestinationGateGasLimit:  budgets.DestinationGate,
		SuccessReceiptGasLimit:   budgets.SuccessReceipt,
		RefundGenerationGasLimit: budgets.RefundGeneration,
		SourceCompletionGasLimit: budgets.SourceCompletion,
	})
	require.NoError(t, err)
	envelopeBytes, err := drwa.EncodeValueEnvelope(artifacts.Envelope)
	require.NoError(t, err)
	receiverBytes, err := drwa.EncodeReceiverGateRecord(drwa.ReceiverGateRecord{
		Holder:            destinationHolder,
		CEBEpoch:          9,
		Admitted:          admitted,
		ValidThroughRound: 100,
	})
	require.NoError(t, err)
	dataHandler := &trieMock.DataTrieTrackerStub{RetrieveValueCalled: func(key []byte) ([]byte, uint32, error) {
		if bytes.Equal(key, drwa.ReceiverGateStorageKey(artifacts.Envelope.Context.RegulatedTokenID)) {
			return receiverBytes, 0, nil
		}
		return nil, 0, nil
	}}
	account := &vmcommonMocks.UserAccountStub{
		AddressBytesCalled:       func() []byte { return destinationHolder[:] },
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler { return dataHandler },
	}
	delegate := &processMock.BuiltInFunctionStub{ProcessBuiltinFunctionCalled: func(acntSnd, acntDst vmcommon.UserAccountHandler, delegateInput *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
		require.Nil(t, acntSnd)
		require.Equal(t, account, acntDst)
		require.Equal(t, uint64(10), delegateInput.GasProvided)
		return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 5}, nil
	}}
	coordinator := &testscommon.ShardsCoordinatorMock{NoShards: 2, CurrentShard: 1, ComputeIdCalled: func(address []byte) uint32 {
		if bytes.Equal(address, source[:]) {
			return 0
		}
		return 1
	}}
	destination, err := newDRWADestination(drwaDestinationArgs{
		delegate:            delegate,
		classifier:          func(_ []byte) (bool, error) { return true, nil },
		enableEpochsHandler: enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.DRWAEnforcementFlag),
		shardCoordinator:    coordinator,
		networkDomain:       networkDomain,
		cebEpoch:            9,
		retainedWorkBudgetsProvider: func(identity [32]byte) (drwa.WorkBudgets, uint64, error) {
			require.Equal(t, gasIdentity, identity)
			return budgets, 100, nil
		},
	})
	require.NoError(t, err)
	require.NoError(t, destination.setBlockchainHook(&testscommon.BlockChainHookStub{CurrentRoundCalled: func() uint64 { return 7 }}))
	executionIdentity := bytes.Repeat([]byte{4}, 32)
	input := &vmcommon.ContractCallInput{
		RecipientAddr: destinationHolder[:],
		Function:      vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope,
		VMInput: vmcommon.VMInput{
			NativeCallOrigin: vmcommon.NativeCallOriginDRWAProtocolMessage,
			CallerAddr:       source[:],
			Arguments:        [][]byte{envelopeBytes},
			CallValue:        big.NewInt(0),
			CallType:         vmData.DirectCall,
			GasProvided:      100,
			CurrentTxHash:    executionIdentity,
			OriginalTxHash:   originIdentity[:],
			PrevTxHash:       originIdentity[:],
		},
	}

	return destination, input, account, artifacts
}
