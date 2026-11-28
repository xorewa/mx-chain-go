package processing

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/config"
	factoryMock "github.com/multiversx/mx-chain-go/factory/mock"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	consensusMock "github.com/multiversx/mx-chain-go/testscommon/consensus"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/integrationtests"
	"github.com/multiversx/mx-chain-go/testscommon/processMocks"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func qualSP279CarrierSchedule() map[string]map[string]uint64 {
	class := drwa.RegistryDeltaCarrierClass
	return map[string]map[string]uint64{drwa.CarrierCostSection: {class + "Source": 4000, class + "Destination": 0,
		class + "Success": 9000, class + "Refund": 0, class + "Completion": 51000}}
}

// SP2-79: the funding owner of carried effects is built on the metachain node
// of a DRWA deployment only, priced by the node's own gas schedule and bound to
// the deployment's retained budget. The baseline schedules have no carrier
// entries, so it prices nothing until an admitted schedule supplies them.
func TestQualSP279CarrierFundingExistsOnlyOnTheMetachainOfADRWADeployment(t *testing.T) {
	store := integrationtests.CreateInMemoryShardAccountsDB()
	account, err := store.LoadAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue([]byte(core.ProtectedKeyPrefix+"DRWA@registry@count"), make([]byte, 8)))
	require.NoError(t, store.SaveAccount(account))
	_, err = store.Commit()
	require.NoError(t, err)
	validator := &processMocks.HeaderValidatorMock{}
	limits := config.DRWAInitialProgrammeLimits{RecordBytes: 4096, AggregateBytes: 1 << 16,
		Records: 100, RetainedBytes: 1 << 20, NewRecordsPerEpoch: 10}

	shard, _ := qualSP222Factory(t)
	shard.drwaConfigurationCandidate, _, _ = qualS1OverlayCandidate(t, 12)
	shard.drwaInitialProgrammeStartup = &config.DRWAInitialProgrammeStartup{Limits: limits}
	shard.drwaHeaderProofVerifier = &consensusMock.HeaderSigVerifierMock{}
	owner, err := shard.newDRWAFinalityImport(store, validator)
	require.NoError(t, err)
	_, isMeta := owner.(*drwaMetaFinalityImport)
	require.False(t, isMeta, "an execution shard has no funding owner")

	meta, _ := qualSP222Factory(t)
	meta.bootstrapComponents = &qualSP222Bootstrap{coordinator: &testscommon.ShardsCoordinatorMock{CurrentShard: core.MetachainShardId}}
	meta.coreData.(*factoryMock.CoreComponentsMock).EnableEpochsHandlerField = enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
	meta.config.StateTriesConfig.MaxStateTrieLevelInMemory = 5
	schedule := testscommon.NewGasScheduleNotifierMock(map[string]map[string]uint64{"BaseOpsAPICost": {"AsyncCallStep": 1}})
	var subscribers []core.GasScheduleSubscribeHandler
	schedule.RegisterNotifyHandlerCalled = func(handler core.GasScheduleSubscribeHandler) { subscribers = append(subscribers, handler) }
	meta.gasSchedule = schedule
	owner, err = meta.newDRWAFinalityImport(store, validator)
	require.NoError(t, err)
	require.Nil(t, owner, "an ordinary metachain node gets none")
	require.Empty(t, subscribers, "and nothing subscribes to its gas schedule")

	meta.drwaConfigurationCandidate, _, _ = qualS1OverlayCandidate(t, 12)
	meta.drwaInitialProgrammeStartup = &config.DRWAInitialProgrammeStartup{Limits: limits}
	meta.drwaHeaderProofVerifier = &consensusMock.HeaderSigVerifierMock{}
	owner, err = meta.newDRWAFinalityImport(store, validator)
	require.NoError(t, err)
	funding := owner.(*drwaMetaFinalityImport).DRWACarrierFunding()
	require.NotNil(t, funding)
	require.Len(t, subscribers, 1, "the price source follows the node's schedule")

	// The baseline schedule has no carrier entries: no admission.
	_, err = funding.Accept(drwa.RegistryDeltaCarrierClass, []byte("member"), 3, ^uint64(0))
	require.ErrorIs(t, err, drwa.ErrCarrierFunding)
	// An admitted schedule with the entries: the admission is priced by it.
	subscribers[0].GasScheduleChange(qualSP279CarrierSchedule())
	_, err = funding.Accept(drwa.RegistryDeltaCarrierClass, []byte("member"), 3, 4000+3*60000-1)
	require.ErrorIs(t, err, drwa.ErrCarrierUnderfunded)
	retained, err := funding.Read(drwa.RegistryDeltaCarrierClass, []byte("member"))
	require.NoError(t, err)
	require.Nil(t, retained)

	meta.gasSchedule = nil
	_, err = meta.newDRWAFinalityImport(store, validator)
	require.ErrorIs(t, err, drwa.ErrCarrierFunding, "no gas schedule: refused, not defaulted")
}

// With the funding owner installed in the metachain node's registration, and
// a schedule that prices the registry delta, ordinary calls of the ESDT system
// contract give what a node without DRWA gives: the same output, gas and state.
func TestQualSP279InstalledFundingLeavesOrdinaryMetachainCallsUnchanged(t *testing.T) {
	enabled := qualSP225MetaNode(t, true, qualSP225GenesisStore(t, qualSP225Regulated))
	native := qualSP225MetaNode(t, false, qualSP225GenesisStore(t, qualSP225Regulated))
	require.Nil(t, native.owner)
	prices, err := drwa.NewGasScheduleCarrierPricing(testscommon.NewGasScheduleNotifierMock(qualSP279CarrierSchedule()))
	require.NoError(t, err)
	funding, err := drwa.NewCarrierFunding(drwa.ArgsCarrierFunding{Accounts: enabled.user, Marshaller: &marshal.GogoProtoMarshalizer{},
		Hasher: blake2b.NewBlake2b(), Block: &qualSP279NoBlock{}, Prices: prices,
		Limits: drwa.RegistrationResourceLimits{Records: 100, RetainedBytes: 1 << 20, NewRecordsPerEpoch: 10}, RecordBytes: 4096})
	require.NoError(t, err)
	require.NoError(t, enabled.owner.SetRegistrationCarrierFunding(funding))
	require.NoError(t, enabled.owner.BeginExecution())

	run := func(label string, input func() *vmcommon.ContractCallInput) *vmcommon.VMOutput {
		t.Helper()
		expected, nativeErr := native.system.RunSmartContractCall(input())
		actual, enabledErr := enabled.system.RunSmartContractCall(input())
		require.Equal(t, nativeErr, enabledErr, label)
		require.Equal(t, expected, actual, label)
		return actual
	}
	issued := run("issue", func() *vmcommon.ContractCallInput {
		input := qualSP225ESDTCall("issue", []byte("OrdinaryToken"), []byte("ORDINARY"), big.NewInt(1000).Bytes(), []byte{2},
			[]byte("canPause"), []byte("true"), []byte("canFreeze"), []byte("true"), []byte("canWipe"), []byte("true"), []byte("canChangeOwner"), []byte("true"))
		input.CallValue = big.NewInt(1000)
		return input
	})
	require.Equal(t, vmcommon.Ok, issued.ReturnCode, issued.ReturnMessage)
	token := ""
	for _, account := range issued.OutputAccounts {
		for _, transfer := range account.OutputTransfers {
			if parts := bytes.Split(transfer.Data, []byte("@")); len(parts) > 1 && string(parts[0]) == core.BuiltInFunctionESDTTransfer {
				decoded := make([]byte, len(parts[1])/2)
				for i := range decoded {
					for _, c := range parts[1][2*i : 2*i+2] {
						decoded[i] <<= 4
						if c >= 'a' {
							decoded[i] |= c - 'a' + 10
						} else {
							decoded[i] |= c - '0'
						}
					}
				}
				token = string(decoded)
			}
		}
	}
	require.NotEmpty(t, token)
	for _, function := range qualSP225PublicMutations {
		for _, shape := range []string{"native_input", "no_gas", "nonzero_value"} {
			run(function+"/"+shape, func() *vmcommon.ContractCallInput {
				input := qualSP225PublicCall(function, token)
				switch shape {
				case "no_gas":
					input.GasProvided = 0
				case "nonzero_value":
					input.CallValue = big.NewInt(1)
				}
				return input
			})
		}
	}
	// A callback addressed to the system contract, as an acknowledgment is.
	run("callBack", func() *vmcommon.ContractCallInput {
		return qualSP225ESDTCall("callBack", []byte{0}, []byte(token), make([]byte, 8))
	})

	nativeRoot, err := native.user.Commit()
	require.NoError(t, err)
	enabledRoot, err := enabled.user.Commit()
	require.NoError(t, err)
	require.Equal(t, nativeRoot, enabledRoot, "identical ordinary state")
}

type qualSP279NoBlock struct{}

func (b *qualSP279NoBlock) IsInterfaceNil() bool { return b == nil }
func (b *qualSP279NoBlock) ExecutingBlock() ([]byte, []byte, uint32, error) {
	return nil, nil, 0, drwa.ErrFinalityImport
}
