package processing

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	vmBuiltins "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	wasmConfig "github.com/multiversx/mx-chain-vm-go/config"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	factoryMock "github.com/multiversx/mx-chain-go/factory/mock"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/drwa"
	processFactory "github.com/multiversx/mx-chain-go/process/factory"
	processMock "github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	nativeValidation "github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
	"github.com/multiversx/mx-chain-go/testscommon"
	dataMock "github.com/multiversx/mx-chain-go/testscommon/dataRetriever"
	"github.com/multiversx/mx-chain-go/testscommon/economicsmocks"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/epochNotifier"
	"github.com/multiversx/mx-chain-go/testscommon/genesisMocks"
	"github.com/multiversx/mx-chain-go/testscommon/integrationtests"
	"github.com/multiversx/mx-chain-go/testscommon/shardingMocks"
	storageMock "github.com/multiversx/mx-chain-go/testscommon/storage"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/systemSmartContracts/defaults"
)

// SP2-25: the classifier as the processing factory installs it. Real account
// stores, the real System VM with its real system contracts, the real hook,
// all created by the production factory methods. The DRWA genesis state is
// provisioned through the exported genesis operation. A regulated token is
// placed in the committed registry records (as an earlier block's registration
// would leave it), because the registration ingress is another row's gate.
// Inert local fixtures only: no network, no node, no transaction.

const (
	qualSP225Regulated = "REGULATED-abcdef"
	qualSP225Ordinary  = "ORDINARY-abcdef"
	qualSP225Denied    = "DRWA public operation denied"
)

// The public ESDT System-SC mutations (P17 system_sc_dispatch rows that are not
// OUT_OF_SCOPE or READ_ONLY).
var qualSP225PublicMutations = []string{"setBurnRoleGlobally", "unsetBurnRoleGlobally", "setSpecialRole", "unSetSpecialRole",
	"transferOwnership", "controlChanges", "transferNFTCreateRole", "stopNFTCreate", "sendAllTransferRoleAddresses",
	"freeze", "unFreeze", "wipe", "pause", "unPause", "freezeSingleNFT", "unFreezeSingleNFT", "wipeSingleNFT",
	"mint", core.BuiltInFunctionESDTBurn, "updateTokenID", "changeSFTToMetaESDT", "changeToDynamic", "changeToMultiShardCreate"}

type qualSP225Node struct {
	pcf        *processComponentsFactory
	user, peer *state.AccountsDB
	factory    process.VirtualMachinesContainerFactory
	system     vmcommon.VMExecutionHandler
	hook       *hooks.BlockChainHookImpl
	owner      *drwa.MetaClassification
}

func qualSP225SystemSCConfig() *config.SystemSmartContractsConfig {
	owner := "3132333435363738393031323334353637383930313233343536373839303234"
	return &config.SystemSmartContractsConfig{
		ESDTSystemSCConfig: config.ESDTSystemSCConfig{BaseIssuingCost: "1000", OwnerAddress: "aaaaaa"},
		GovernanceSystemSCConfig: config.GovernanceSystemSCConfig{
			V1:           config.GovernanceSystemSCConfigV1{ProposalCost: "500"},
			Active:       config.GovernanceSystemSCConfigActive{ProposalCost: "500", MinQuorum: 0.5, MinPassThreshold: 0.5, MinVetoThreshold: 0.5, LostProposalFee: "1"},
			OwnerAddress: owner, MaxVotingDelayPeriodInEpochs: 30,
		},
		StakingSystemSCConfig: config.StakingSystemSCConfig{GenesisNodePrice: "1000", UnJailValue: "100", MinStepValue: "100", MinStakeValue: "1",
			UnBondPeriod: 1, UnBondPeriodSupernova: 2, NumRoundsWithoutBleed: 1, MaximumPercentageToBleed: 1, BleedPercentagePerRound: 1,
			MaxNumberOfNodesForStake: 100, MinUnstakeTokensValue: "1", StakeLimitPercentage: 100.0, NodeLimitPercentage: 100.0},
		DelegationManagerSystemSCConfig: config.DelegationManagerSystemSCConfig{MinCreationDeposit: "100", MinStakeAmount: "100", ConfigChangeAddress: owner},
		DelegationSystemSCConfig:        config.DelegationSystemSCConfig{MinServiceFee: 0, MaxServiceFee: 100},
		SoftAuctionConfig:               config.SoftAuctionConfig{TopUpStep: "10", MinTopUp: "1", MaxTopUp: "32000000", MaxNumberOfIterations: 100000},
	}
}

func qualSP225Flags() *enableEpochsHandlerMock.EnableEpochsHandlerStub {
	return enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.ESDTFlag, common.StakeFlag, common.BuiltInFunctionsFlag,
		common.ESDTMultiTransferFlag, common.ESDTNFTCreateOnMultiShardFlag, common.MetaESDTSetFlag, common.ESDTRegisterAndSetAllRolesFlag)
}

// qualSP225Factory is a processing factory reduced to what the VM factory
// methods read. deployment selects an admitted DRWA deployment.
func qualSP225Factory(t *testing.T, shard uint32, deployment bool, user, peer state.AccountsAdapter) *processComponentsFactory {
	t.Helper()
	gas := wasmConfig.MakeGasMapForTests()
	defaults.FillGasMapInternal(gas, 1)
	pcf := &processComponentsFactory{
		coreData: &factoryMock.CoreComponentsMock{
			Hash: blake2b.NewBlake2b(), IntMarsh: &marshal.GogoProtoMarshalizer{},
			AddrPubKeyConv:      testscommon.NewPubkeyConverterMock(32),
			UInt64ByteSliceConv: &processMock.Uint64ByteSliceConverterMock{},
			EpochChangeNotifier: &epochNotifier.EpochNotifierStub{}, EnableEpochsHandlerField: qualSP225Flags(),
			EnableRoundsHandlerField: &testscommon.EnableRoundsHandlerStub{},
			RoundHandlerField:        &testscommon.RoundHandlerMock{},
			EconomicsHandler:         &economicsmocks.EconomicsHandlerMock{GenesisTotalSupplyCalled: func() *big.Int { return big.NewInt(2000000000000) }},
			NodesConfig:              &genesisMocks.NodesSetupStub{}, RatingHandler: &testscommon.RaterMock{},
		},
		data: &factoryMock.DataComponentsMock{
			Storage: &storageMock.ChainStorerStub{}, Blkc: &testscommon.ChainHandlerStub{}, DataPool: &dataMock.PoolsHolderStub{},
		},
		bootstrapComponents: &qualG25Bootstrap{coordinator: &testscommon.ShardsCoordinatorMock{CurrentShard: shard, NoShards: 3}},
		crypto:              &factoryMock.CryptoComponentsMock{MsgSigVerifier: &processMock.MessageSignVerifierMock{}},
		nodesCoordinator:    &shardingMocks.NodesCoordinatorMock{GetNumTotalEligibleCalled: func() uint64 { return 1000 }},
		systemSCConfig:      qualSP225SystemSCConfig(),
		gasSchedule:         testscommon.NewGasScheduleNotifierMock(gas),
		config:              testscommon.GetGeneralConfig(),
		flagsConfig:         config.ContextFlagsConfig{WorkingDir: t.TempDir()},
		state: &factoryMock.StateComponentsHolderStub{
			AccountsAdapterCalled: func() state.AccountsAdapter { return user },
			PeerAccountsCalled:    func() state.AccountsAdapter { return peer },
		},
	}
	pcf.config.SmartContractsStorage = config.StorageConfig{
		Cache: config.CacheConfig{Capacity: 10, Type: string(storageunit.LRUCache)},
		DB:    config.DBConfig{FilePath: "compiled", Type: string(storageunit.MemoryDB), MaxBatchSize: 1, MaxOpenFiles: 10},
	}
	pcf.config.VirtualMachine.Execution.TransferAndExecuteByUserAddresses = []string{"0101010101010101010101010101010101010101010101010101010101010101"}
	if deployment {
		pcf.drwaConfigurationCandidate, _, _ = qualS1OverlayCandidate(t, 12)
		pcf.drwaInitialProgrammeStartup = &config.DRWAInitialProgrammeStartup{}
	}
	return pcf
}

// qualSP225GenesisStore provisions the DRWA genesis state through the exported
// genesis operation and, optionally, one committed registry member.
func qualSP225GenesisStore(t *testing.T, regulated ...string) *state.AccountsDB {
	t.Helper()
	db := integrationtests.CreateInMemoryShardAccountsDB()
	limits := qualStageALimits()
	marshaller, hasher := &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b()
	evidence, err := drwa.DecodeInitialProgrammeEvidence(qualStageARaw(t), "synthetic", "pin", limits, marshaller, hasher)
	require.NoError(t, err)
	minimum := &config.DRWAMinimumGenesis{ProfileDigest: [32]byte{1}, ReleaseDigest: [32]byte{2}, MaxEverTokens: 8, RegistryProofBytes: 1 << 20}
	stage, err := drwa.PrepareInitialProgrammeGenesis(db, []drwa.InitialProgrammeEvidence{evidence}, limits, minimum, marshaller, hasher, 0)
	require.NoError(t, err)
	require.NoError(t, stage())
	if len(regulated) != 0 {
		account, loadErr := db.LoadAccount(core.SystemAccountAddress)
		require.NoError(t, loadErr)
		system := account.(state.UserAccountHandler)
		count := make([]byte, 8)
		binary.BigEndian.PutUint64(count, uint64(len(regulated)))
		require.NoError(t, system.SaveKeyValue([]byte(core.ProtectedKeyPrefix+"DRWA@registry@count"), count))
		for ordinal, token := range regulated {
			entry := make([]byte, 8)
			binary.BigEndian.PutUint64(entry, uint64(ordinal))
			require.NoError(t, system.SaveKeyValue(append([]byte(core.ProtectedKeyPrefix+"DRWA@registry@entry@"), entry...), []byte(token)))
			require.NoError(t, system.SaveKeyValue([]byte(core.ProtectedKeyPrefix+"DRWA@registry@member@"+token), []byte{1}))
		}
		require.NoError(t, db.SaveAccount(system))
	}
	_, err = db.Commit()
	require.NoError(t, err)
	return db
}

func qualSP225MetaNode(t *testing.T, deployment bool, user *state.AccountsDB) *qualSP225Node {
	t.Helper()
	peer := integrationtests.CreateInMemoryShardAccountsDB()
	pcf := qualSP225Factory(t, core.MetachainShardId, deployment, user, peer)
	if deployment {
		pcf.drwaNativeValidationSource = &nativeValidation.NativeValidationSource{
			ProtoMarshalizer: &marshal.GogoProtoMarshalizer{}, Hasher: blake2b.NewBlake2b(), ArgsParser: smartContract.NewArgumentParser(),
			EnableEpochsHandler: qualSP225Flags(), ChainID: "inert-chain",
		}
	}
	enabledAt, err := pcf.drwaHeaderTimeEnabledAt()
	require.NoError(t, err)
	factory, container, owner, err := pcf.createProcessingVMMeta(vmBuiltins.NewBuiltInFunctionContainer(),
		&testscommon.SimpleNFTStorageHandlerStub{}, &testscommon.ESDTGlobalSettingsHandlerStub{}, &testscommon.EpochStartTriggerStub{}, enabledAt)
	require.NoError(t, err)
	hook := factory.BlockChainHookImpl().(*hooks.BlockChainHookImpl)
	t.Cleanup(func() { _ = hook.Close() })
	system, err := container.Get(processFactory.SystemVirtualMachine)
	require.NoError(t, err)
	require.NoError(t, hook.SetCurrentHeader(&block.MetaBlock{Epoch: 12, Round: 440, Nonce: 5}))
	return &qualSP225Node{pcf: pcf, user: user, peer: peer, factory: factory, system: system, hook: hook, owner: owner}
}

func qualSP225ESDTCall(function string, arguments ...[]byte) *vmcommon.ContractCallInput {
	return &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Repeat([]byte{1}, 32), CallValue: big.NewInt(0),
		GasProvided: 100000000, Arguments: arguments}, RecipientAddr: bytes.Clone(core.ESDTSCAddress), Function: function}
}

func qualSP225PublicCall(function, token string) *vmcommon.ContractCallInput {
	input := qualSP225ESDTCall(function, []byte(token), bytes.Repeat([]byte{2}, 32), []byte(core.ESDTRoleNFTCreate))
	switch function {
	case "setBurnRoleGlobally", "unsetBurnRoleGlobally", "pause", "unPause", "sendAllTransferRoleAddresses", "stopNFTCreate",
		"updateTokenID", "changeToDynamic", "changeToMultiShardCreate":
		input.Arguments = input.Arguments[:1]
	case "transferOwnership", "freeze", "unFreeze", "wipe":
		input.Arguments = input.Arguments[:2]
	case "controlChanges":
		input.Arguments = [][]byte{[]byte(token), []byte("canPause"), []byte("true")}
	case "changeSFTToMetaESDT":
		input.Arguments = [][]byte{[]byte(token), {}}
	}
	return input
}

func (n *qualSP225Node) requireUntouched(t *testing.T) {
	t.Helper()
	require.Zero(t, n.user.JournalLen())
	require.Zero(t, n.peer.JournalLen())
}

func TestQualSP225InstalledMetaDeniesEveryPublicESDTMutation(t *testing.T) {
	node := qualSP225MetaNode(t, true, qualSP225GenesisStore(t, qualSP225Regulated))
	require.NotNil(t, node.owner)
	require.True(t, node.system.(vm.DRWANativeCallExecutor).DRWANativeCallConfigured())

	// Before the first execution nothing is ordinary.
	output, err := node.system.RunSmartContractCall(qualSP225PublicCall("pause", qualSP225Ordinary))
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.Nil(t, output)

	node = qualSP225MetaNode(t, true, qualSP225GenesisStore(t, qualSP225Regulated))
	require.NoError(t, node.owner.BeginExecution())
	for _, function := range qualSP225PublicMutations {
		t.Run(function, func(t *testing.T) {
			output, err := node.system.RunSmartContractCall(qualSP225PublicCall(function, qualSP225Regulated))
			require.NoError(t, err)
			require.Equal(t, vmcommon.UserError, output.ReturnCode)
			require.Equal(t, qualSP225Denied, output.ReturnMessage)
			node.requireUntouched(t)

			output, err = node.system.RunSmartContractCall(qualSP225PublicCall(function, qualSP225Ordinary))
			require.NoError(t, err)
			require.NotEqual(t, qualSP225Denied, output.ReturnMessage)
		})
	}
	status := node.system.(interface{ DRWAExecutionError() error })
	require.NoError(t, status.DRWAExecutionError())
}

// INV-0, carry T40/EXISTING-45: on identical DRWA-extended pre-state, every
// System-SC call on an ordinary token gives the same complete VM output (return
// code, message, data, gas, refund, output accounts, logs) and the same
// committed root on the DRWA node and on the node built without DRWA.
func TestQualSP225InstalledMetaOrdinaryEquivalence(t *testing.T) {
	enabled := qualSP225MetaNode(t, true, qualSP225GenesisStore(t, qualSP225Regulated))
	native := qualSP225MetaNode(t, false, qualSP225GenesisStore(t, qualSP225Regulated))
	require.Nil(t, native.owner)
	require.False(t, native.system.(vm.DRWANativeCallExecutor).DRWANativeCallConfigured(), "without DRWA the factory is the native one")
	require.NoError(t, enabled.owner.BeginExecution())

	run := func(input func() *vmcommon.ContractCallInput) *vmcommon.VMOutput {
		t.Helper()
		expected, nativeErr := native.system.RunSmartContractCall(input())
		actual, enabledErr := enabled.system.RunSmartContractCall(input())
		require.Equal(t, nativeErr, enabledErr)
		require.Equal(t, expected, actual)
		return actual
	}

	issue := func() *vmcommon.ContractCallInput {
		input := qualSP225ESDTCall("issue", []byte("OrdinaryToken"), []byte("ORDINARY"), big.NewInt(1000).Bytes(), []byte{2},
			[]byte("canPause"), []byte("true"), []byte("canFreeze"), []byte("true"), []byte("canWipe"), []byte("true"), []byte("canChangeOwner"), []byte("true"))
		input.CallValue = big.NewInt(1000)
		return input
	}
	issued := run(issue)
	t.Logf("native issue: code %s message %q", issued.ReturnCode, issued.ReturnMessage)
	token := qualSP225Ordinary
	for _, account := range issued.OutputAccounts {
		for _, transfer := range account.OutputTransfers {
			if parts := bytes.Split(transfer.Data, []byte("@")); len(parts) > 1 && string(parts[0]) == core.BuiltInFunctionESDTTransfer {
				decoded := make([]byte, len(parts[1])/2)
				for i := range decoded {
					var value byte
					for _, c := range parts[1][2*i : 2*i+2] {
						value <<= 4
						switch {
						case c >= '0' && c <= '9':
							value |= c - '0'
						case c >= 'a' && c <= 'f':
							value |= c - 'a' + 10
						}
					}
					decoded[i] = value
				}
				token = string(decoded)
			}
		}
	}
	t.Logf("ordinary token used for the matrix: %s", token)

	for _, function := range qualSP225PublicMutations {
		for _, shape := range []string{"native_input", "no_arguments", "nonzero_value", "no_gas"} {
			run(func() *vmcommon.ContractCallInput {
				input := qualSP225PublicCall(function, token)
				switch shape {
				case "no_arguments":
					input.Arguments = nil
				case "nonzero_value":
					input.CallValue = big.NewInt(1)
				case "no_gas":
					input.GasProvided = 0
				}
				return input
			})
		}
	}
	run(func() *vmcommon.ContractCallInput { return qualSP225ESDTCall("getTokenProperties", []byte(token)) })
	run(func() *vmcommon.ContractCallInput { return qualSP225ESDTCall("unknownEndpoint", []byte(token)) })

	nativeRoot, err := native.user.Commit()
	require.NoError(t, err)
	enabledRoot, err := enabled.user.Commit()
	require.NoError(t, err)
	_, err = enabled.peer.Commit()
	require.NoError(t, err)
	require.Equal(t, nativeRoot, enabledRoot, "identical ordinary state delta")
	require.NoError(t, enabled.owner.Committed())
	require.NoError(t, enabled.owner.BeginExecution())
	run(func() *vmcommon.ContractCallInput { return qualSP225PublicCall("pause", token) })
}

func TestQualSP225InstalledMetaFailsClosedWithoutGenesisState(t *testing.T) {
	node := qualSP225MetaNode(t, true, integrationtests.CreateInMemoryShardAccountsDB())
	require.ErrorIs(t, node.owner.BeginExecution(), vm.ErrDRWAExecution)
	output, err := node.system.RunSmartContractCall(qualSP225PublicCall("pause", qualSP225Ordinary))
	require.ErrorIs(t, err, vm.ErrDRWAExecution, "an unprovisioned registry never makes a token ordinary")
	require.Nil(t, output)
}

// The reserved registration requests are refused deterministically on the
// installed owner; they do not fail the block.
func TestQualSP225InstalledMetaRefusesReservedRegistrationRequests(t *testing.T) {
	node := qualSP225MetaNode(t, true, qualSP225GenesisStore(t))
	require.NoError(t, node.owner.BeginExecution())
	executor := node.system.(vm.DRWANativeCallExecutor)
	for _, function := range []string{"DRWARegisterToken", "DRWARegisterBootstrapIntent"} {
		t.Run(function, func(t *testing.T) {
			tx := &transaction.Transaction{SndAddr: bytes.Repeat([]byte{1}, 32), RcvAddr: bytes.Clone(core.ESDTSCAddress),
				Value: big.NewInt(0), Data: []byte(function + "@01"), ChainID: []byte("inert-chain")}
			called := false
			code, err := executor.WithDRWANativeCall(tx, nil, node.user, func(vm.DRWANativeCallHandoff) (vmcommon.ReturnCode, error) {
				called = true
				return vmcommon.Ok, nil
			})
			require.ErrorIs(t, err, process.ErrTransactionNotExecutable)
			require.NotErrorIs(t, err, vm.ErrDRWAExecution)
			require.Equal(t, vmcommon.UserError, code)
			require.False(t, called)
			node.requireUntouched(t)
		})
	}
	require.NoError(t, node.system.(interface{ DRWAExecutionError() error }).DRWAExecutionError())
}

// The VMs that never commit (transaction simulator, API query) classify from
// the committed projection and cannot mutate or skip classification.
func TestQualSP225InstalledMetaReadOnlyVMs(t *testing.T) {
	node := qualSP225MetaNode(t, true, qualSP225GenesisStore(t, qualSP225Regulated))
	queryUser, queryPeer := qualSP225GenesisStore(t, qualSP225Regulated), integrationtests.CreateInMemoryShardAccountsDB()
	build := func() vmcommon.VMExecutionHandler {
		classifier, tokens := node.pcf.drwaReadOnlyClassifier(queryUser, queryPeer)
		require.NotNil(t, classifier)
		factory, err := node.pcf.createVMFactoryMetaWithClassifier(queryUser, queryPeer, vmBuiltins.NewBuiltInFunctionContainer(),
			node.pcf.config.SmartContractsStorage, &testscommon.SimpleNFTStorageHandlerStub{}, &testscommon.ESDTGlobalSettingsHandlerStub{},
			&testscommon.EpochStartTriggerStub{}, nil, classifier, tokens)
		require.NoError(t, err)
		t.Cleanup(func() { _ = factory.BlockChainHookImpl().Close() })
		container, err := factory.Create()
		require.NoError(t, err)
		system, err := container.Get(processFactory.SystemVirtualMachine)
		require.NoError(t, err)
		return system
	}

	early := build()
	output, err := early.RunSmartContractCall(qualSP225PublicCall("pause", qualSP225Ordinary))
	require.ErrorIs(t, err, vm.ErrDRWAExecution, "before the first reconstruction a simulation is refused, not ordinary")
	require.Nil(t, output)

	require.NoError(t, node.owner.BeginExecution())
	system := build()
	for token, denied := range map[string]bool{qualSP225Regulated: true, qualSP225Ordinary: false} {
		output, err = system.RunSmartContractCall(qualSP225PublicCall("pause", token))
		require.NoError(t, err)
		require.Equal(t, denied, output.ReturnMessage == qualSP225Denied, token)
	}
	require.Zero(t, queryUser.JournalLen())
	_, hasHandoff := system.(interface {
		ReplaceDRWAClassifier(vm.DRWATokenClassifier) error
	})
	require.True(t, hasHandoff)
	require.ErrorIs(t, system.(interface {
		ReplaceDRWAClassifier(vm.DRWATokenClassifier) error
	}).ReplaceDRWAClassifier(node.owner.Classifier()), vm.ErrDRWAExecution, "a read-only classifier admits no handoff")

	// The API factory receives the same kind of classifier through the process
	// components, with the admission for built-in calls.
	managed := &managedProcessComponents{processComponents: &processComponents{
		drwaMetaClassification: node.owner, drwaConfigurationCandidate: node.pcf.drwaConfigurationCandidate}}
	classifier, admission, enforcedAt := managed.DRWAQueryClassification(queryUser, queryPeer)
	require.NotNil(t, classifier)
	require.NotNil(t, admission)
	require.True(t, enforcedAt(12, 440))
	require.False(t, enforcedAt(11, 440))
	require.NoError(t, classifier.ValidateAccounts(queryUser, queryPeer))

	for name, components := range map[string]*managedProcessComponents{
		"no_components": {}, "no_drwa": {processComponents: &processComponents{}},
	} {
		classifier, admission, enforcedAt = components.DRWAQueryClassification(queryUser, queryPeer)
		require.Nil(t, classifier, name)
		require.Nil(t, admission, name)
		require.Nil(t, enforcedAt, name)
	}
}
