package drwa

import (
	"bytes"
	"fmt"
	"math/big"
	"path/filepath"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/versioning"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	nativeTx "github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/forking"
	"github.com/multiversx/mx-chain-go/process/block/postprocess"
	"github.com/multiversx/mx-chain-go/process/guardian"
	"github.com/multiversx/mx-chain-go/process/interceptors"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	nativeValidation "github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	storageFactory "github.com/multiversx/mx-chain-go/storage/factory"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/integrationtests"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/systemSmartContracts"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// qualSP224NativeCallConsumer is the one time consumer a production path
// constructs today: the registration candidate's native-call handoff on the
// metachain (WithDRWANativeCall and the lease it issues). The setup is the one
// of TestQualNativeCandidateOriginalTransactionConnection, scenario "ordinary":
// real signature, receipt, hook, System VM and candidate; the transaction is an
// ordinary ownership transfer of an unregulated token.
func qualSP224NativeCallConsumer(t *testing.T) *qualSP224Consumer {
	t.Helper()
	cfg, err := common.LoadMainConfig(filepath.Join("..", "..", "cmd", "node", "config", "config.toml"))
	require.NoError(t, err)
	ec := qualCandidateEpochs(t, qualDRWACandidateFixtures["enableEpochs.toml"].body)
	flags := qualCandidateFlags(t, ec, ec.EnableEpochs.SupernovaEnableEpoch)
	key, pub := qualNativeAccountKeyGen.GeneratePair()
	sender, err := pub.ToByteArray()
	require.NoError(t, err)
	token, successor := []byte("AAA-abcdef"), bytes.Repeat([]byte{2}, 32)
	f := qualRegistryTransportWithSetup(t, false, make([]byte, 8), []byte{1}, false, func(accounts state.AccountsAdapter) {
		a, e := accounts.LoadAccount(core.ESDTSCAddress)
		require.NoError(t, e)
		body, e := (&marshal.GogoProtoMarshalizer{}).Marshal(&systemSmartContracts.ESDTDataV2{OwnerAddress: bytes.Clone(sender), TokenName: []byte("TokenName"), TickerName: []byte("AAA"), TokenType: []byte(core.FungibleESDT), CanChangeOwner: true})
		require.NoError(t, e)
		require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue(token, body))
		require.NoError(t, accounts.SaveAccount(a))
	})
	transport, err := newRegistryTransport(f.reader, 2, f.limit)
	require.NoError(t, err)
	projection, err := transport.reconstruct(f.anchor, f.count, f.members)
	require.NoError(t, err)
	store := &qualRegistrationCandidateStore{qualNativeStore: &qualNativeStore{AccountsAdapter: f.source}}
	coordinator, err := sharding.NewMultiShardCoordinator(3, core.MetachainShardId)
	require.NoError(t, err)
	candidate, err := reconstructRegistrationCandidate(store, coordinator, 2, projection)
	require.NoError(t, err)
	notifier := forking.NewGenericEpochNotifier()
	guarded, err := guardian.NewGuardedAccount(&marshal.GogoProtoMarshalizer{}, notifier, qualNativeGuardianDelay)
	require.NoError(t, err)
	locker := &sync.RWMutex{}
	_, hook, pool := qualNativeCreateVMAndBlockchainHookAndDataPool(store, qualNativeCreateMockGasScheduleNotifier(), qualNativeCreateDefaultVMConfig(), coordinator, locker, notifier, flags, &testscommon.ChainHandlerStub{}, guarded, true)
	t.Cleanup(func() { require.NoError(t, hook.Close()); require.NoError(t, pool.Close()) })
	epoch := ec.EnableEpochs.SupernovaEnableEpoch
	headerAt := func(time uint64) data.HeaderHandler {
		return &block.MetaBlockV3{Epoch: epoch, Round: 30, Nonce: 20, TimestampMs: time, ChainID: []byte(cfg.GeneralSettings.ChainID)}
	}
	require.NoError(t, hook.SetEpochStartHeader(headerAt(1000)))
	notifier.CheckEpoch(headerAt(1000))
	physical := qualSystemSCNativeObserved(t, store, candidate, hook, func(context vm.ContextHandler) vm.ContextHandler { return context })
	container := &mock.VMContainerMock{GetCalled: func([]byte) (vmcommon.VMExecutionHandler, error) { return physical.runtime, nil }}
	execution, err := qualNativeCreateTxProcessorWithOneSCExecutorWithVMs(store, container, hook, postprocess.NewFeeAccumulator(), coordinator, ec.EnableEpochs, testscommon.GetDefaultRoundsConfig(), locker, pool, notifier, guarded, forking.NewGenericRoundNotifier(), &testscommon.ChainHandlerStub{}, 0.5, true)
	require.NoError(t, err)
	proto := &marshal.GogoProtoMarshalizer{}
	hasher := integrationtests.TestHasher
	cache, err := storageunit.NewCache(storageFactory.GetCacherFromConfig(cfg.WhiteListerVerifiedTxs))
	require.NoError(t, err)
	t.Cleanup(func() { cache.Clear(); require.NoError(t, cache.Close()) })
	whitelist, err := interceptors.NewWhiteListDataVerifier(cache, 0)
	require.NoError(t, err)
	parser := smartContract.NewArgumentParser()
	version := versioning.NewTxVersionChecker(core.InitialVersionOfTransaction)
	tx := &nativeTx.Transaction{Value: big.NewInt(0), SndAddr: sender, RcvAddr: bytes.Clone(core.ESDTSCAddress), GasPrice: execution.EconomicsHandler.MinGasPrice(), GasLimit: 1000000, Data: []byte(fmt.Sprintf("transferOwnership@%x@%x", token, successor)), ChainID: []byte(cfg.GeneralSettings.ChainID), Version: core.InitialVersionOfTransaction}
	require.NoError(t, execution.EconomicsHandler.CheckValidityTxValues(tx))
	message, err := tx.GetDataForSigning(qualNativeHexConverter, qualNativeTxSignMarshalizer, qualNativeTxSignHasher)
	require.NoError(t, err)
	tx.Signature, err = qualNativeSingleSigner.Sign(key, message)
	require.NoError(t, err)
	encoded, err := proto.Marshal(tx)
	require.NoError(t, err)
	intercepted, err := nativeValidation.NewInterceptedTransaction(encoded, proto, qualNativeTxSignMarshalizer, hasher, qualNativeAccountKeyGen, qualNativeSingleSigner, qualNativeHexConverter, coordinator, execution.EconomicsHandler, whitelist, parser, tx.ChainID, flags.IsFlagEnabled(common.TransactionSignedWithTxHashFlag), qualNativeTxSignHasher, version, flags)
	require.NoError(t, err)
	require.NoError(t, intercepted.CheckValidity())
	receipt := intercepted.NativeValidationReceipt()
	require.NotNil(t, receipt)
	actual := intercepted.Transaction().(*nativeTx.Transaction)
	candidate.native = &registrationNativeExecution{source: nativeValidation.NativeValidationSource{ProtoMarshalizer: proto, SignMarshalizer: qualNativeTxSignMarshalizer, Hasher: hasher, TxSignHasher: qualNativeTxSignHasher, KeyGen: qualNativeAccountKeyGen, Signer: qualNativeSingleSigner, Converter: qualNativeHexConverter, VersionChecker: version, Coordinator: coordinator, FeeHandler: execution.EconomicsHandler, VerifiedTransactions: whitelist, ArgsParser: parser, EnableEpochsHandler: flags, EnableSignedTxWithHash: flags.IsFlagEnabled(common.TransactionSignedWithTxHashFlag), ChainID: string(tx.ChainID)}, headers: hook, physical: physical.runtime}
	destination, err := store.GetExistingAccount(core.ESDTSCAddress)
	require.NoError(t, err)
	return &qualSP224Consumer{hook: hook, shard: core.MetachainShardId, store: store, at: 1000, ownLookup: true, header: headerAt,
		identity: func(header data.HeaderHandler) ([]byte, error) {
			return core.CalculateHash(integrationtests.TestMarshalizer, integrationtests.TestHasher, header)
		},
		run: func(*HeaderTimeContext) error {
			entered := false
			code, callErr := candidate.WithDRWANativeCall(actual, receipt, store, physical.runtime, func(lease vm.DRWANativeCallLease) (vmcommon.ReturnCode, error) {
				entered = true
				// The lease re-reads the block's context at every use.
				if e := lease.VerifyTransaction(actual, store, nil, destination.(state.UserAccountHandler)); e != nil {
					return vmcommon.ExecutionFailed, e
				}
				return vmcommon.Ok, nil
			})
			if callErr != nil {
				require.False(t, entered, "a refused native call never reaches the System VM")
				return callErr
			}
			require.True(t, entered)
			require.Equal(t, vmcommon.Ok, code)
			return nil
		}}
}

func TestQualSP224NativeCallRefusesEveryOtherContext(t *testing.T) {
	qualSP224Refusals(t, qualSP224NativeCallConsumer)
}

// The lease a native call holds is bound to the block's context for its whole
// life: when the header is replaced while the call runs, the next lease use is
// refused and the call fails.
func TestQualSP224NativeCallLeaseFollowsTheBlockContext(t *testing.T) {
	c := qualSP224NativeCallConsumer(t)
	_, _, err := qualSP224Begin(t, c.hook, c.headerAt(c.at))
	require.NoError(t, err)
	root, journal := qualSP224State(t, c.store)
	// The consumer's run verifies the transaction through the lease; replace
	// the header from inside the same native call, before that use.
	replaced := false
	inner := c.run
	c.run = func(context *HeaderTimeContext) error {
		if !replaced {
			replaced = true
			require.NoError(t, c.hook.SetCurrentHeader(c.headerAt(c.at+1)))
		}
		return inner(context)
	}
	require.Error(t, c.run(nil))
	after, afterJournal := qualSP224State(t, c.store)
	require.Equal(t, root, after)
	require.Equal(t, journal, afterJournal)
}
