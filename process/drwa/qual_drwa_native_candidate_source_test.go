package drwa

import (
	"bytes"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/versioning"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	nativeTx "github.com/multiversx/mx-chain-core-go/data/transaction"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/forking"
	"github.com/multiversx/mx-chain-go/p2p"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/block/postprocess"
	"github.com/multiversx/mx-chain-go/process/guardian"
	"github.com/multiversx/mx-chain-go/process/interceptors"
	"github.com/multiversx/mx-chain-go/process/interceptors/processor"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	nativeValidation "github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	storageFactory "github.com/multiversx/mx-chain-go/storage/factory"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
	"github.com/multiversx/mx-chain-go/testscommon"
	cacheFixture "github.com/multiversx/mx-chain-go/testscommon/cache"
	"github.com/multiversx/mx-chain-go/testscommon/integrationtests"
	"github.com/multiversx/mx-chain-go/txcache"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/multiversx/mx-chain-go/vm/systemSmartContracts"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Only the native original-transaction handoff is exercised. Native signatures,
// header capability, accounts and SC/SystemVM are real. Fixture projection,
// activation, balances and capacities supply no canonical B/G6, appointment,
// funding, production ingress or F1/F4 certificate admission.
func TestQualNativeCandidateOriginalTransactionConnection(t *testing.T) {
	cfg, err := common.LoadMainConfig(filepath.Join("..", "..", "cmd", "node", "config", "config.toml"))
	require.NoError(t, err)
	ec := qualCandidateEpochs(t, qualDRWACandidateFixtures["enableEpochs.toml"].body)
	flags := qualCandidateFlags(t, ec, ec.EnableEpochs.SupernovaEnableEpoch)
	key, pub := qualNativeAccountKeyGen.GeneratePair()
	sender, err := pub.ToByteArray()
	require.NoError(t, err)
	type ordinaryOutcome struct {
		Code                vmcommon.ReturnCode
		Root, Token         []byte
		Trace               []string
		Prepared            *vmcommon.ContractCallInput
		Output              *vmcommon.VMOutput
		Fees, DeveloperFees *big.Int
	}
	ordinaryBaselines := make(map[bool]ordinaryOutcome)
	for _, scenario := range []string{"bootstrap_denied", "bootstrap_denied_v1", "registration_denied", "registration_denied_v1", "pool_baseline", "pool_off", "pool_on", "pool_baseline_v1", "pool_off_v1", "pool_on_v1", "ordinary", "regulated", "ordinary_v1", "regulated_v1", "gas", "caller", "arguments", "callback", "foreign_vm", "missing_receipt", "changed_original", "foreign_store", "ended_header", "source_removed", "wrong_provider", "relayed", "bind_DRWARegisterToken", "bind_DRWARegisterBootstrapIntent", "bind_control"} {
		t.Run(scenario, func(t *testing.T) {
			regulated := scenario == "regulated" || scenario == "regulated_v1"
			count := make([]byte, 8)
			if regulated {
				count[7] = 2
			}
			token := []byte("AAA-abcdef")
			successor := bytes.Repeat([]byte{2}, 32)
			f := qualRegistryTransportWithSetup(t, false, count, []byte{1}, false, func(accounts state.AccountsAdapter) {
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
			header := &block.MetaBlockV3{Epoch: ec.EnableEpochs.SupernovaEnableEpoch, TimestampMs: 1000, ChainID: []byte(cfg.GeneralSettings.ChainID)}
			require.NoError(t, hook.SetEpochStartHeader(header))
			install, end, err := hook.BeginDRWAHeaderEvaluation()
			require.NoError(t, err)
			defer end()
			require.NoError(t, install(header))
			trace := []string{}
			var prepared *vmcommon.ContractCallInput
			var output *vmcommon.VMOutput
			var classifier vm.DRWATokenClassifier = candidate
			if strings.HasPrefix(scenario, "pool_baseline") {
				classifier = nil
			}
			physical := qualSystemSCNativeObserved(t, store, classifier, hook, func(context vm.ContextHandler) vm.ContextHandler {
				return &qualNativePreludeObserver{ContextHandler: context, trace: &trace, input: &prepared, output: &output}
			})
			container := &mock.VMContainerMock{GetCalled: func([]byte) (vmcommon.VMExecutionHandler, error) { return physical.runtime, nil }}
			nativeEpochs := ec.EnableEpochs
			if strings.HasSuffix(scenario, "_v1") {
				// Labelled synthetic selection of the actual V1 processor, while
				// retaining the evaluated post-Supernova native header capability.
				nativeEpochs.SCProcessorV2EnableEpoch = header.Epoch + 1
			}
			fees := postprocess.NewFeeAccumulator()
			execution, err := qualNativeCreateTxProcessorWithOneSCExecutorWithVMs(store, container, hook, fees, coordinator, nativeEpochs, testscommon.GetDefaultRoundsConfig(), locker, pool, notifier, guarded, forking.NewGenericRoundNotifier(), &testscommon.ChainHandlerStub{}, 0.5, true)
			require.NoError(t, err)
			proto := &marshal.GogoProtoMarshalizer{}
			hasher := integrationtests.TestHasher // exact same native fixture factory as SC preparation
			cache, err := storageunit.NewCache(storageFactory.GetCacherFromConfig(cfg.WhiteListerVerifiedTxs))
			require.NoError(t, err)
			t.Cleanup(func() { cache.Clear(); require.NoError(t, cache.Close()) })
			whitelist, err := interceptors.NewWhiteListDataVerifier(cache, 0)
			require.NoError(t, err)
			parser := smartContract.NewArgumentParser()
			version := versioning.NewTxVersionChecker(core.InitialVersionOfTransaction)
			tx := &nativeTx.Transaction{Value: big.NewInt(0), SndAddr: sender, RcvAddr: bytes.Clone(core.ESDTSCAddress), GasPrice: execution.EconomicsHandler.MinGasPrice(), GasLimit: 1000000, Data: []byte(fmt.Sprintf("transferOwnership@%x@%x", token, successor)), ChainID: []byte(cfg.GeneralSettings.ChainID), Version: core.InitialVersionOfTransaction}
			bootstrapDenied := strings.HasPrefix(scenario, "bootstrap_denied")
			registrationDenied := strings.HasPrefix(scenario, "registration_denied")
			if bootstrapDenied {
				tx.Data = []byte("DRWARegisterBootstrapIntent@01@02")
			}
			if registrationDenied {
				tx.Data = []byte("DRWARegisterToken@01@02")
			}
			// SP2-23, TA-SP2-23-1-2: a relayed original, and a reserved name
			// under an authentic receipt at a contract other than the ESDT one.
			relayed, bind := scenario == "relayed", strings.HasPrefix(scenario, "bind_")
			relayerKey := key
			if relayed {
				for {
					candidateKey, candidatePub := qualNativeAccountKeyGen.GeneratePair()
					address, e := candidatePub.ToByteArray()
					require.NoError(t, e)
					if coordinator.SameShard(address, sender) {
						relayerKey, tx.RelayerAddr = candidateKey, address
						break
					}
				}
			}
			if bind {
				tx.RcvAddr = bytes.Clone(vm.GovernanceSCAddress)
				tx.Data = []byte(strings.TrimPrefix(scenario, "bind_") + "@01@02")
				require.False(t, nativeValidation.RequiresDRWANativeValidationReceipt(tx))
			}
			require.NoError(t, execution.EconomicsHandler.CheckValidityTxValues(tx))
			message, err := tx.GetDataForSigning(qualNativeHexConverter, qualNativeTxSignMarshalizer, qualNativeTxSignHasher)
			require.NoError(t, err)
			tx.Signature, err = qualNativeSingleSigner.Sign(key, message)
			require.NoError(t, err)
			if relayed {
				tx.RelayerSignature, err = qualNativeSingleSigner.Sign(relayerKey, message)
				require.NoError(t, err)
			}
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
			native, ok := execution.NativeSC.(interface {
				ExecuteSmartContractTransactionWithDRWA(data.TransactionHandler, state.UserAccountHandler, state.UserAccountHandler, any) (vmcommon.ReturnCode, error)
			})
			require.True(t, ok)
			notifier.CheckEpoch(header)
			if bootstrapDenied || registrationDenied {
				before, e := store.RootHash()
				require.NoError(t, e)
				journal, outputs := store.JournalLen(), len(candidate.writer.boundary.outputs)
				code, e := native.ExecuteSmartContractTransactionWithDRWA(actual, nil, destination.(state.UserAccountHandler), receipt)
				require.ErrorIs(t, e, process.ErrTransactionNotExecutable, "generic proof mechanics confer no production role/provider admission")
				require.NotErrorIs(t, e, vm.ErrDRWAExecution)
				require.Equal(t, vmcommon.UserError, code)
				after, e := store.RootHash()
				require.NoError(t, e)
				require.Equal(t, before, after)
				require.Equal(t, journal, store.JournalLen())
				require.Len(t, candidate.writer.boundary.outputs, outputs)
				require.Empty(t, candidate.view.added)
				require.Empty(t, trace, "neither reserved registration route can reach the prelude without its provider")
				return
			}
			if relayed {
				require.True(t, common.IsRelayedTxV3(actual))
				verifying := candidate.native.source
				verifying.EnableSignedTxWithHash = flags.IsFlagEnabled(common.TransactionSignedWithTxHashFlag)
				require.NoError(t, nativeValidation.VerifyNativeValidationReceipt(verifying, receipt, actual, intercepted.Hash()),
					"the receipt itself is authentic: the refusal below is the relay rule")
				entered := false
				code, e := candidate.WithDRWANativeCall(actual, receipt, store, physical.runtime, func(vm.DRWANativeCallLease) (vmcommon.ReturnCode, error) {
					entered = true
					return vmcommon.Ok, nil
				})
				require.ErrorIs(t, e, vm.ErrDRWAExecution)
				require.Equal(t, vmcommon.ExecutionFailed, code)
				require.False(t, entered, "a relayed original opens no native operation")
				require.Empty(t, trace)
				return
			}
			if bind {
				target, e := store.LoadAccount(actual.RcvAddr)
				require.NoError(t, e)
				function, arguments, e := parser.ParseCallData(string(actual.Data))
				require.NoError(t, e)
				entered := false
				var bound error
				_, e = candidate.WithDRWANativeCall(actual, receipt, store, physical.runtime, func(lease vm.DRWANativeCallLease) (vmcommon.ReturnCode, error) {
					entered = true
					require.NoError(t, lease.VerifyTransaction(actual, store, nil, target.(state.UserAccountHandler)))
					input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(actual.SndAddr), CallValue: big.NewInt(0),
						CallType: vmData.DirectCall, GasPrice: actual.GasPrice, GasProvided: 1, Arguments: arguments,
						CurrentTxHash: intercepted.Hash(), OriginalTxHash: intercepted.Hash(), PrevTxHash: intercepted.Hash()},
						RecipientAddr: bytes.Clone(actual.RcvAddr), Function: function}
					bound = lease.(vm.DRWANativePreparedCallLease).BindCall(input)
					if bound != nil {
						return vmcommon.ExecutionFailed, bound
					}
					return vmcommon.Ok, nil
				})
				require.True(t, entered)
				if scenario == "bind_control" {
					require.NoError(t, bound, "the same call under another name is bound")
					require.NoError(t, e)
				} else {
					require.ErrorIs(t, bound, vm.ErrDRWAExecution, "a reserved registration name is never bound to a lease")
					require.ErrorIs(t, e, vm.ErrDRWAExecution)
				}
				require.Empty(t, trace)
				return
			}
			var code vmcommon.ReturnCode
			if strings.HasPrefix(scenario, "pool_") {
				// The actual native pool/Save consumer must hand ordinary execution
				// the same transaction, with no receipt charge or lease dependency.
				transport, ok := pool.Transactions().(interface {
					ConfigureNativeValidationSource(*nativeValidation.NativeValidationSource) error
					NativeValidationReceiptFor([]byte, string, *nativeTx.Transaction) *nativeValidation.NativeValidationReceipt
				})
				require.True(t, ok)
				if strings.HasPrefix(scenario, "pool_on") {
					require.NoError(t, transport.ConfigureNativeValidationSource(&candidate.native.source))
				}
				route := process.ShardCacherIdentifier(intercepted.SenderShardId(), intercepted.ReceiverShardId())
				if strings.HasPrefix(scenario, "pool_baseline") {
					// Pinned native Save's successful AddData branch, independently
					// of current interception/receipt-routing implementation.
					pool.Transactions().AddData(intercepted.Hash(), actual, actual.Size(), route)
				} else {
					save, e := processor.NewTxInterceptorProcessor(&processor.ArgTxInterceptorProcessor{
						ShardedDataCache: pool.Transactions(), TxValidator: &mock.TxValidatorStub{}, DirectSentTransactionsCache: &cacheFixture.CacherStub{},
					})
					require.NoError(t, e)
					stored, e := save.Save(intercepted, "", "", p2p.Broadcast)
					require.NoError(t, e)
					require.True(t, stored)
				}
				cache, ok := pool.Transactions().ShardDataStore(route).(interface {
					GetByTxHashWithValidationReceipt([]byte) (*txcache.WrappedTransaction, interface{}, bool)
				})
				require.True(t, ok)
				wrapped, metadata, found := cache.GetByTxHashWithValidationReceipt(intercepted.Hash())
				require.True(t, found)
				require.Equal(t, int64(actual.Size()), wrapped.Size)
				require.Nil(t, metadata)
				require.Nil(t, transport.NativeValidationReceiptFor(intercepted.Hash(), route, actual))
				code, err = execution.NativeSC.ExecuteSmartContractTransaction(wrapped.Tx, nil, destination.(state.UserAccountHandler))
			} else {
				code, err = native.ExecuteSmartContractTransactionWithDRWA(actual, nil, destination.(state.UserAccountHandler), receipt)
			}
			require.NoError(t, err, "the configured native candidate must carry the validated original through SC preparation and the actual SystemVM")
			expected := vmcommon.Ok
			if regulated {
				expected = vmcommon.UserError
			}
			require.Equal(t, expected, code, "authenticated original EOA does not bypass the regulated public-operation guard")
			account, e := store.GetExistingAccount(core.ESDTSCAddress)
			require.NoError(t, e)
			raw, _, e := account.(state.UserAccountHandler).RetrieveValue(token)
			require.NoError(t, e)
			retained := &systemSmartContracts.ESDTDataV2{}
			require.NoError(t, proto.Unmarshal(retained, raw))
			owner := successor
			if regulated {
				owner = sender
			}
			require.Equal(t, owner, retained.OwnerAddress)
			if regulated {
				require.Empty(t, trace, "classification must deny before the physical native prelude")
			} else {
				require.Equal(t, []string{"clean", "address", "value", "gas"}, trace)
			}
			if strings.HasPrefix(scenario, "pool_") {
				root, e := store.RootHash()
				require.NoError(t, e)
				observed := ordinaryOutcome{code, root, bytes.Clone(raw), append([]string(nil), trace...), prepared, output, fees.GetAccumulatedFees(), fees.GetDeveloperFees()}
				require.NotNil(t, output)
				v1 := strings.HasSuffix(scenario, "_v1")
				if strings.HasPrefix(scenario, "pool_baseline") {
					ordinaryBaselines[v1] = observed
				} else {
					require.Equal(t, ordinaryBaselines[v1], observed, "ordinary native state, prepared gas/caller/arguments and prelude must match the receipt-free baseline")
				}
			}
			if !regulated {
				require.NotNil(t, prepared)
				// Every refusal gets a fresh real native owner above. A denied
				// lease poisons its original operation and cannot be retried.
				switch scenario {
				case "gas", "caller", "arguments", "callback":
					var expired vm.DRWANativeCallLease
					_, err = candidate.WithDRWANativeCall(actual, receipt, store, physical.runtime, func(lease vm.DRWANativeCallLease) (vmcommon.ReturnCode, error) {
						expired = lease
						require.NoError(t, lease.VerifyTransaction(actual, store, nil, destination.(state.UserAccountHandler)))
						expected := *prepared
						require.NoError(t, lease.(vm.DRWANativePreparedCallLease).BindCall(&expected))
						require.NoError(t, lease.VerifyCall(prepared), "independent valid control before the isolated mutation")
						changed := *prepared
						switch scenario {
						case "gas":
							changed.GasProvided++
						case "caller":
							changed.CallerAddr = successor
						case "arguments":
							changed.Arguments = [][]byte{token, sender}
						case "callback":
							changed.CallType = vmData.AsynchronousCallBack
						}
						return vmcommon.ExecutionFailed, lease.VerifyCall(&changed)
					})
					require.Error(t, err)
					require.NotNil(t, expired)
					require.Error(t, expired.VerifyCall(prepared), "expired/denied operation cannot reuse its native receipt")
				case "foreign_vm", "missing_receipt", "changed_original", "foreign_store", "ended_header", "source_removed", "wrong_provider":
					entered := false
					unexpected := func(vm.DRWANativeCallLease) (vmcommon.ReturnCode, error) { entered = true; return vmcommon.Ok, nil }
					switch scenario {
					case "foreign_vm":
						_, err = candidate.WithDRWANativeCall(actual, receipt, store, &mock.VMExecutionHandlerStub{}, unexpected)
					case "missing_receipt":
						_, err = candidate.WithDRWANativeCall(actual, nil, store, physical.runtime, unexpected)
					case "changed_original":
						actual.Nonce++
						_, err = candidate.WithDRWANativeCall(actual, receipt, store, physical.runtime, unexpected)
					case "foreign_store":
						alias := &qualRegistrationCandidateStore{qualNativeStore: store.qualNativeStore}
						_, err = candidate.WithDRWANativeCall(actual, receipt, alias, physical.runtime, unexpected)
					case "ended_header":
						end()
						_, err = candidate.WithDRWANativeCall(actual, receipt, store, physical.runtime, unexpected)
					case "source_removed":
						candidate.native = nil
						_, err = candidate.WithDRWANativeCall(actual, receipt, store, physical.runtime, unexpected)
					case "wrong_provider":
						candidate.native.source.ChainID = "synthetic foreign native factory"
						_, err = candidate.WithDRWANativeCall(actual, receipt, store, physical.runtime, unexpected)
					}
					require.Error(t, err)
					require.False(t, entered)
				}
			}
			require.False(t, bytes.Equal(actual.SndAddr, core.ESDTSCAddress))
		})
	}
}

// Observation-only forwarding of the REAL context/capabilities. No callback
// below authenticates, creates a lease, or changes a result.
type qualNativePreludeObserver struct {
	vm.ContextHandler
	trace  *[]string
	input  **vmcommon.ContractCallInput
	output **vmcommon.VMOutput
}

func (o *qualNativePreludeObserver) CleanCache() {
	*o.trace = append(*o.trace, "clean")
	o.ContextHandler.CleanCache()
}
func (o *qualNativePreludeObserver) SetSCAddress(a []byte) {
	*o.trace = append(*o.trace, "address")
	o.ContextHandler.SetSCAddress(a)
}
func (o *qualNativePreludeObserver) AddTxValueToSmartContract(v *big.Int, a []byte) {
	*o.trace = append(*o.trace, "value")
	o.ContextHandler.AddTxValueToSmartContract(v, a)
}
func (o *qualNativePreludeObserver) SetGasProvided(g uint64) {
	*o.trace = append(*o.trace, "gas")
	o.ContextHandler.SetGasProvided(g)
}
func (o *qualNativePreludeObserver) DRWANativeCallConfigured() bool {
	return o.ContextHandler.(interface{ DRWANativeCallConfigured() bool }).DRWANativeCallConfigured()
}
func (o *qualNativePreludeObserver) WithDRWANativeCall(tx data.TransactionHandler, v any, a state.AccountsAdapter, p vmcommon.VMExecutionHandler, f func(vm.DRWANativeCallLease) (vmcommon.ReturnCode, error)) (vmcommon.ReturnCode, error) {
	return o.ContextHandler.(vm.DRWANativeCallContext).WithDRWANativeCall(tx, v, a, p, f)
}
func (o *qualNativePreludeObserver) ExecuteDRWASystemCall(i *vmcommon.ContractCallInput, f func() (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
	*o.input = i
	return o.ContextHandler.(vm.DRWASystemCallContext).ExecuteDRWASystemCall(i, f)
}

func (o *qualNativePreludeObserver) CreateVMOutput() *vmcommon.VMOutput {
	output := o.ContextHandler.CreateVMOutput()
	if o.output != nil {
		*o.output = output
	}
	return output
}
