package drwa

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/integrationTests"
	"github.com/multiversx/mx-chain-go/integrationTests/vm"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Qualification fault boundaries wrap the REAL native transaction processor;
// they neither authenticate a bool nor implement a surrogate transaction engine.
type qualConsentProcessor struct {
	process.TransactionProcessor
	run func(*transaction.Transaction) (vmcommon.ReturnCode, error)
}

func (p *qualConsentProcessor) ProcessTransaction(tx *transaction.Transaction) (vmcommon.ReturnCode, error) {
	return p.run(tx)
}

type qualConsentMarshal struct {
	marshal.Marshalizer
	err error
}

func (m *qualConsentMarshal) Marshal(v interface{}) ([]byte, error) { return nil, m.err }

type qualConsentSaveFailure struct {
	qualConsentAccount
	err error
}

func (a *qualConsentSaveFailure) SaveKeyValue(_, _ []byte) error { return a.err }

type qualConsentFinalAccounts struct {
	state.AccountsAdapter
	boundary func(vmcommon.AccountHandler) (vmcommon.AccountHandler, error)
}

func (s *qualConsentFinalAccounts) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	a, err := s.AccountsAdapter.GetExistingAccount(address)
	if err != nil {
		return a, err
	}
	return s.boundary(a)
}

func TestQualDRWAPrivilegedConsentProcessorVersions(t *testing.T) {
	for _, v := range []string{"v1", "v2"} {
		for _, guarded := range []bool{false, true} {
			name := v + "/unguarded"
			if guarded {
				name = v + "/guarded"
			}
			t.Run(name, func(t *testing.T) {
				epochs := config.EnableEpochs{}
				if v == "v1" {
					epochs.SCProcessorV2EnableEpoch = math.MaxUint32
				}
				ctx := qualConsentContextConfig(t, epochs)
				epoch := uint32(0)
				var guardian []byte
				if guarded {
					epoch = qualConsentGuard(t, ctx)
					guardian = qualConsentGuardian
				}
				_, owner := qualConsentInstall(t, ctx, epoch)
				qualConsentProcess(t, ctx, qualConsentData(qualConsentScope()), guardian)
				_, out, err := owner.Commit()
				require.NoError(t, err)
				require.Len(t, out, 1)
				require.NotEmpty(t, qualConsentValue(t, ctx))
			})
		}
	}
}

func TestQualDRWAPrivilegedConsentTransactionGuards(t *testing.T) {
	for _, name := range []string{"tx", "processor", "codec", "hasher", "endpoint", "hash_failure", "missing_action"} {
		t.Run(name, func(t *testing.T) {
			ctx := qualConsentContext(t)
			c, owner := qualConsentInstall(t, ctx, 0)
			tx := qualConsentTx(t, ctx, qualConsentData(qualConsentScope()), nil)
			processor := ctx.TxProcessor
			codec := ctx.Marshalizer
			hasher := integrationTests.TestHasher
			failure := errors.New("qualification hash boundary")
			switch name {
			case "tx":
				tx = nil
			case "processor":
				processor = nil
			case "codec":
				codec = nil
			case "hasher":
				hasher = nil
			case "endpoint":
				tx.Data = []byte("SaveKeyValue@01@02")
			case "hash_failure":
				codec = &qualConsentMarshal{codec, failure}
			case "missing_action":
				processor = &qualConsentProcessor{processor, func(tx *transaction.Transaction) (vmcommon.ReturnCode, error) {
					copyTx := *tx
					copyTx.Data = nil
					return ctx.TxProcessor.ProcessTransaction(&copyTx)
				}}
			}
			code, err := c.ExecuteNativeTransaction(tx, processor, codec, hasher)
			require.Error(t, err)
			if name == "missing_action" {
				require.Equal(t, vmcommon.ExecutionFailed, code)
			} else {
				require.Equal(t, vmcommon.UserError, code)
			}
			require.Empty(t, qualConsentValue(t, ctx))
			if name == "hash_failure" {
				require.ErrorIs(t, err, failure)
			}
			_, out, err := owner.Commit()
			require.NoError(t, err)
			require.Empty(t, out)
		})
	}
}

func TestQualDRWAPrivilegedConsentNativeSuccessBoundary(t *testing.T) {
	for _, name := range []string{"native_error", "native_code", "save_value", "save_account", "load_account", "final_account_type", "final_nonce", "final_code", "rollback_failure", "commit_failure", "panic", "reentry"} {
		t.Run(name, func(t *testing.T) {
			ctx := qualConsentContext(t)
			c, oldOwner := qualConsentInstall(t, ctx, 0)
			_ = oldOwner
			store := &qualNativeStore{AccountsAdapter: ctx.Accounts}
			owner, err := NewRollbackContainment(store)
			require.NoError(t, err)
			c.accounts = store
			c.containment = owner
			initial, err := ctx.Accounts.RootHash()
			require.NoError(t, err)
			tx := qualConsentTx(t, ctx, qualConsentData(qualConsentScope()), nil)
			failure := errors.New("qualification post-dispatch boundary")
			processor := &qualConsentProcessor{TransactionProcessor: ctx.TxProcessor}
			processor.run = func(tx *transaction.Transaction) (vmcommon.ReturnCode, error) {
				if name == "reentry" {
					code, err := c.ExecuteNativeTransaction(tx, ctx.TxProcessor, ctx.Marshalizer, integrationTests.TestHasher)
					require.ErrorIs(t, err, ErrExecutionBusy)
					require.Equal(t, vmcommon.UserError, code)
				}
				code, err := ctx.TxProcessor.ProcessTransaction(tx)
				require.NoError(t, err)
				require.Equal(t, vmcommon.Ok, code)
				switch name {
				case "native_error":
					return code, failure
				case "native_code":
					return vmcommon.UserError, nil
				case "save_value":
					c.accounts = &qualConsentFinalAccounts{store, func(a vmcommon.AccountHandler) (vmcommon.AccountHandler, error) {
						return &qualConsentSaveFailure{a.(qualConsentAccount), failure}, nil
					}}
				case "load_account":
					c.accounts = &qualConsentFinalAccounts{store, func(a vmcommon.AccountHandler) (vmcommon.AccountHandler, error) { return a, failure }}
				case "final_account_type":
					c.accounts = &qualConsentFinalAccounts{store, func(a vmcommon.AccountHandler) (vmcommon.AccountHandler, error) {
						return &qualConsentVMOnlyWithCode{a.(vmcommon.UserAccountHandler)}, nil
					}}
				case "final_nonce":
					c.accounts = &qualConsentFinalAccounts{store, func(a vmcommon.AccountHandler) (vmcommon.AccountHandler, error) { a.IncreaseNonce(1); return a, nil }}
				case "final_code":
					c.accounts = &qualConsentFinalAccounts{store, func(a vmcommon.AccountHandler) (vmcommon.AccountHandler, error) {
						a.(state.UserAccountHandler).SetCodeHash([]byte("post-native unexpected code"))
						return a, nil
					}}
				case "save_account":
					store.saveErr = failure
				case "rollback_failure":
					store.saveErr = failure
					store.revertErr = failure
				case "commit_failure":
					store.commitErr = failure
				case "panic":
					panic(failure)
				}
				return code, err
			}
			if name == "panic" {
				require.Panics(t, func() { _, _ = c.ExecuteNativeTransaction(tx, processor, ctx.Marshalizer, integrationTests.TestHasher) })
			} else {
				code, err := c.ExecuteNativeTransaction(tx, processor, ctx.Marshalizer, integrationTests.TestHasher)
				switch name {
				case "native_error":
					require.Equal(t, vmcommon.Ok, code)
					require.ErrorIs(t, err, failure)
				case "native_code":
					require.Equal(t, vmcommon.UserError, code)
					require.NoError(t, err)
				case "commit_failure", "reentry":
					require.Equal(t, vmcommon.Ok, code)
					require.NoError(t, err)
				default:
					require.Equal(t, vmcommon.ExecutionFailed, code)
					if name == "final_account_type" || name == "final_nonce" || name == "final_code" {
						require.ErrorIs(t, err, ErrPrivilegedConsent)
					} else {
						require.ErrorIs(t, err, failure)
					}
				}
			}
			require.False(t, c.executing)
			require.Nil(t, c.pendingAccount)
			require.Nil(t, c.expectedHash)
			if name == "native_error" || name == "native_code" {
				require.Empty(t, qualConsentValue(t, ctx))
				a, err := ctx.Accounts.GetExistingAccount(qualConsentEOA)
				require.NoError(t, err)
				require.Equal(t, tx.Nonce+1, a.GetNonce())
				_, out, err := owner.Commit()
				require.NoError(t, err)
				for _, o := range out {
					require.Nil(t, o)
				}
			} else if name == "reentry" {
				_, out, err := owner.Commit()
				require.NoError(t, err)
				require.Len(t, out, 1)
				require.NotEmpty(t, qualConsentValue(t, ctx))
			} else if name == "save_value" || name == "save_account" || name == "load_account" || name == "final_account_type" || name == "final_nonce" || name == "final_code" {
				require.Empty(t, qualConsentValue(t, ctx))
				root, err := ctx.Accounts.RootHash()
				require.NoError(t, err)
				require.Equal(t, initial, root)
				_, out, err := owner.Commit()
				require.NoError(t, err)
				require.Empty(t, out)
			} else {
				_, out, err := owner.Commit()
				require.Error(t, err)
				require.Nil(t, out)
				store.saveErr = nil
				store.revertErr = nil
				store.commitErr = nil
				store.recreateErr = failure
				require.ErrorIs(t, owner.Recover(), failure)
				store.recreateErr = nil
				require.NoError(t, owner.Recover())
				root, err := ctx.Accounts.RootHash()
				require.NoError(t, err)
				require.Equal(t, initial, root)
				require.Empty(t, qualConsentValue(t, ctx))
				_, out, err = owner.Commit()
				require.ErrorIs(t, err, ErrExecutionClosed)
				require.Nil(t, out)
			}
		})
	}
}

func TestQualDRWAPrivilegedConsentConcurrentEntry(t *testing.T) {
	ctx := qualConsentContext(t)
	c, owner := qualConsentInstall(t, ctx, 0)
	entered, release := make(chan struct{}), make(chan struct{})
	processor := &qualConsentProcessor{TransactionProcessor: ctx.TxProcessor, run: func(tx *transaction.Transaction) (vmcommon.ReturnCode, error) {
		close(entered)
		<-release
		return ctx.TxProcessor.ProcessTransaction(tx)
	}}
	tx := qualConsentTx(t, ctx, qualConsentData(qualConsentScope()), nil)
	done := make(chan error, 1)
	go func() {
		_, err := c.ExecuteNativeTransaction(tx, processor, ctx.Marshalizer, integrationTests.TestHasher)
		done <- err
	}()
	<-entered
	code, err := c.ExecuteNativeTransaction(tx, ctx.TxProcessor, ctx.Marshalizer, integrationTests.TestHasher)
	close(release)
	require.ErrorIs(t, err, ErrExecutionBusy)
	require.Equal(t, vmcommon.UserError, code)
	require.NoError(t, <-done)
	_, out, err := owner.Commit()
	require.NoError(t, err)
	require.Len(t, out, 1)
}

func TestQualDRWAPrivilegedConsentSlotLifecycle(t *testing.T) {
	ctx := qualConsentContext(t)
	c, owner := qualConsentInstall(t, ctx, 0)
	s := qualConsentScope()
	qualConsentProcess(t, ctx, qualConsentData(s), nil)
	_, _, err := owner.Commit()
	require.NoError(t, err)
	oldValue := qualConsentValue(t, ctx)
	oldH, oldW, oldBudget := qualConsentWitness(t, ctx, 0)
	reader := qualConsentReader(t, ctx)
	require.NoError(t, c.ReadEvidence(reader, oldH, 1, s, oldW, oldBudget))
	// Ordinary native SaveKeyValue cannot forge or replace a protected action
	// record. Its failure/nonce effects follow the unchanged native processor.
	data := []byte("SaveKeyValue@" + hex.EncodeToString(experimentalPrivilegedConsentKey) + "@" + hex.EncodeToString([]byte("forged")))
	tx := qualConsentTx(t, ctx, data, nil)
	code, err := ctx.TxProcessor.ProcessTransaction(tx)
	require.Equal(t, vmcommon.UserError, code)
	require.ErrorIs(t, err, process.ErrFailedTransaction)
	require.Equal(t, oldValue, qualConsentValue(t, ctx))
	a, err := ctx.Accounts.GetExistingAccount(s.Address)
	require.NoError(t, err)
	require.Equal(t, tx.Nonce+1, a.GetNonce())
	h, w, budget := qualConsentWitness(t, ctx, 0)
	require.Error(t, c.ReadEvidence(reader, h, 1, s, w, budget))
	// The unchanged owner key grants no freshness waiver. A new successful
	// native action refreshes this single slot; the old roles no longer match.
	c, owner = qualConsentInstall(t, ctx, 0)
	next := s
	next.Roles = []byte("next fixture roles")
	qualConsentProcess(t, ctx, qualConsentData(next), nil)
	_, _, err = owner.Commit()
	require.NoError(t, err)
	h, w, budget = qualConsentWitness(t, ctx, 0)
	require.NoError(t, c.ReadEvidence(reader, h, 1, next, w, budget))
	require.Error(t, c.ReadEvidence(reader, h, 1, s, w, budget))
	require.Error(t, c.ReadEvidence(reader, h, 1, s, oldW, oldBudget))
	root, err := ctx.Accounts.RootHash()
	require.NoError(t, err)
	require.NoError(t, ctx.Accounts.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
	reloaded := qualConsentReader(t, ctx)
	require.NoError(t, c.ReadEvidence(reloaded, h, 1, next, w, budget))
	require.Equal(t, qualConsentValue(t, ctx), encodeExperimentalConsent(next, tx.Nonce+2, 0))
}

func TestQualDRWAPrivilegedConsentNativeAccountPreservation(t *testing.T) {
	for _, v := range []string{"v1", "v2"} {
		t.Run(v, func(t *testing.T) {
			epochs := config.EnableEpochs{}
			if v == "v1" {
				epochs.SCProcessorV2EnableEpoch = math.MaxUint32
			}
			ctx := qualConsentContextConfig(t, epochs)
			c, owner := qualConsentInstall(t, ctx, 0)
			var nativeBalance []byte
			processor := &qualConsentProcessor{TransactionProcessor: ctx.TxProcessor, run: func(tx *transaction.Transaction) (vmcommon.ReturnCode, error) {
				code, err := ctx.TxProcessor.ProcessTransaction(tx)
				a, e := ctx.Accounts.GetExistingAccount(qualConsentEOA)
				require.NoError(t, e)
				nativeBalance = a.(state.UserAccountHandler).GetBalance().Bytes()
				return code, err
			}}
			tx := qualConsentTx(t, ctx, qualConsentData(qualConsentScope()), nil)
			// Keep excess gas small so native penalization cannot consume the whole
			// limit and accidentally hide a lost-refund persistence defect.
			tx.GasLimit = ctx.EconomicsData.ComputeGasLimit(tx) + 100
			code, err := c.ExecuteNativeTransaction(tx, processor, ctx.Marshalizer, integrationTests.TestHasher)
			require.NoError(t, err)
			require.Equal(t, vmcommon.Ok, code)
			a, err := ctx.Accounts.GetExistingAccount(qualConsentEOA)
			require.NoError(t, err)
			require.Equal(t, nativeBalance, a.(state.UserAccountHandler).GetBalance().Bytes(), "final consent persistence must preserve the native processor's refund/account state")
			_, _, err = owner.Commit()
			require.NoError(t, err)
		})
	}
}

// Both contexts use unchanged native transactions, with identical inputs. Only
// one has the dormant candidate installed. Compare each lifecycle instant's
// whole account root, raw account, native gas/fees, logs and outgoing SCR bytes.
func qualConsentNativeSnapshot(t *testing.T, ctx *vm.VMTestContext) []byte {
	t.Helper()
	root, err := ctx.Accounts.Commit()
	require.NoError(t, err)
	a, err := ctx.Accounts.GetExistingAccount(qualConsentEOA)
	require.NoError(t, err)
	raw, err := ctx.Marshalizer.Marshal(a)
	require.NoError(t, err)
	logs, err := json.Marshal(ctx.TxsLogsProcessor.GetAllCurrentLogs())
	require.NoError(t, err)
	var scrs [][]byte
	for _, scr := range ctx.GetIntermediateTransactions(t) {
		raw, err := ctx.Marshalizer.Marshal(scr)
		require.NoError(t, err)
		scrs = append(scrs, raw)
	}
	value, _, _ := a.(state.UserAccountHandler).RetrieveValue(experimentalPrivilegedConsentKey)
	require.Empty(t, value)
	encoded, err := json.Marshal([]interface{}{root, raw, ctx.GetGasRemaining(), ctx.TxFeeHandler.GetAccumulatedFees().String(), ctx.TxFeeHandler.GetDeveloperFees().String(), logs, scrs})
	require.NoError(t, err)
	return encoded
}
func TestQualDRWAPrivilegedConsentGuardianEquivalence(t *testing.T) {
	for _, v := range []string{"v1", "v2"} {
		t.Run(v, func(t *testing.T) {
			epochs := config.EnableEpochs{}
			if v == "v1" {
				epochs.SCProcessorV2EnableEpoch = math.MaxUint32
			}
			plain, installed := qualConsentContextConfig(t, epochs), qualConsentContextConfig(t, epochs)
			c, owner := qualConsentInstall(t, installed, 0)
			_ = c
			require.Equal(t, qualConsentNativeSnapshot(t, plain), qualConsentNativeSnapshot(t, installed))
			for _, step := range []string{"set_delayed", "too_early", "activate", "guard", "wrong_guardian", "instant_replace", "guarded_ordinary", "unguard", "unguarded_ordinary"} {
				var data, guardian []byte
				switch step {
				case "set_delayed":
					data = []byte("SetGuardian@" + hex.EncodeToString(qualConsentGuardian) + "@01")
				case "too_early", "guard":
					data = []byte("GuardAccount")
				case "activate":
					plain.EpochNotifier.CheckEpoch(&block.Header{Epoch: vm.EpochGuardianDelay})
					installed.EpochNotifier.CheckEpoch(&block.Header{Epoch: vm.EpochGuardianDelay})
				case "wrong_guardian":
					data = []byte("UnGuardAccount")
					guardian = bytes.Repeat([]byte{0x51}, 32)
				case "instant_replace":
					data = []byte("SetGuardian@" + hex.EncodeToString(bytes.Repeat([]byte{0x51}, 32)) + "@01")
					guardian = qualConsentGuardian
				case "guarded_ordinary":
					guardian = bytes.Repeat([]byte{0x51}, 32)
				case "unguard":
					data = []byte("UnGuardAccount")
					guardian = bytes.Repeat([]byte{0x51}, 32)
				}
				if step != "activate" {
					tx1, tx2 := qualConsentTx(t, plain, data, guardian), qualConsentTx(t, installed, data, guardian)
					code1, err1 := plain.TxProcessor.ProcessTransaction(tx1)
					code2, err2 := installed.TxProcessor.ProcessTransaction(tx2)
					require.Equal(t, code1, code2, step)
					require.Equal(t, err1, err2, step)
				}
				require.Equal(t, qualConsentNativeSnapshot(t, plain), qualConsentNativeSnapshot(t, installed), step)
			}
			require.Empty(t, owner.outputs, "pure guardian/native paths add no consent output")
		})
	}
}
