package drwa

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/integrationTests"
	"github.com/multiversx/mx-chain-go/integrationTests/vm"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/state"
	stateDisabled "github.com/multiversx/mx-chain-go/state/disabled"
	"github.com/multiversx/mx-chain-go/state/factory"
	"github.com/multiversx/mx-chain-go/testscommon"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Explicit experimental fixtures: none is a production address/profile/gas
// allocation. Native processor, builtin dispatcher, AccountsDB and guardians
// are real. ProcessTransaction assumes prior interceptor authentication; that
// separate signature gate is exercised by the signature qualification file.
var qualConsentEOA = bytes.Repeat([]byte{0x31}, 32)
var qualConsentGuardian = bytes.Repeat([]byte{0x41}, 32)

func qualConsentScope() PrivilegedConsentScope {
	return PrivilegedConsentScope{[]byte("fixture-domain"), []byte("TOKEN-fixture"), []byte("fixture-program"),
		[]byte("fixture-target"), []byte("fixture-roles"), bytes.Clone(qualConsentEOA)}
}
func qualConsentData(s PrivilegedConsentScope) []byte {
	data := ExperimentalPrivilegedConsentEndpoint
	for _, f := range [][]byte{s.Domain, s.Token, s.Program, s.Target, s.Roles, s.Address} {
		data += "@" + hex.EncodeToString(f)
	}
	return []byte(data)
}
func qualConsentContext(t *testing.T) *vm.VMTestContext {
	return qualConsentContextConfig(t, config.EnableEpochs{})
}

func qualConsentContextConfig(t *testing.T, epochs config.EnableEpochs) *vm.VMTestContext {
	t.Helper()
	coordinator := testscommon.NewMultiShardsCoordinatorMock(2)
	coordinator.CurrentShard = 1
	ctx, err := vm.CreatePreparedTxProcessorWithVMsWithShardCoordinator(epochs, coordinator, 1)
	require.NoError(t, err)
	t.Cleanup(ctx.Close)
	a, err := ctx.Accounts.LoadAccount(qualConsentEOA)
	require.NoError(t, err)
	require.NoError(t, a.(state.UserAccountHandler).AddToBalance(big.NewInt(1000000000)))
	require.NoError(t, ctx.Accounts.SaveAccount(a))
	_, err = ctx.Accounts.Commit()
	require.NoError(t, err)
	return ctx
}
func qualConsentInstall(t *testing.T, ctx *vm.VMTestContext, epoch uint32) (*PrivilegedConsentCandidate, *RollbackContainment) {
	t.Helper()
	_, err := ctx.Accounts.Commit()
	require.NoError(t, err)
	owner, err := NewRollbackContainment(ctx.Accounts)
	require.NoError(t, err)
	c, err := NewPrivilegedConsentCandidate(ctx.Accounts, owner, []byte("fixture-domain"), 32, 256, nil, func() uint32 { return epoch }, 10)
	require.NoError(t, err)
	container := ctx.BlockchainHook.(*hooks.BlockChainHookImpl).GetBuiltinFunctionsContainer()
	if _, exists := container.Keys()[ExperimentalPrivilegedConsentEndpoint]; exists {
		err = container.Replace(ExperimentalPrivilegedConsentEndpoint, c)
	} else {
		err = container.Add(ExperimentalPrivilegedConsentEndpoint, c)
	}
	require.NoError(t, err)
	return c, owner
}
func qualConsentTx(t *testing.T, ctx *vm.VMTestContext, data []byte, guardian []byte) *transaction.Transaction {
	t.Helper()
	a, err := ctx.Accounts.LoadAccount(qualConsentEOA)
	require.NoError(t, err)
	tx := vm.CreateTransaction(a.GetNonce(), big.NewInt(0), bytes.Clone(qualConsentEOA), bytes.Clone(qualConsentEOA), 1, 1000000, data)
	if guardian != nil {
		tx.GuardianAddr = guardian
		tx.Options = transaction.MaskGuardedTransaction
		tx.Version = 2
	}
	return tx
}
func qualConsentProcess(t *testing.T, ctx *vm.VMTestContext, data []byte, guardian []byte) {
	t.Helper()
	tx := qualConsentTx(t, ctx, data, guardian)
	var code vmcommon.ReturnCode
	var err error
	if bytes.HasPrefix(data, []byte(ExperimentalPrivilegedConsentEndpoint+"@")) {
		fn, e := ctx.BlockchainHook.(*hooks.BlockChainHookImpl).GetBuiltinFunctionsContainer().Get(ExperimentalPrivilegedConsentEndpoint)
		require.NoError(t, e)
		code, err = fn.(*PrivilegedConsentCandidate).ExecuteNativeTransaction(tx, ctx.TxProcessor, ctx.Marshalizer, integrationTests.TestHasher)
	} else {
		code, err = ctx.TxProcessor.ProcessTransaction(tx)
	}
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, code)
}
func qualConsentValue(t *testing.T, ctx *vm.VMTestContext) []byte {
	t.Helper()
	a, err := ctx.Accounts.GetExistingAccount(qualConsentEOA)
	require.NoError(t, err)
	v, _, _ := a.(state.UserAccountHandler).RetrieveValue(experimentalPrivilegedConsentKey)
	return v
}
func qualConsentGuard(t *testing.T, ctx *vm.VMTestContext) uint32 {
	t.Helper()
	qualConsentProcess(t, ctx, []byte("SetGuardian@"+hex.EncodeToString(qualConsentGuardian)+"@01"), nil)
	epoch := vm.EpochGuardianDelay
	ctx.EpochNotifier.CheckEpoch(&block.Header{Epoch: epoch})
	qualConsentProcess(t, ctx, []byte("GuardAccount"), nil)
	return epoch
}

func TestQualDRWAPrivilegedConsentNative(t *testing.T) {
	for _, name := range []string{"unguarded", "guarded", "wrong_guardian", "guarded_missing_guardian", "unguarded_guarded_tx", "wrong_domain", "wrong_address", "missing_role", "value", "insufficient_gas", "nonce_only_failure", "duplicate"} {
		t.Run(name, func(t *testing.T) {
			ctx := qualConsentContext(t)
			epoch := uint32(0)
			var guardian []byte
			if name == "guarded" || name == "wrong_guardian" || name == "guarded_missing_guardian" {
				epoch = qualConsentGuard(t, ctx)
				guardian = bytes.Clone(qualConsentGuardian)
			}
			c, owner := qualConsentInstall(t, ctx, epoch)
			s := qualConsentScope()
			switch name {
			case "wrong_guardian":
				guardian = bytes.Repeat([]byte{0x51}, 32)
			case "guarded_missing_guardian":
				guardian = nil
			case "unguarded_guarded_tx":
				guardian = qualConsentGuardian
			case "wrong_domain":
				s.Domain = []byte("wrong-domain")
			case "wrong_address":
				s.Address = bytes.Repeat([]byte{0x32}, 32)
			case "missing_role":
				s.Roles = nil
			}
			tx := qualConsentTx(t, ctx, qualConsentData(s), guardian)
			before := tx.Nonce
			if name == "value" {
				tx.Value = big.NewInt(1)
			}
			if name == "insufficient_gas" {
				tx.GasLimit = 1
			}
			if name == "nonce_only_failure" {
				tx.Data = []byte("unknownFunction")
				tx.Value = big.NewInt(2000000000)
			}
			var code vmcommon.ReturnCode
			var err error
			if name == "nonce_only_failure" {
				code, err = ctx.TxProcessor.ProcessTransaction(tx)
			} else {
				code, err = c.ExecuteNativeTransaction(tx, ctx.TxProcessor, ctx.Marshalizer, integrationTests.TestHasher)
			}
			if err != nil {
				t.Logf("native diagnostic: composite=%v logs=%v", ctx.GetCompositeTestError(), ctx.TxsLogsProcessor.GetAllCurrentLogs())
			}
			if name == "unguarded" || name == "guarded" || name == "duplicate" {
				require.NoError(t, err)
				require.Equal(t, vmcommon.Ok, code)
				require.Equal(t, encodeExperimentalConsent(s, before+1, epoch), qualConsentValue(t, ctx))
				_, outputs, e := owner.Commit()
				require.NoError(t, e)
				require.Len(t, outputs, 1)
				if name == "duplicate" {
					// Duplicate presentation consumes no state; a distinct native tx
					// refreshing the same target follows native nonce/gas, not a free replay.
					_, owner = qualConsentInstall(t, ctx, epoch)
					qualConsentProcess(t, ctx, qualConsentData(s), guardian)
					_, _, e = owner.Commit()
					require.NoError(t, e)
					require.Equal(t, encodeExperimentalConsent(s, before+2, epoch), qualConsentValue(t, ctx))
				}
			} else {
				if name == "nonce_only_failure" {
					require.Equal(t, vmcommon.Ok, code)
				} else {
					require.NotEqual(t, vmcommon.Ok, code)
				}
				require.Empty(t, qualConsentValue(t, ctx))
				if name == "nonce_only_failure" {
					require.ErrorIs(t, err, process.ErrFailedTransaction)
					a, e := ctx.Accounts.GetExistingAccount(qualConsentEOA)
					require.NoError(t, e)
					require.Equal(t, before+1, a.GetNonce())
				}
			}
			_ = c
		})
	}
}

func TestQualDRWAPrivilegedConsentGuards(t *testing.T) {
	for _, name := range []string{"nil_sender", "nil_input", "unbound_execution", "wrong_tx_hash", "pending_action", "function", "async", "caller", "recipient", "nil_value", "value", "esdt", "error_return", "locked_gas", "gas", "argument_count", "empty_field", "field_bound", "domain", "address_binding", "short_address", "sc_address", "system_prefix", "reserved", "code", "pending_code", "vm_only_account", "missing_code_method"} {
		t.Run(name, func(t *testing.T) {
			f := qualNativeReaderFixture(t, false, 1)
			owner, err := NewRollbackContainment(f.adb)
			require.NoError(t, err)
			s := qualConsentScope()
			s.Address = f.address
			c, err := NewPrivilegedConsentCandidate(f.adb, owner, s.Domain, 32, 256, [][]byte{bytes.Repeat([]byte{0x66}, 32)}, func() uint32 { return 3 }, 10)
			require.NoError(t, err)
			a, err := f.adb.LoadAccount(f.address)
			require.NoError(t, err)
			u := a.(state.UserAccountHandler)
			var sender vmcommon.UserAccountHandler = u.(vmcommon.UserAccountHandler)
			in := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: f.address, Arguments: [][]byte{s.Domain, s.Token, s.Program, s.Target, s.Roles, s.Address}, CallValue: big.NewInt(0), GasProvided: 10}, RecipientAddr: f.address, Function: ExperimentalPrivilegedConsentEndpoint}
			c.executing = true
			c.expectedHash = []byte("native-tx-hash")
			in.CurrentTxHash = bytes.Clone(c.expectedHash)
			switch name {
			case "nil_sender":
				sender = nil
			case "nil_input":
				in = nil
			case "unbound_execution":
				c.executing = false
			case "wrong_tx_hash":
				in.CurrentTxHash = []byte("other")
			case "pending_action":
				c.pendingAccount = u
			case "function":
				in.Function = "ordinary"
			case "async":
				in.CallType = vmData.AsynchronousCall
			case "caller":
				in.CallerAddr = qualConsentEOA
				in.RecipientAddr = qualConsentEOA
				in.Arguments[5] = qualConsentEOA
			case "recipient":
				in.RecipientAddr = qualConsentEOA
			case "nil_value":
				in.CallValue = nil
			case "value":
				in.CallValue = big.NewInt(1)
			case "esdt":
				in.ESDTTransfers = []*vmcommon.ESDTTransfer{{}}
			case "error_return":
				in.ReturnCallAfterError = true
			case "locked_gas":
				in.GasLocked = 1
			case "gas":
				in.GasProvided = 9
			case "argument_count":
				in.Arguments = in.Arguments[:5]
			case "empty_field":
				in.Arguments[2] = nil
			case "field_bound":
				in.Arguments[2] = bytes.Repeat([]byte{1}, 257)
			case "domain":
				in.Arguments[0] = []byte("other")
			case "address_binding":
				in.Arguments[5] = qualConsentEOA
			case "short_address", "sc_address", "system_prefix", "reserved":
				address := bytes.Repeat([]byte{0x66}, 32)
				if name == "short_address" {
					address = []byte{1}
				}
				if name == "sc_address" {
					address = make([]byte, 32)
					address[31] = 1
				}
				if name == "system_prefix" {
					address = bytes.Clone(core.SystemAccountAddress)
					address[31] = 1
				}
				af, createErr := factory.NewAccountCreator(factory.ArgsAccountCreator{Hasher: f.args.Hasher, Marshaller: f.args.Marshaller, EnableEpochsHandler: f.args.EnableEpochsHandler, StateAccessesCollector: stateDisabled.NewDisabledStateAccessesCollector()})
				require.NoError(t, createErr)
				invalidAccount, createErr := af.CreateAccount(address)
				require.NoError(t, createErr)
				sender = invalidAccount.(vmcommon.UserAccountHandler)
				in.CallerAddr = address
				in.RecipientAddr = address
				in.Arguments[5] = address
			case "code":
				u.SetCodeHash([]byte("actual-code-hash"))
			case "pending_code":
				u.SetCode([]byte("not yet saved native code"))
				require.Empty(t, u.GetCodeHash(), "pending native code has not yet acquired a persisted hash")
			case "vm_only_account":
				sender = &qualConsentVMOnlyWithCode{sender}
			case "missing_code_method":
				sender = &qualConsentMissingCode{u.(qualConsentAccount)}
			}
			out, err := c.ProcessBuiltinFunction(sender, nil, in)
			require.Error(t, err)
			require.Nil(t, out)
			v, _, _ := u.RetrieveValue(experimentalPrivilegedConsentKey)
			require.Empty(t, v)
		})
	}
}

type qualConsentVMOnly struct{ vmcommon.UserAccountHandler }
type qualConsentVMOnlyWithCode struct{ vmcommon.UserAccountHandler }

func (a *qualConsentVMOnlyWithCode) GetCode() []byte { return nil }

type qualConsentAccount interface {
	state.UserAccountHandler
	vmcommon.UserAccountHandler
}
type qualConsentMissingCode struct{ qualConsentAccount }

func TestQualDRWAPrivilegedConsentConstructor(t *testing.T) {
	for _, name := range []string{"accounts", "containment", "domain", "length", "bound", "domain_bound", "epoch", "gas"} {
		t.Run(name, func(t *testing.T) {
			f := qualNativeReaderFixture(t, false, 1)
			owner, err := NewRollbackContainment(f.adb)
			require.NoError(t, err)
			var accounts state.AccountsAdapter = f.adb
			domain := []byte("d")
			length, bound := 32, 256
			epoch := func() uint32 { return 3 }
			gas := uint64(10)
			switch name {
			case "accounts":
				accounts = nil
			case "containment":
				owner = nil
			case "domain":
				domain = nil
			case "length":
				length = 0
			case "bound":
				bound = 0
			case "domain_bound":
				domain = bytes.Repeat([]byte{1}, 257)
			case "epoch":
				epoch = nil
			case "gas":
				gas = 0
			}
			c, err := NewPrivilegedConsentCandidate(accounts, owner, domain, length, bound, nil, epoch, gas)
			require.Error(t, err)
			require.Nil(t, c)
		})
	}
}

func TestQualDRWAPrivilegedConsentEncoding(t *testing.T) {
	s := qualConsentScope()
	// Independent framing vector (version 1, nonce 2, epoch 3, six length-
	// prefixed literal fields); no encoder-produced fixture is the oracle.
	s = PrivilegedConsentScope{[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e"), []byte("f")}
	want := "01000000000000000200000003000000000000000161000000000000000162000000000000000163000000000000000164000000000000000165000000000000000166"
	require.Equal(t, want, hex.EncodeToString(encodeExperimentalConsent(s, 2, 3)))
	require.NotEqual(t, encodeExperimentalConsent(PrivilegedConsentScope{Domain: []byte("ab"), Token: []byte("c")}, 2, 3), encodeExperimentalConsent(PrivilegedConsentScope{Domain: []byte("a"), Token: []byte("bc")}, 2, 3))
}
