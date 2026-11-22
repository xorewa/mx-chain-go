package txsFee

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/integrationTests/vm"
	"github.com/multiversx/mx-chain-go/integrationTests/vm/txsFee/utils"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// This is a native-equivalence experiment, not an admitted DRWA account path.
// The native membership schema is used literally. All other protected values
// are inert qualification sentinels, not allocated holder/decision codecs.
// No fixture substitutes for native authentication or regulated compliance.
func TestQualDRWANativeGuardianEquivalence(t *testing.T) {
	for _, fixture := range []struct {
		name  string
		value []byte
	}{
		{"initial_epoch", []byte{1, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"retained_nonzero_epoch", []byte{1, 0, 0, 0, 0, 0, 0, 0, 7}},
		{"malformed_opaque_state", []byte{255}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			plain := prepareTestContextForGuardedAccounts(t)
			defer plain.Close()
			withSentinels := prepareTestContextForGuardedAccounts(t)
			defer withSentinels.Close()
			token := []byte("ORDINARY-abcdef")
			for _, c := range []*vm.VMTestContext{plain, withSentinels} {
				utils.CreateAccountWithESDTBalance(t, c.Accounts, alice, initialMint,
					token, 0, big.NewInt(1000), uint32(core.Fungible))
				for _, address := range [][]byte{bob, charlie, david} {
					mintAddress(t, c, address, big.NewInt(0), "native fixture")
				}
			}
			sentinels := map[string][]byte{
				core.ProtectedKeyPrefix + "DRWA@membership@REGULATED-abcdef":             {1},
				core.ProtectedKeyPrefix + "QUAL@T24@HolderProfileState@" + string(alice): fixture.value,
				core.ProtectedKeyPrefix + "QUAL@T24@restriction":                         []byte("restricted"),
				core.ProtectedKeyPrefix + "QUAL@T24@decision":                            []byte("expired"),
				core.ProtectedKeyPrefix + "QUAL@T24@lifecycle":                           []byte("FAIL_SAFE"),
			}
			qualNativeGuardianSentinels(t, withSentinels, sentinels, true)
			qualNativeGuardianSentinels(t, plain, nil, true)
			for _, c := range []*vm.VMTestContext{plain, withSentinels} {
				_, err := c.Accounts.Commit()
				require.NoError(t, err)
			}

			status := createUnGuardedAccountStatus()
			run := func(name string, operation func(*vm.VMTestContext) (vmcommon.ReturnCode, error),
				code vmcommon.ReturnCode, expectedError error) {
				require.True(t, t.Run(name, func(t *testing.T) {
					for _, c := range []*vm.VMTestContext{plain, withSentinels} {
						c.CreateBlockStarted()
						c.TxsLogsProcessor.Clean()
					}
					aCode, aError := operation(plain)
					bCode, bError := operation(withSentinels)
					require.Equal(t, code, aCode)
					require.Equal(t, code, bCode)
					if expectedError == nil {
						require.NoError(t, aError)
						require.NoError(t, bError)
					} else {
						require.ErrorIs(t, aError, expectedError)
						require.ErrorIs(t, bError, expectedError)
						require.Equal(t, aError.Error(), bError.Error())
					}
					qualNativeGuardianCompare(t, plain, withSentinels)
					for _, c := range []*vm.VMTestContext{plain, withSentinels} {
						testGuardianStatus(t, c, alice, status)
						u := qualNativeGuardianAccount(t, c, alice)
						require.Empty(t, u.GetCodeHash(), "guarded metadata is not contract code")
						if status.isGuarded {
							require.NotEmpty(t, u.GetCodeMetadata())
						}
					}
					qualNativeGuardianSentinels(t, withSentinels, sentinels, false)
				}))
			}
			egld := func(guardian []byte) func(*vm.VMTestContext) (vmcommon.ReturnCode, error) {
				return func(c *vm.VMTestContext) (vmcommon.ReturnCode, error) {
					limit := transferGas
					if guardian != nil {
						limit += guardianSigVerificationGas
					}
					tx := vm.CreateTransaction(getNonce(c, alice), transferValue, alice, david, gasPrice, limit, nil)
					qualNativeGuardianTx(tx, guardian)
					return c.TxProcessor.ProcessTransaction(tx)
				}
			}
			esdtTransfer := func(guardian []byte) func(*vm.VMTestContext) (vmcommon.ReturnCode, error) {
				return func(c *vm.VMTestContext) (vmcommon.ReturnCode, error) {
					tx := utils.CreateESDTTransferTx(getNonce(c, alice), alice, david,
						token, big.NewInt(10), gasPrice, 2000000)
					qualNativeGuardianTx(tx, guardian)
					return c.TxProcessor.ProcessTransaction(tx)
				}
			}
			run("unguarded_ordinary_egld", egld(nil), vmcommon.Ok, nil)
			run("guard_without_active", func(c *vm.VMTestContext) (vmcommon.ReturnCode, error) {
				return guardAccount(c, alice)
			}, vmcommon.UserError, process.ErrFailedTransaction)
			status.pending = &guardianInfo{address: bob, uuid: uuid, epoch: vm.EpochGuardianDelay}
			run("set_pending", func(c *vm.VMTestContext) (vmcommon.ReturnCode, error) {
				return setGuardian(c, alice, bob, uuid)
			}, vmcommon.Ok, nil)
			run("guard_before_activation", func(c *vm.VMTestContext) (vmcommon.ReturnCode, error) {
				return guardAccount(c, alice)
			}, vmcommon.UserError, process.ErrFailedTransaction)
			run("guarded_format_while_unguarded", egld(bob), vmcommon.UserError, process.ErrTransactionNotExecutable)
			for _, c := range []*vm.VMTestContext{plain, withSentinels} {
				setNewEpochOnContext(c, vm.EpochGuardianDelay)
			}
			status.active, status.pending = status.pending, nil
			for _, c := range []*vm.VMTestContext{plain, withSentinels} {
				testGuardianStatus(t, c, alice, status)
			}
			qualNativeGuardianSentinels(t, withSentinels, sentinels, false)
			status.isGuarded = true
			run("guard_at_activation", func(c *vm.VMTestContext) (vmcommon.ReturnCode, error) {
				return guardAccount(c, alice)
			}, vmcommon.Ok, nil)
			run("unguarded_egld_denied", egld(nil), vmcommon.UserError, process.ErrTransactionNotExecutable)
			run("wrong_guardian_denied", egld(charlie), vmcommon.UserError, process.ErrTransactionNotExecutable)
			run("correct_guardian_egld", egld(bob), vmcommon.Ok, nil)
			run("unguarded_esdt_denied", esdtTransfer(nil), vmcommon.UserError, process.ErrTransactionNotExecutable)
			run("correct_guardian_esdt", esdtTransfer(bob), vmcommon.Ok, nil)
			for _, c := range []*vm.VMTestContext{plain, withSentinels} {
				utils.CheckESDTBalance(t, c, alice, token, big.NewInt(990))
				utils.CheckESDTBalance(t, c, david, token, big.NewInt(10))
			}
			status.pending = &guardianInfo{address: charlie, uuid: uuid, epoch: 2 * vm.EpochGuardianDelay}
			run("native_unguarded_set_exception", func(c *vm.VMTestContext) (vmcommon.ReturnCode, error) {
				return setGuardian(c, alice, charlie, uuid)
			}, vmcommon.Ok, nil)
			run("second_pending_replacement_denied", func(c *vm.VMTestContext) (vmcommon.ReturnCode, error) {
				return setGuardian(c, alice, david, uuid)
			}, vmcommon.UserError, process.ErrTransactionNotExecutable)
			status.active = &guardianInfo{address: charlie, uuid: uuid, epoch: vm.EpochGuardianDelay}
			status.pending = nil
			run("cosigned_immediate_replacement", func(c *vm.VMTestContext) (vmcommon.ReturnCode, error) {
				return setGuardianCoSigned(c, alice, bob, charlie, uuid)
			}, vmcommon.Ok, nil)
			status.isGuarded = false
			run("unguard_retains_active_record", func(c *vm.VMTestContext) (vmcommon.ReturnCode, error) {
				return removeGuardiansCoSigned(c, alice, charlie)
			}, vmcommon.Ok, nil)
			run("unguarded_egld_after_unguard", egld(nil), vmcommon.Ok, nil)
			run("guarded_format_after_unguard_denied", egld(charlie), vmcommon.UserError, process.ErrTransactionNotExecutable)
			t.Run("native_commit_recreation", func(t *testing.T) {
				for _, c := range []*vm.VMTestContext{plain, withSentinels} {
					root, err := c.Accounts.Commit()
					require.NoError(t, err)
					require.NoError(t, c.Accounts.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
					testGuardianStatus(t, c, alice, status)
				}
				qualNativeGuardianCompare(t, plain, withSentinels)
				qualNativeGuardianSentinels(t, withSentinels, sentinels, false)
			})
		})
	}
}

func qualNativeGuardianTx(tx *transaction.Transaction, guardian []byte) {
	if guardian != nil {
		tx.GuardianAddr = bytes.Clone(guardian)
		tx.Version = txWithOptionVersion
		tx.Options |= transaction.MaskGuardedTransaction
	}
}

func qualNativeGuardianAccount(t *testing.T, c *vm.VMTestContext, address []byte) state.UserAccountHandler {
	a, err := c.Accounts.GetExistingAccount(address)
	require.NoError(t, err)
	u, ok := a.(state.UserAccountHandler)
	require.True(t, ok)
	return u
}

func qualNativeGuardianCompare(t *testing.T, a, b *vm.VMTestContext) {
	t.Helper()
	require.Equal(t, a.Accounts.JournalLen(), b.Accounts.JournalLen())
	require.Equal(t, a.GetGasRemaining(), b.GetGasRemaining())
	require.Equal(t, a.TxFeeHandler.GetAccumulatedFees(), b.TxFeeHandler.GetAccumulatedFees())
	require.Equal(t, a.TxFeeHandler.GetDeveloperFees(), b.TxFeeHandler.GetDeveloperFees())
	require.Equal(t, a.TxsLogsProcessor.GetAllCurrentLogs(), b.TxsLogsProcessor.GetAllCurrentLogs())
	x, y := a.GetIntermediateTransactions(t), b.GetIntermediateTransactions(t)
	require.Len(t, y, len(x))
	for i := range x {
		xBytes, err := a.Marshalizer.Marshal(x[i])
		require.NoError(t, err)
		yBytes, err := b.Marshalizer.Marshal(y[i])
		require.NoError(t, err)
		require.Equal(t, xBytes, yBytes, "entire native intermediate output")
	}
	for _, address := range [][]byte{alice, bob, charlie, david} {
		x := qualNativeGuardianAccount(t, a, address)
		y := qualNativeGuardianAccount(t, b, address)
		xBytes, err := a.Marshalizer.Marshal(x)
		require.NoError(t, err)
		yBytes, err := b.Marshalizer.Marshal(y)
		require.NoError(t, err)
		require.Equal(t, xBytes, yBytes, "entire native account record")
		key := []byte(core.ProtectedKeyPrefix + core.GuardiansKeyIdentifier)
		xBytes, _, xErr := x.RetrieveValue(key)
		yBytes, _, yErr := y.RetrieveValue(key)
		if len(x.GetRootHash()) == 0 {
			// A native EOA without a data trie returns ErrNilTrie, not an
			// absent-key successful read. The native guardian reader handles
			// this as no configured guardian; compare that exact outcome.
			require.ErrorIs(t, xErr, state.ErrNilTrie)
			require.ErrorIs(t, yErr, state.ErrNilTrie)
		} else {
			require.NoError(t, xErr)
			require.NoError(t, yErr)
		}
		require.Equal(t, xBytes, yBytes, "native guardian storage")
	}
}

func qualNativeGuardianSentinels(t *testing.T, c *vm.VMTestContext, sentinels map[string][]byte, install bool) {
	t.Helper()
	if install {
		a, err := c.Accounts.LoadAccount(core.SystemAccountAddress)
		require.NoError(t, err)
		u, ok := a.(state.UserAccountHandler)
		require.True(t, ok)
		for key, value := range sentinels {
			require.NoError(t, u.SaveKeyValue([]byte(key), bytes.Clone(value)))
		}
		require.NoError(t, c.Accounts.SaveAccount(u))
		return
	}
	u := qualNativeGuardianAccount(t, c, core.SystemAccountAddress)
	for key, value := range sentinels {
		actual, _, err := u.RetrieveValue([]byte(key))
		require.NoError(t, err)
		require.Equal(t, value, actual, "native guardian path must preserve every sentinel")
	}
}
