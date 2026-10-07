package drwa

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/integrationTests"
	"github.com/multiversx/mx-chain-go/integrationTests/vm"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Explicit admission-owner input fixtures only. These do not simulate or prove
// bootstrap admission, token-to-intent transport or programme authorisation.
type qualConsentReferences struct {
	programs map[string][]byte
	err      error
}

func (r *qualConsentReferences) AdmittedProgram(token []byte) ([]byte, error) {
	return bytes.Clone(r.programs[string(token)]), r.err
}
func (r *qualConsentReferences) IsInterfaceNil() bool { return r == nil }

func qualConsentReferenceFixture() *qualConsentReferences {
	return &qualConsentReferences{programs: map[string][]byte{
		"TOKEN-fixture": []byte("fixture-program"),
		"TOKEN-second":  []byte("fixture-second-program"),
	}}
}

func qualConsentSeedMembership(t *testing.T, accounts state.AccountsAdapter) {
	t.Helper()
	a, err := accounts.LoadAccount(bytes.Clone(core.SystemAccountAddress))
	require.NoError(t, err)
	u := a.(state.UserAccountHandler)
	require.NoError(t, u.SaveKeyValue([]byte(localMembershipCountKey), make([]byte, 8)))
	require.NoError(t, accounts.SaveAccount(u))
	store := &protectedState{accounts: accounts}
	for _, token := range []string{"TOKEN-fixture", "TOKEN-second"} {
		require.NoError(t, store.materializeMembership([]byte(token)))
	}
	_, err = accounts.Commit()
	require.NoError(t, err)
}

func qualConsentScopedValue(t *testing.T, accounts state.AccountsAdapter, s PrivilegedConsentScope) []byte {
	t.Helper()
	a, err := accounts.GetExistingAccount(bytes.Clone(core.SystemAccountAddress))
	require.NoError(t, err)
	value, _, _ := a.(state.UserAccountHandler).RetrieveValue(privilegedConsentRecordKey(s.Address, s.Token, s.Program))
	return value
}

func TestQualDRWAPrivilegedConsentKeyFraming(t *testing.T) {
	key := privilegedConsentRecordKey([]byte("a"), []byte("b"), []byte("c"))
	require.Equal(t, "ELRONDDRWA@privilegedConsent@record@", privilegedConsentRecordPrefix)
	require.Equal(t, "000000000000000161000000000000000162000000000000000163", hex.EncodeToString(key[len(privilegedConsentRecordPrefix):]))
	require.NotEqual(t, privilegedConsentRecordKey([]byte("ab"), []byte("c"), []byte("d")), privilegedConsentRecordKey([]byte("a"), []byte("bc"), []byte("d")))
	for _, prefix := range []string{membershipKeyPrefix, registryMemberKeyPrefix, registryCountKey, localMembershipCountKey, localMembershipEntryPrefix} {
		require.False(t, bytes.HasPrefix(key, []byte(prefix)))
		require.False(t, bytes.HasPrefix([]byte(prefix), []byte(privilegedConsentRecordPrefix)))
	}
}

func TestQualDRWAPrivilegedConsentScopedRetention(t *testing.T) {
	ctx := qualConsentContext(t)
	c, owner := qualConsentInstall(t, ctx, 0)
	first := qualConsentScope()
	qualConsentProcess(t, ctx, qualConsentData(first), nil)
	_, _, err := owner.Commit()
	require.NoError(t, err)
	firstBytes := qualConsentScopedValue(t, ctx.Accounts, first)
	oldH, oldW, oldBudget := qualConsentWitnessScope(t, ctx, 0, first)
	c, owner = qualConsentInstall(t, ctx, 0)
	second := first
	second.Token, second.Program = []byte("TOKEN-second"), []byte("fixture-second-program")
	qualConsentProcess(t, ctx, qualConsentData(second), nil)
	_, _, err = owner.Commit()
	require.NoError(t, err)
	require.Equal(t, firstBytes, qualConsentScopedValue(t, ctx.Accounts, first), "another token must not overwrite this retained record")
	require.Equal(t, encodeExperimentalConsent(second, 2, 0), qualConsentScopedValue(t, ctx.Accounts, second))
	h, w, budget := qualConsentWitnessScope(t, ctx, 0, second)
	r := qualConsentReader(t, ctx)
	require.NoError(t, c.ReadEvidence(r, h, 1, second, w, budget))
	// Physical retention does not waive native nonce/epoch freshness. The
	// historical first observation remains valid only for that selected root.
	h1, w1, b1 := qualConsentWitnessScope(t, ctx, 0, first)
	require.Error(t, c.ReadEvidence(r, h1, 1, first, w1, b1))
	require.NoError(t, c.ReadEvidence(r, oldH, 1, first, oldW, oldBudget))
	for _, scope := range []PrivilegedConsentScope{first, second} {
		a, e := ctx.Accounts.GetExistingAccount(scope.Address)
		require.NoError(t, e)
		v, _, _ := a.(state.UserAccountHandler).RetrieveValue(privilegedConsentRecordKey(scope.Address, scope.Token, scope.Program))
		require.Empty(t, v, "the EOA data trie is not the consent locus")
	}
	// A second actual EOA gets a separate record for the same token/programme.
	other := first
	other.Address = bytes.Repeat([]byte{0x33}, 32)
	a, err := ctx.Accounts.LoadAccount(other.Address)
	require.NoError(t, err)
	require.NoError(t, a.(state.UserAccountHandler).AddToBalance(big.NewInt(1000000000)))
	require.NoError(t, ctx.Accounts.SaveAccount(a))
	c, owner = qualConsentInstall(t, ctx, 0)
	tx := vm.CreateTransaction(0, big.NewInt(0), other.Address, other.Address, 1, 1000000, qualConsentData(other))
	code, err := c.ExecuteNativeTransaction(tx, ctx.TxProcessor, ctx.Marshalizer, integrationTests.TestHasher)
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, code)
	_, _, err = owner.Commit()
	require.NoError(t, err)
	require.Equal(t, encodeExperimentalConsent(other, 1, 0), qualConsentScopedValue(t, ctx.Accounts, other))
	require.Equal(t, firstBytes, qualConsentScopedValue(t, ctx.Accounts, first))
	h, w, budget = qualConsentWitnessScope(t, ctx, 0, other)
	require.NoError(t, c.ReadEvidence(r, h, 1, other, w, budget))
}

type qualConsentMembershipReadFailure struct {
	state.UserAccountHandler
	failure error
}

func (a *qualConsentMembershipReadFailure) RetrieveValue(key []byte) ([]byte, uint32, error) {
	v, depth, err := a.UserAccountHandler.RetrieveValue(key)
	if err != nil {
		return v, depth, err
	}
	return v, depth, a.failure
}

func TestQualDRWAPrivilegedConsentAdmissionReference(t *testing.T) {
	for _, name := range []string{"unregistered_token", "wrong_program", "missing_reference", "reference_error", "membership_error", "malformed_membership"} {
		t.Run(name, func(t *testing.T) {
			ctx := qualConsentContext(t)
			c, owner := qualConsentInstall(t, ctx, 0)
			s := qualConsentScope()
			failure := errors.New("qualification admission reference failure")
			switch name {
			case "unregistered_token":
				s.Token = []byte("unregistered fixture token")
				c.references.(*qualConsentReferences).programs[string(s.Token)] = s.Program
			case "wrong_program":
				s.Program = []byte("caller-selected programme")
			case "missing_reference":
				delete(c.references.(*qualConsentReferences).programs, string(s.Token))
			case "reference_error":
				c.references.(*qualConsentReferences).err = failure
			case "membership_error":
				c.accounts = &qualConsentFinalAccounts{ctx.Accounts, func(a vmcommon.AccountHandler) (vmcommon.AccountHandler, error) {
					return &qualConsentMembershipReadFailure{a.(state.UserAccountHandler), failure}, nil
				}}
			case "malformed_membership":
				a, err := ctx.Accounts.GetExistingAccount(core.SystemAccountAddress)
				require.NoError(t, err)
				key, err := membershipKey(s.Token)
				require.NoError(t, err)
				require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue(key, []byte{2}))
				require.NoError(t, ctx.Accounts.SaveAccount(a))
			}
			tx := qualConsentTx(t, ctx, qualConsentData(s), nil)
			code, _ := c.ExecuteNativeTransaction(tx, ctx.TxProcessor, ctx.Marshalizer, integrationTests.TestHasher)
			require.NotEqual(t, vmcommon.Ok, code)
			require.Empty(t, qualConsentScopedValue(t, ctx.Accounts, s))
			// Isolate the builtin admission guard from the separate final
			// persistence recheck. This is component denial evidence only;
			// native authentication is exercised by the transaction above.
			a, err := ctx.Accounts.GetExistingAccount(s.Address)
			require.NoError(t, err)
			c.executing, c.expectedHash = true, []byte("qualified native dispatch boundary")
			input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: s.Address,
				Arguments: [][]byte{s.Domain, s.Token, s.Program, s.Target, s.Roles, s.Address},
				CallValue: big.NewInt(0), GasProvided: 10, CurrentTxHash: bytes.Clone(c.expectedHash)},
				RecipientAddr: s.Address, Function: ExperimentalPrivilegedConsentEndpoint}
			builtinOutput, err := c.ProcessBuiltinFunction(a.(vmcommon.UserAccountHandler), nil, input)
			require.ErrorIs(t, err, ErrPrivilegedConsent)
			require.Nil(t, builtinOutput)
			c.executing, c.expectedHash = false, nil
			_, out, err := owner.Commit()
			require.NoError(t, err)
			for _, output := range out {
				require.Nil(t, output)
			}
		})
	}
}

func TestQualDRWAPrivilegedConsentFinalAdmissionReference(t *testing.T) {
	for _, name := range []string{"reference_error", "reference_removed", "membership_removed", "system_reload_error"} {
		t.Run(name, func(t *testing.T) {
			ctx := qualConsentContext(t)
			c, owner := qualConsentInstall(t, ctx, 0)
			s := qualConsentScope()
			failure := errors.New("qualification final reference boundary")
			processor := &qualConsentProcessor{TransactionProcessor: ctx.TxProcessor, run: func(tx *transaction.Transaction) (vmcommon.ReturnCode, error) {
				code, err := ctx.TxProcessor.ProcessTransaction(tx)
				require.NoError(t, err)
				require.Equal(t, vmcommon.Ok, code)
				switch name {
				case "reference_error":
					c.references.(*qualConsentReferences).err = failure
				case "reference_removed":
					delete(c.references.(*qualConsentReferences).programs, string(s.Token))
				case "membership_removed":
					a, e := ctx.Accounts.GetExistingAccount(core.SystemAccountAddress)
					require.NoError(t, e)
					key, e := membershipKey(s.Token)
					require.NoError(t, e)
					require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue(key, nil))
					require.NoError(t, ctx.Accounts.SaveAccount(a))
				case "system_reload_error":
					calls := 0
					c.accounts = &qualConsentFinalAccounts{ctx.Accounts, func(a vmcommon.AccountHandler) (vmcommon.AccountHandler, error) {
						if bytes.Equal(a.AddressBytes(), core.SystemAccountAddress) {
							calls++
							if calls == 2 {
								return nil, failure
							}
						}
						return a, nil
					}}
				}
				return code, err
			}}
			code, err := c.ExecuteNativeTransaction(qualConsentTx(t, ctx, qualConsentData(s), nil), processor, ctx.Marshalizer, integrationTests.TestHasher)
			require.Equal(t, vmcommon.ExecutionFailed, code)
			if name == "system_reload_error" {
				require.ErrorIs(t, err, failure)
			} else {
				require.ErrorIs(t, err, ErrPrivilegedConsent)
			}
			require.Empty(t, qualConsentScopedValue(t, ctx.Accounts, s))
			_, out, err := owner.Commit()
			require.NoError(t, err)
			require.Empty(t, out)
		})
	}
}
