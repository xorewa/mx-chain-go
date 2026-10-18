package drwa

// FA-01 RT-01: clause-derived negative component cases (F05/E09, scoped
// uniqueness and E10). Existing experimental fixture values are reused, not
// production allocations. No remote authority, new profile or wire is admitted.

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/integrationTests"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestQualFA01ConsentExactArity(t *testing.T) {
	ctx := qualConsentContext(t)
	c, _ := qualConsentInstall(t, ctx, 0)
	s := qualConsentScope()
	fields := [][]byte{s.Domain, s.Token, s.Program, s.Target, s.Roles, s.Address}
	for _, n := range []int{5, 6, 7} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			args := append([][]byte(nil), fields...)
			if n < len(args) {
				args = args[:n]
			}
			if n > len(args) {
				args = append(args, s.Roles)
			}
			_, err := c.scope(&vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: s.Address, Arguments: args}})
			if n == len(fields) {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrPrivilegedConsent)
			}
		})
	}
}

func TestQualFA01ConsentMissingDispatch(t *testing.T) {
	ctx := qualConsentContext(t)
	c, owner := qualConsentInstall(t, ctx, 0)
	tx := qualConsentTx(t, ctx, qualConsentData(qualConsentScope()), nil)
	// The native pipeline executes an ordinary self transfer, so it returns Ok
	// without staging the consent builtin. The candidate must return its error,
	// not dereference a missing pending account. Capture a mutant panic as data
	// so the missing guard is caught by an assertion, never a crashing test.
	processor := &qualConsentProcessor{TransactionProcessor: ctx.TxProcessor, run: func(tx *transaction.Transaction) (vmcommon.ReturnCode, error) {
		ordinary := *tx
		ordinary.Data = nil
		return ctx.TxProcessor.ProcessTransaction(&ordinary)
	}}
	var code vmcommon.ReturnCode
	var err error
	var recovered interface{}
	func() {
		defer func() { recovered = recover() }()
		code, err = c.ExecuteNativeTransaction(tx, processor, ctx.Marshalizer, integrationTests.TestHasher)
	}()
	require.Nil(t, recovered, "missing dispatch must return a refusal")
	require.Equal(t, vmcommon.ExecutionFailed, code)
	require.ErrorIs(t, err, ErrPrivilegedConsent)
	require.False(t, c.executing)
	require.Empty(t, qualConsentValue(t, ctx))
	_, outputs, err := owner.Commit()
	require.NoError(t, err)
	require.Empty(t, outputs)
}

func TestQualFA01ScopedAdmissionOwnedStore(t *testing.T) {
	f := qualScopedNew(t)
	other := qualScopedNew(t)
	for _, own := range []bool{true, false} {
		t.Run(fmt.Sprint(own), func(t *testing.T) {
			boundary := f.boundary
			if !own {
				boundary = other.boundary
			}
			records, err := newScopedAdmissionRecords(f.store, boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(),
				f.records.domain, f.records.limits, f.mandates, qualClockSource(f.clock, f.store))
			if own {
				require.NoError(t, err)
				require.NotNil(t, records)
			} else {
				require.ErrorIs(t, err, errScopedAdmission)
				require.Nil(t, records)
			}
		})
	}
}

func TestQualFA01ScopedAdmissionSingleEnrollment(t *testing.T) {
	f := qualScopedNew(t)
	f.enroll(t)
	// Exact replay is idempotent; a differently signed ENROLL for this same
	// owner/programme is not a SUCCESSOR and must not replace the current version.
	before, err := f.store.RootHash()
	require.NoError(t, err)
	f.enroll(t)
	replay, err := f.store.RootHash()
	require.NoError(t, err)
	require.Equal(t, before, replay)
	body := append(bytes.Clone(f.versionBody), f.versionBody...)
	id := qualScopedHash("VERSION", f.scope, nil, body)
	require.NotEqual(t, f.d.authority, id)
	proof := f.mandates.proof("ENROLL", nil, id)
	require.ErrorIs(t, f.records.install(f.context, f.d.owner, f.d.program, nil, body, proof), errScopedAdmission)
	after, err := f.store.RootHash()
	require.NoError(t, err)
	require.Equal(t, before, after, "a second enrollment changes neither pointer nor retained budget")
}

func TestQualFA01BurnNormalizationRequiresClassification(t *testing.T) {
	for _, auto := range []bool{false, true} {
		for _, install := range []bool{false, true} {
			t.Run(fmt.Sprintf("auto_%t/install_%t", auto, install), func(t *testing.T) {
				f := qualBurnFixtureFor(t, auto, core.FungibleESDT, "unclassified-registration", []byte{4, 0})
				qualBurnPrepare(t, f)
				classified, err := f.b.material.classify(f.b.material.required.candidateHash, f.id)
				require.NoError(t, err)
				require.False(t, classified)
				// All later registration proof checks succeed at this same source root.
				// This isolates the classifier refusal, unlike the old wrong-token case.
				_, err = f.b.authenticateRegistration(f.id, f.w)
				require.NoError(t, err)
				if install {
					f.args.EnableEpochsHandler.(vmcommon.EpochSubscriberHandler).EpochConfirmed(7, 0)
				}
				before, err := f.db.RootHash()
				require.NoError(t, err)
				journal := f.db.JournalLen()
				if install {
					err = f.b.MaterializeRegistration(f.id, f.w)
				} else {
					err = f.b.Normalize(f.id, f.w)
				}
				require.ErrorIs(t, err, errInvalidRegistrationRecord)
				after, err := f.db.RootHash()
				require.NoError(t, err)
				require.Equal(t, before, after)
				require.Equal(t, journal, f.db.JournalLen())
				require.Equal(t, []byte{4, 0}, qualBurnValue(t, f.db, f.id))
			})
		}
	}
}
