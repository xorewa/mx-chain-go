package drwa

import (
	"bytes"
	"errors"
	"testing"

	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestQualDRWAScopedInstallMandatesReadOnly(t *testing.T) {
	for _, operation := range []string{"ENROLL", "SUCCESSOR", "initial-pair", "owned-initial-pair"} {
		faults := []string{"unrelated", "same-value", "aba", "other-store", "verifier-error", "native-error"}
		if operation == "owned-initial-pair" {
			faults = append(faults, "rollback-poison")
		}
		for _, fault := range faults {
			t.Run(operation+"/"+fault, func(t *testing.T) {
				f, run, writes, mandates := qualScopedInstallMandateOperation(t, operation)
				other := qualRegistrationStore(t, 0)
				reader := &rootReadFault{AccountsAdapter: other}
				var err error
				f.boundary, err = NewRollbackContainment(f.store, reader)
				require.NoError(t, err)
				f.records.boundary = f.boundary
				if operation == "SUCCESSOR" {
					f.enroll(t)
				}

				key := []byte("fixture/unrelated-prior-operation")
				value := []byte("retained lawful fixture value")
				require.NoError(t, f.boundary.Execute(func() (*vmcommon.VMOutput, error) {
					qualRecordPut(t, f.store, key, value)
					qualRecordPut(t, other, key, value)
					return nil, nil
				}))
				poison := errors.New("synthetic second store rollback error")
				if fault == "rollback-poison" {
					_, _, err = f.boundary.Commit()
					require.NoError(t, err)
					f.boundary, err = NewRollbackContainment(f.store, reader)
					require.NoError(t, err)
					f.records.boundary = f.boundary
					other.revertErr = poison
				}
				original := qualSnapshotScopedAdmission(t, f)
				originalWrites := make([][]byte, len(writes))
				for i, w := range writes {
					originalWrites[i] = bytes.Clone(qualRegistryValue(t, f.store, string(w.key)))
				}
				otherRoot, err := other.RootHash()
				require.NoError(t, err)
				otherJournal := other.JournalLen()
				calls := f.mandates.calls
				target := 1
				if mandates == 2 && fault == "other-store" {
					target = 2
				}
				f.mandates.hook = func() {
					if f.mandates.calls != calls+target {
						return
					}
					switch fault {
					case "unrelated", "verifier-error":
						qualRecordPut(t, f.store, key, []byte("injected verifier write"))
					case "same-value", "aba":
						before, e := f.store.RootHash()
						require.NoError(t, e)
						journal := f.store.JournalLen()
						if fault == "aba" {
							qualRecordPut(t, f.store, key, []byte("transient verifier write"))
						}
						qualRecordPut(t, f.store, key, value)
						after, e := f.store.RootHash()
						require.NoError(t, e)
						require.Equal(t, before, after)
						require.Greater(t, f.store.JournalLen(), journal)
					case "other-store", "rollback-poison":
						qualRecordPut(t, other, key, []byte("injected write in second owned store"))
					}
				}
				want := errScopedAdmission
				if fault == "verifier-error" {
					want = errInvalidRegistrationRecord
					f.records.mandates = qualScopedMandateFailure{f.mandates, want}
				}
				if fault == "native-error" {
					want = errInvalidRegistrationRecord
					reader.at, reader.failure = reader.calls+2, want
				}
				err = run()
				require.ErrorIs(t, err, want)
				require.Equal(t, calls+target, f.mandates.calls)
				if fault == "rollback-poison" {
					require.ErrorIs(t, err, poison)
					roots, outputs, commitErr := f.boundary.Commit()
					require.ErrorIs(t, commitErr, want)
					require.ErrorIs(t, commitErr, poison)
					require.Empty(t, roots)
					require.Empty(t, outputs)
					require.ErrorIs(t, run(), poison, "the poisoned owner cannot start a healthy retry")
					other.revertErr = nil
					require.NoError(t, f.boundary.Recover())
				}
				require.Equal(t, original, qualSnapshotScopedAdmission(t, f))
				for i, w := range writes {
					require.Equal(t, originalWrites[i], qualRegistryValue(t, f.store, string(w.key)))
				}
				afterOther, err := other.RootHash()
				require.NoError(t, err)
				require.Equal(t, otherRoot, afterOther)
				require.Equal(t, otherJournal, other.JournalLen())
				require.Equal(t, value, qualRegistryValue(t, f.store, string(key)))
				require.Equal(t, value, qualRegistryValue(t, other, string(key)))
				require.Empty(t, qualRegistryValue(t, f.store, "fixture/owned-pair-prior-write"))

				if fault == "rollback-poison" {
					f.boundary, err = NewRollbackContainment(f.store, reader)
					require.NoError(t, err)
					f.records.boundary = f.boundary
				}
				f.mandates.hook = nil
				f.records.mandates = f.mandates
				reader.at = 0
				calls = f.mandates.calls
				require.NoError(t, run())
				require.Equal(t, calls+mandates, f.mandates.calls)
				for _, w := range writes {
					require.Equal(t, w.value, qualRegistryValue(t, f.store, string(w.key)))
				}
				require.NotEqual(t, original.budget, qualRegistryValue(t, f.store, scopedAdmissionPrefix+"budget"))
				require.Equal(t, value, qualRegistryValue(t, f.store, string(key)))
				require.Equal(t, value, qualRegistryValue(t, other, string(key)))
			})
		}
	}
}

func qualScopedInstallMandateOperation(t *testing.T, operation string) (*qualScopedFixture, func() error, []scopedAdmissionWrite, int) {
	t.Helper()
	if operation == "ENROLL" || operation == "SUCCESSOR" {
		f := qualScopedNew(t)
		var predecessor []byte
		if operation == "SUCCESSOR" {
			predecessor = f.d.authority
		}
		id := qualScopedHash("VERSION", f.scope, predecessor, f.versionBody)
		proof := f.mandates.proof(operation, predecessor, id)
		scopeID := qualScopedHash("SCOPE", f.scope)
		writes := []scopedAdmissionWrite{
			{f.records.key("version", id), qualRecordFrame(f.scope, predecessor, f.versionBody)},
			{f.records.key("current", scopeID), qualRecordFrame(f.scope, id)},
		}
		return f, func() error {
			return f.records.install(f.context, f.d.owner, f.d.program, predecessor, f.versionBody, proof)
		}, writes, 1
	}
	f, g, args, proofs, bodies, approval := qualInitialPair(t)
	run := func() error { return qualInitialInstall(f, g, args, proofs, bodies, approval) }
	if operation == "owned-initial-pair" {
		run = func() error {
			return f.boundary.executeOwned(func(owner *rollbackOperation) ([]*vmcommon.VMOutput, error) {
				qualRecordPut(t, f.store, []byte("fixture/owned-pair-prior-write"), []byte("earlier in original operation"))
				// The native owner must still veto commitment if the caller drops the inner error.
				_ = f.records.installInitialPurposePairOwned(owner, f.context, f.d.owner, g, args, proofs, bodies, approval,
					[]byte("admission\x00opaque"), []byte("independent\xc3\xa9"))
				return nil, nil
			})
		}
	}
	return f, run, qualInitialWrites(t, f), 2
}
