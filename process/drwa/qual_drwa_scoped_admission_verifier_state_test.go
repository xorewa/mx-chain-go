package drwa

import (
	"bytes"
	"encoding/binary"
	"testing"

	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type qualScopedAdmissionSnapshot struct {
	root, budget, decision, withdrawn []byte
	journal                           int
}

func qualSnapshotScopedAdmission(t *testing.T, f *qualScopedFixture) qualScopedAdmissionSnapshot {
	t.Helper()
	root, err := f.store.RootHash()
	require.NoError(t, err)
	return qualScopedAdmissionSnapshot{
		root:      bytes.Clone(root),
		budget:    bytes.Clone(qualRegistryValue(t, f.store, scopedAdmissionPrefix+"budget")),
		decision:  bytes.Clone(qualRegistryValue(t, f.store, scopedAdmissionPrefix+"decision@"+string(f.id()))),
		withdrawn: bytes.Clone(qualRegistryValue(t, f.store, scopedAdmissionPrefix+"withdrawn@"+string(f.id()))),
		journal:   f.store.JournalLen(),
	}
}

type qualScopedMandateFailure struct {
	scopedAdmissionMandates
	err error
}

func (m qualScopedMandateFailure) Verify(purpose string, scope, predecessor, digest, evidence []byte) error {
	if err := m.scopedAdmissionMandates.Verify(purpose, scope, predecessor, digest, evidence); err != nil {
		return err
	}
	return m.err
}

func TestQualDRWAScopedAdmissionVerifierPreservesPriorState(t *testing.T) {
	for _, operation := range []string{"ADMISSION", "WITHDRAW"} {
		for _, fault := range []string{"overwrite", "same-value", "aba", "other-store", "verifier-error", "root-error"} {
			t.Run(operation+"/"+fault, func(t *testing.T) {
				f := qualScopedNew(t)
				other := qualRegistrationStore(t, 0)
				read := &rootReadFault{AccountsAdapter: other}
				var err error
				f.boundary, err = NewRollbackContainment(f.store, read)
				require.NoError(t, err)
				f.records.boundary = f.boundary
				f.enroll(t)
				proof := f.mandates.proof("ADMISSION", f.d.authority, qualScopedHash("ADMISSION", f.body()))
				run := func() error { return f.records.admit(f.context, f.d, proof) }
				if operation == "WITHDRAW" {
					f.admit(t)
					proof = f.withdrawProof()
					run = func() error { return f.records.withdraw(f.context, f.d, proof) }
				}

				key := []byte("fixture/prior-lawful-state")
				value := []byte("retained before verification")
				require.NoError(t, f.boundary.Execute(func() (*vmcommon.VMOutput, error) {
					qualRecordPut(t, f.store, key, value)
					qualRecordPut(t, other, key, value)
					return nil, nil
				}))
				original := qualSnapshotScopedAdmission(t, f)
				otherRoot, err := other.RootHash()
				require.NoError(t, err)
				otherJournal := other.JournalLen()
				calls := f.mandates.calls

				want := errScopedAdmission
				f.mandates.hook = func() {
					switch fault {
					case "overwrite", "verifier-error":
						qualRecordPut(t, f.store, key, []byte("injected verifier write"))
					case "same-value":
						qualRecordPut(t, f.store, key, value)
					case "aba":
						qualRecordPut(t, f.store, key, []byte("transient verifier write"))
						qualRecordPut(t, f.store, key, value)
					case "other-store":
						qualRecordPut(t, other, key, []byte("injected verifier write in second store"))
					}
					if fault == "same-value" || fault == "aba" {
						root, rootErr := f.store.RootHash()
						require.NoError(t, rootErr)
						require.Equal(t, original.root, root)
						require.Greater(t, f.store.JournalLen(), original.journal)
					}
				}
				if fault == "verifier-error" {
					want = errInvalidRegistrationRecord
					f.records.mandates = qualScopedMandateFailure{f.mandates, want}
				}
				if fault == "root-error" {
					want = errInvalidRegistrationRecord
					read.at, read.failure = read.calls+2, want
				}
				require.ErrorIs(t, run(), want)
				require.Equal(t, calls+1, f.mandates.calls)
				require.Equal(t, original, qualSnapshotScopedAdmission(t, f))
				require.Equal(t, otherJournal, other.JournalLen())
				after, err := other.RootHash()
				require.NoError(t, err)
				require.Equal(t, otherRoot, after)
				require.Equal(t, value, qualRegistryValue(t, f.store, string(key)))
				require.Equal(t, value, qualRegistryValue(t, other, string(key)))

				f.records.mandates = f.mandates
				f.mandates.hook = nil
				read.at = 0
				require.NoError(t, run(), "the same signed mandate can execute without a verifier side effect")
				committed := qualSnapshotScopedAdmission(t, f)
				if operation == "WITHDRAW" {
					require.Equal(t, f.body(), committed.withdrawn)
					require.ErrorIs(t, f.checkDecision(f.context, f.d), errScopedAdmission)
				} else {
					require.Equal(t, f.body(), committed.decision)
					require.NoError(t, f.checkDecision(f.context, f.d))
				}
			})
		}
	}
}

// Model06: the deliberately mutating verifier is a hostile synthetic adapter,
// not an appointed authority or canonical producer. Native storage and the
// operation's shared rollback journal are real. No native ingress is installed.
func TestQualDRWAScopedAdmissionVerifierState(t *testing.T) {
	for _, operation := range []string{"ENROLL", "ADMISSION", "WITHDRAW"} {
		faults := []string{"healthy", "budget"}
		if operation == "ADMISSION" {
			faults = append(faults, "current", "version")
		}
		if operation == "WITHDRAW" {
			faults = append(faults, "current", "decision")
		}
		for _, fault := range faults {
			t.Run(operation+"/"+fault, func(t *testing.T) {
				f := qualScopedNew(t)
				if operation != "ENROLL" {
					f.enroll(t)
				}
				if operation == "WITHDRAW" {
					f.admit(t)
				}
				proof := f.mandates.proof("ENROLL", nil, f.d.authority)
				if operation == "ADMISSION" {
					proof = f.mandates.proof(operation, f.d.authority, qualScopedHash("ADMISSION", f.body()))
				}
				if operation == "WITHDRAW" {
					proof = f.withdrawProof()
				}
				before, err := f.store.RootHash()
				require.NoError(t, err)
				journal := f.store.JournalLen()
				calls := f.mandates.calls
				f.mandates.hook = func() {
					switch fault {
					case "current":
						body := []byte("synthetic successor installed inside verifier")
						next := qualScopedHash("VERSION", f.scope, f.d.authority, body)
						qualRecordPut(t, f.store, f.records.key("version", next), qualRecordFrame(f.scope, f.d.authority, body))
						qualRecordPut(t, f.store, f.records.key("current", qualScopedHash("SCOPE", f.scope)), qualRecordFrame(f.scope, next))
					case "version":
						qualRecordPut(t, f.store, f.records.key("version", f.d.authority), []byte("malformed immutable version"))
					case "decision":
						qualRecordPut(t, f.store, f.records.key("decision", f.id()), []byte("conflicting immutable decision"))
					case "budget":
						budget := make([]byte, 32)
						binary.BigEndian.PutUint64(budget, f.records.limits.records)
						binary.BigEndian.PutUint64(budget[8:], uint64(len(scopedAdmissionPrefix+"budget")+32))
						qualRecordPut(t, f.store, []byte(scopedAdmissionPrefix+"budget"), budget)
					}
				}
				switch operation {
				case "ENROLL":
					err = f.records.install(f.context, f.d.owner, f.d.program, nil, f.versionBody, proof)
				case "ADMISSION":
					err = f.records.admit(f.context, f.d, proof)
				case "WITHDRAW":
					err = f.records.withdraw(f.context, f.d, proof)
				}
				require.Equal(t, calls+1, f.mandates.calls, "test must enter the genuine verifier boundary")
				if fault == "healthy" {
					require.NoError(t, err)
					return
				}
				require.ErrorIs(t, err, errScopedAdmission, "prior state cannot authorize the post-verifier write")
				after, err := f.store.RootHash()
				require.NoError(t, err)
				require.Equal(t, before, after, "rollback includes the verifier-side mutation")
				require.Equal(t, journal, f.store.JournalLen())
			})
		}
	}
}
