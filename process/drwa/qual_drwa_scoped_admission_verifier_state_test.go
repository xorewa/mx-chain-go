package drwa

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

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
