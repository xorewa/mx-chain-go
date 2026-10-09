package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/stretchr/testify/require"
)

// T13 model03, DEVELOPMENT ONLY. The existing trusted SUCCESSOR fixture
// assumes lawful succession; it is not actual C02 recovery evidence or a
// successor-possession verifier. Current rosters/mandates are explicit synthetic
// inputs. Native signatures, protected storage and journal rollback are real.
func qualScopedSuccessors(t *testing.T, f *qualScopedFixture, count int) []byte {
	t.Helper()
	current := bytes.Clone(f.d.authority)
	for n := 1; n <= count; n++ {
		body := []byte(fmt.Sprintf("explicit synthetic successor %d", n))
		next := qualScopedHash("VERSION", f.scope, current, body)
		// The pre-established synthetic SUCCESSOR purpose is distinct from
		// admission. The unavailable old admission roster supplies no signature.
		require.NoError(t, f.records.install(f.context, f.d.owner, f.d.program, current, body,
			f.mandates.proof("SUCCESSOR", current, next)))
		role := w03SignatureProof(t, 5, 3, []uint64{0, 1, 2})
		require.NotEqual(t, f.mandates.roles["ADMISSION"].members, role.members)
		f.mandates.roles["ADMISSION"] = role
		// Explicit separate WITHDRAW mandate on the same current roster.
		f.mandates.roles["WITHDRAW"] = role
		current = next
	}
	return current
}

func qualScopedCurrentWithdrawal(f *qualScopedFixture, current []byte) []byte {
	return f.mandates.proof("WITHDRAW", current,
		qualScopedHash("WITHDRAW", f.scope, f.id(), f.body(), current))
}

func TestQualDRWAScopedAdmissionSuccessorWithdrawal(t *testing.T) {
	for _, successionCount := range []int{1, 2} {
		for _, fault := range []string{"none", "old-coordinate", "old-roster-current-message", "admission-purpose", "missing-mandate", "bad-signature", "save"} {
			t.Run(fmt.Sprintf("successors_%d/%s", successionCount, fault), func(t *testing.T) {
				f := qualScopedNew(t)
				f.enroll(t)
				f.admit(t)
				require.NoError(t, f.records.checkDecision(f.context, f.d))
				oldProof, oldRole := f.withdrawProof(), f.mandates.roles["WITHDRAW"]
				current := qualScopedSuccessors(t, f, successionCount)
				require.Error(t, f.records.checkDecision(f.context, f.d), "old admission is stale before any withdrawal")
				other := f.d
				other.version, other.authority = []byte("unrelated-current-decision"), current
				otherBody := qualRecordFrame(f.scope, other.issuer, other.version, other.commitment, current,
					binary.BigEndian.AppendUint64(nil, uint64(other.validUntil)))
				require.NoError(t, f.records.admit(f.context, other,
					f.mandates.proof("ADMISSION", current, qualScopedHash("ADMISSION", otherBody))))
				require.NoError(t, f.records.checkDecision(f.context, other))
				proof := qualScopedCurrentWithdrawal(f, current)
				withdrawDigest := qualScopedHash("WITHDRAW", f.scope, f.id(), f.body(), current)
				currentMandate := f.mandates.roles["WITHDRAW"]
				nativeFault := errors.New("successor withdrawal native save fault")
				switch fault {
				case "old-coordinate":
					proof = oldProof
				case "old-roster-current-message":
					oldRole.digest = qualScopedHash("MANDATE", []byte("WITHDRAW"), f.scope, current, withdrawDigest)
					oldRole.sign(t)
					proof = qualRecordFrame(oldRole.signatures...)
				case "admission-purpose":
					proof = f.mandates.proof("ADMISSION", current, withdrawDigest)
				case "missing-mandate":
					delete(f.mandates.roles, "WITHDRAW")
				case "bad-signature":
					proof[len(proof)-1] ^= 1
				case "save":
					f.store.saveErr = nativeFault
				}
				before, err := f.store.RootHash()
				require.NoError(t, err)
				journal := f.store.JournalLen()
				budget := qualRegistryValue(t, f.store, scopedAdmissionPrefix+"budget")
				if fault != "none" {
					err = f.records.withdraw(f.context, f.d, proof)
					require.Error(t, err)
					if fault == "save" {
						require.ErrorIs(t, err, nativeFault)
					}
					after, e := f.store.RootHash()
					require.NoError(t, e)
					require.Equal(t, before, after)
					require.Equal(t, journal, f.store.JournalLen())
					require.Equal(t, budget, qualRegistryValue(t, f.store, scopedAdmissionPrefix+"budget"))
					require.Empty(t, qualRegistryValue(t, f.store, scopedAdmissionPrefix+"withdrawn@"+string(f.id())))
					require.NoError(t, f.records.checkDecision(f.context, other))
					f.store.saveErr = nil
					f.mandates.roles["WITHDRAW"] = currentMandate
				}
				require.NoError(t, f.records.withdraw(f.context, f.d, qualScopedCurrentWithdrawal(f, current)))
				require.Equal(t, f.body(), qualRegistryValue(t, f.store, scopedAdmissionPrefix+"decision@"+string(f.id())))
				require.Equal(t, f.body(), qualRegistryValue(t, f.store, scopedAdmissionPrefix+"withdrawn@"+string(f.id())))
				require.Equal(t, uint64(6+successionCount), binary.BigEndian.Uint64(qualRegistryValue(t, f.store, scopedAdmissionPrefix+"budget")))
				require.NoError(t, f.records.checkDecision(f.context, other))
				roots, _, err := f.boundary.Commit()
				require.NoError(t, err)
				require.NoError(t, f.store.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
				f.boundary, err = NewRollbackContainment(f.store)
				require.NoError(t, err)
				f.records.boundary = f.boundary
				require.Equal(t, f.body(), qualRegistryValue(t, f.store, scopedAdmissionPrefix+"withdrawn@"+string(f.id())))
				require.NoError(t, f.records.checkDecision(f.context, other))
				journal = f.store.JournalLen()
				budget = qualRegistryValue(t, f.store, scopedAdmissionPrefix+"budget")
				require.NoError(t, f.records.withdraw(f.context, f.d, qualScopedCurrentWithdrawal(f, current)))
				f.enroll(t) // retained enrollment cannot move the pointer backward
				require.Equal(t, journal, f.store.JournalLen())
				require.Equal(t, budget, qualRegistryValue(t, f.store, scopedAdmissionPrefix+"budget"))
				after, err := f.store.RootHash()
				require.NoError(t, err)
				require.Equal(t, roots[0], after)
				account, err := f.records.codec.state.systemAccount()
				require.NoError(t, err)
				actualCurrent, err := f.records.current(account, f.scope)
				require.NoError(t, err)
				require.Equal(t, current, actualCurrent)
				require.Error(t, f.records.checkDecision(f.context, f.d))
			})
		}
	}
}

func TestQualDRWAScopedAdmissionWithdrawnBeforeSuccessor(t *testing.T) {
	for _, successionCount := range []int{1, 2} {
		t.Run(fmt.Sprintf("successors_%d", successionCount), func(t *testing.T) {
			f := qualScopedNew(t)
			f.enroll(t)
			f.admit(t)
			require.NoError(t, f.records.withdraw(f.context, f.d, f.withdrawProof()))
			current := qualScopedSuccessors(t, f, successionCount)
			before, err := f.store.RootHash()
			require.NoError(t, err)
			journal := f.store.JournalLen()
			budget := qualRegistryValue(t, f.store, scopedAdmissionPrefix+"budget")
			require.NoError(t, f.records.withdraw(f.context, f.d, qualScopedCurrentWithdrawal(f, current)))
			require.Error(t, f.records.admit(f.context, f.d,
				f.mandates.proof("ADMISSION", f.d.authority, qualScopedHash("ADMISSION", f.body()))))
			require.Equal(t, f.body(), qualRegistryValue(t, f.store, scopedAdmissionPrefix+"withdrawn@"+string(f.id())))
			require.Equal(t, budget, qualRegistryValue(t, f.store, scopedAdmissionPrefix+"budget"))
			require.Equal(t, journal, f.store.JournalLen())
			after, err := f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Error(t, f.records.checkDecision(f.context, f.d))
		})
	}
}
