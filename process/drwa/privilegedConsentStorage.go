package drwa

import (
	"bytes"
	"encoding/binary"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/state"
)

// DRWA-defined experimental allocation, pending Part B L346 review. It is
// disjoint from membership, registry and membershipIndex, and lies entirely
// within the native protected-key domain. Ledger L34 fixes the account locus
// and retention tuple, not this prefix or framing.
const privilegedConsentRecordPrefix = core.ProtectedKeyPrefix + "DRWA@privilegedConsent@record@"

// PrivilegedConsentReferenceReader belongs to the admission owner, not consent
// storage. AdmittedProgram must resolve the immutable authoritative registered
// token-to-consumed-intent/programme association (Part A L2245/L2389) from the
// already admitted local execution context. It must fail when unavailable,
// unadmitted or inconsistent. It performs no remote read and admits no new
// token/programme. There is no production implementation or wiring here; its
// owning construction/transport must be qualified before the first consumer.
// One canonical programme per registered token bounds record cardinality to
// one slot per EOA/registered token. A caller-supplied programme is not authority.
type PrivilegedConsentReferenceReader interface {
	AdmittedProgram(token []byte) ([]byte, error)
	IsInterfaceNil() bool
}

func privilegedConsentRecordKey(address, token, program []byte) []byte {
	key := []byte(privilegedConsentRecordPrefix)
	for _, field := range [][]byte{address, token, program} {
		key = binary.BigEndian.AppendUint64(key, uint64(len(field)))
		key = append(key, field...)
	}
	return key
}

// checkPrivilegedConsentReference uses T07 read-only. A reference resolver
// cannot mint membership, and local membership does not supply programme facts.
func checkPrivilegedConsentReference(accounts state.AccountsAdapter, references PrivilegedConsentReferenceReader,
	token, program []byte) error {
	store := &protectedState{accounts: accounts}
	// T07 returns false for every absent, malformed or unavailable item. Its
	// error cannot accompany true, so a second error predicate is redundant.
	present, _ := store.membership(token)
	if !present {
		return ErrPrivilegedConsent
	}
	admitted, err := references.AdmittedProgram(bytes.Clone(token))
	if err != nil || !bytes.Equal(admitted, program) {
		return ErrPrivilegedConsent
	}
	return nil
}

// savePrivilegedConsent must run inside the successful native operation's T04
// snapshot. Reloading the exact native system account preserves other owning
// mechanisms' fields and never saves a stale sender over native fee/refund data.
func savePrivilegedConsent(accounts state.AccountsAdapter, address, token, program, record []byte) error {
	store := &protectedState{accounts: accounts}
	account, err := store.systemAccount()
	if err != nil {
		return err
	}
	if err = account.SaveKeyValue(privilegedConsentRecordKey(address, token, program), bytes.Clone(record)); err != nil {
		return err
	}
	return accounts.SaveAccount(account)
}
