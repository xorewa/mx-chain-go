package drwa

import (
	"bytes"
	"encoding/binary"
	"math"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/state"
)

// Experimental native local enumeration records, not format allocation. These
// are not registration authority or a second persistence journal. Their sole
// purpose is bounding reconstruction by local DRWA membership (Part A L4874-76)
// rather than enumerating unrelated ESDT metadata in the same system account.
const localMembershipCountKey = core.ProtectedKeyPrefix + "DRWA@membershipIndex@count"
const localMembershipEntryPrefix = core.ProtectedKeyPrefix + "DRWA@membershipIndex@entry@"

func localMembershipEntryKey(ordinal uint64) []byte {
	key := make([]byte, len(localMembershipEntryPrefix)+8)
	copy(key, localMembershipEntryPrefix)
	binary.BigEndian.PutUint64(key[len(localMembershipEntryPrefix):], ordinal)
	return key
}

func readLocalMembershipCount(u state.UserAccountHandler) (uint64, error) {
	value, _, err := u.RetrieveValue([]byte(localMembershipCountKey))
	if err != nil {
		return 0, err
	}
	if len(value) != 8 {
		return 0, errInvalidMembership
	}
	return binary.BigEndian.Uint64(value), nil
}

// appendLocalMembershipIndex participates in the caller's native account save
// and T04 rollback boundary, never saving/committing independently. The sole
// materializeMembership writer owns this count/ordinal invariant. Raw arbitrary
// canonical-store tampering is not authenticated by this local enumeration.
func appendLocalMembershipIndex(u state.UserAccountHandler, tokenID []byte, count uint64) error {
	if count == math.MaxUint64 {
		return errInvalidMembership
	}
	key := localMembershipEntryKey(count)
	old, _, err := u.RetrieveValue(key)
	if err != nil {
		return err
	}
	if len(old) != 0 {
		return errInvalidMembership
	}
	if err = u.SaveKeyValue(key, bytes.Clone(tokenID)); err != nil {
		return err
	}
	value := make([]byte, 8)
	binary.BigEndian.PutUint64(value, count+1)
	return u.SaveKeyValue([]byte(localMembershipCountKey), value)
}
