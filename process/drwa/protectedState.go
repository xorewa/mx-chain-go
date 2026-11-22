package drwa

import (
	"bytes"
	"errors"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/state"
)

// Experimental construction domain, not a release-format allocation. It is
// wholly inside the existing native protected-key domain (Part A 1005-1012;
// Part B 346/350). No ordinary storage key becomes newly reserved.
const membershipKeyPrefix = core.ProtectedKeyPrefix + "DRWA@membership@"

var errInvalidMembership = errors.New("invalid DRWA membership record")

// protectedState is the DRWA-owned native storage component. Its first typed
// item is permanent membership, needed by W04 (Part A 4845-4888). It owns no
// separate trie, journal, cache, commit or registration authority. Further
// owning mechanisms must supply their own qualified typed records; this does
// not infer holder, restriction, pending or terminal schemas from prose.
//
// There are no importers outside this package and no public raw-key writer,
// configurable prefix or account address. The first production caller belongs
// to the W04 construction, not ordinary ESDT dispatch. That caller must establish
// authority, context and exclusive native-store ownership and include writes
// and account saves in its RollbackContainment operation. A returned save error
// does not mean that no mutation happened. Namespace membership is not consent.
type protectedState struct {
	accounts state.AccountsAdapter
}

func newProtectedState(accounts state.AccountsAdapter) (*protectedState, error) {
	if check.IfNil(accounts) {
		return nil, state.ErrNilAccountsAdapter
	}
	return &protectedState{accounts: accounts}, nil
}

func membershipKey(tokenID []byte) ([]byte, error) {
	if len(tokenID) == 0 {
		return nil, errInvalidMembership
	}
	key := make([]byte, len(membershipKeyPrefix)+len(tokenID))
	copy(key, membershipKeyPrefix)
	copy(key[len(membershipKeyPrefix):], tokenID)
	return key, nil
}

// systemAccount reloads native state for every operation; no account reference
// survives native rollback/recreation. Missing or unavailable state is an error,
// never permission to create a namespace or fall back to ordinary execution.
func (s *protectedState) systemAccount() (state.UserAccountHandler, error) {
	a, err := s.accounts.GetExistingAccount(bytes.Clone(core.SystemAccountAddress))
	if err != nil {
		return nil, err
	}
	u, _ := a.(state.UserAccountHandler)
	if check.IfNil(u) || !bytes.Equal(u.AddressBytes(), core.SystemAccountAddress) {
		return nil, errInvalidMembership
	}
	return u, nil
}

func readMembership(account state.UserAccountHandler, key []byte) (bool, error) {
	value, _, err := account.RetrieveValue(key)
	if err != nil {
		return false, err
	}
	if len(value) == 0 {
		return false, nil
	}
	// A single present marker is sufficient: membership has no removal state.
	// Absent, malformed and unavailable are distinct. Lifecycle is separate.
	if len(value) != 1 || value[0] != 1 {
		return false, errInvalidMembership
	}
	return true, nil
}

func (s *protectedState) membership(tokenID []byte) (bool, error) {
	key, err := membershipKey(tokenID)
	if err != nil {
		return false, err
	}
	account, err := s.systemAccount()
	if err != nil {
		return false, err
	}
	return readMembership(account, key)
}

// materializeMembership only persists an already-authorized local membership
// item. It is not DRWARegisterToken and cannot increment the registry count or
// authorize a receiving-shard message. W04 supplies those owning predicates.
// Duplicate materialization preserves the native journal and record exactly.
// There is deliberately no erase or raw-value operation.
func (s *protectedState) materializeMembership(tokenID []byte) error {
	key, err := membershipKey(tokenID)
	if err != nil {
		return err
	}
	account, err := s.systemAccount()
	if err != nil {
		return err
	}
	count, err := readLocalMembershipCount(account)
	if err != nil {
		return err
	}
	present, err := readMembership(account, key)
	if err != nil || present {
		return err
	}
	if err = account.SaveKeyValue(key, []byte{1}); err != nil {
		return err
	}
	if err = appendLocalMembershipIndex(account, tokenID, count); err != nil {
		return err
	}
	return s.accounts.SaveAccount(account)
}
