package drwa

import (
	"bytes"
	"errors"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
)

// Experimental construction record, not Part B L346 format allocation. The
// eight-byte zero is the empty registry count; this component cannot register
// a token or change that count (Part A L912-915). It is disjoint from membership.
const registryCountKey = core.ProtectedKeyPrefix + "DRWA@registry@count"

var errInvalidGenesisState = errors.New("DRWA provisioning requires an empty native genesis store")

// provisionGenesis creates the exact L26 system account and its native data
// trie, with an empty registry record. It is an unwired construction, not a
// complete DRWA genesis: manager identity, authorities, profiles and plane state
// remain separate obligations (Part A L912-917).
//
// The future DRWA genesis owner must call this BEFORE other genesis mutations,
// under exclusive store ownership inside RollbackContainment.Execute, and abort
// genesis on any error. Native account saves may partially mutate before failing.
// The owner must establish fresh-chain provenance; an empty root alone is not
// authority to reset or upgrade an existing chain (Part A L910). There is no
// startup repair, caller-supplied address, raw-key API or ordinary-path caller.
func (s *protectedState) provisionGenesis() error {
	if s.accounts.JournalLen() != 0 {
		return ErrUncommittedState
	}
	root, err := s.accounts.RootHash()
	if err != nil {
		return err
	}
	if !common.IsEmptyTrie(root) {
		return errInvalidGenesisState
	}
	a, err := s.accounts.LoadAccount(bytes.Clone(core.SystemAccountAddress))
	if err != nil {
		return err
	}
	u, _ := a.(state.UserAccountHandler)
	if check.IfNil(u) || !bytes.Equal(u.AddressBytes(), core.SystemAccountAddress) {
		return errInvalidGenesisState
	}
	if err = u.SaveKeyValue([]byte(registryCountKey), make([]byte, 8)); err != nil {
		return err
	}
	if err = u.SaveKeyValue([]byte(localMembershipCountKey), make([]byte, 8)); err != nil {
		return err
	}
	return s.accounts.SaveAccount(u)
}
