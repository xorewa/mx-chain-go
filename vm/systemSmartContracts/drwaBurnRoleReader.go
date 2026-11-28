package systemSmartContracts

import (
	"bytes"
	"errors"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/marshal"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"

	"github.com/multiversx/mx-chain-go/state"
)

// ErrDRWABurnRoleRead signals that the metachain token record could not be
// read exactly. It is never absence of the role.
var ErrDRWABurnRoleRead = errors.New("DRWA metachain burn-for-all role read failed")

// DRWABurnRoleReader reads, from the ESDT system contract's own account in the
// metachain store, whether a token's record holds the burn-for-all special
// role (Part A E.20.2: the absence of the metachain role is an authoritative
// fact of its own). It reads the record the native contract writes; it writes
// nothing.
type DRWABurnRoleReader struct {
	accounts   state.AccountsAdapter
	marshaller marshal.Marshalizer
}

// NewDRWABurnRoleReader creates the reader of one metachain account store.
func NewDRWABurnRoleReader(accounts state.AccountsAdapter, marshaller marshal.Marshalizer) (*DRWABurnRoleReader, error) {
	if check.IfNil(accounts) || check.IfNil(marshaller) {
		return nil, ErrDRWABurnRoleRead
	}
	return &DRWABurnRoleReader{accounts: accounts, marshaller: marshaller}, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (r *DRWABurnRoleReader) IsInterfaceNil() bool { return r == nil }

// HasBurnForAllRole returns whether the token's metachain record holds the
// burn-for-all role. A token without a record, an unreadable account and an
// undecodable record are errors.
func (r *DRWABurnRoleReader) HasBurnForAllRole(tokenID []byte) (bool, error) {
	account, err := r.accounts.GetExistingAccount(bytes.Clone(core.ESDTSCAddress))
	if err != nil {
		return false, errors.Join(ErrDRWABurnRoleRead, err)
	}
	user, ok := account.(state.UserAccountHandler)
	if !ok || check.IfNil(user) {
		return false, ErrDRWABurnRoleRead
	}
	raw, _, err := user.RetrieveValue(bytes.Clone(tokenID))
	if err != nil {
		return false, errors.Join(ErrDRWABurnRoleRead, err)
	}
	if len(raw) == 0 {
		return false, ErrDRWABurnRoleRead
	}
	token := &ESDTDataV2{}
	if err = r.marshaller.Unmarshal(token, raw); err != nil {
		return false, errors.Join(ErrDRWABurnRoleRead, err)
	}
	return checkIfDefinedRoleExistsInToken(token, []byte(vmcommon.ESDTRoleBurnForAll)), nil
}
