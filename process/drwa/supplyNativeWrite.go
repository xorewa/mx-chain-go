package drwa

import (
	"bytes"
	"math/big"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// supplyWriteBinding comes from the original owner's verified operation.
// Nil caps mean explicitly unbounded. The leaf version is required whenever
// the operation uses a protected child, including an existing empty child.
type supplyWriteBinding struct {
	token, cebHash          []byte
	epoch, actionNonce      uint64
	cumulativeCap, nonceCap *big.Int
	leafVersion             *core.TrieNodeVersion
}

type supplyNativeWrite struct {
	reader                *setupLocalStateReader
	db                    *state.AccountsDB
	local                 localSetupState
	binding               supplyWriteBinding
	supplyKey, successor  []byte
	effect                vmcommon.DRWASupplyEffect
	position              positionLeafChange
	expectedOriginBalance *big.Int
}

func (w *supplyNativeWrite) prepare(o *supplyNativeOperation, origin vmcommon.UserAccountHandler, effect vmcommon.DRWASupplyEffect) error {
	s := w.local.supply
	r := w.reader.records
	if !bytes.Equal(effect.TokenIdentifier, s.token) || !bytes.Equal(effect.RoleAddress, s.origin) ||
		effect.TokenType != uint32(s.family) || !positionNonceValid(s.family, effect.Nonce) ||
		w.binding.nonceCap != nil && (s.family == core.Fungible || uniqueNonceFamily(s.family)) {
		return errSupplyAccounting
	}
	if (s.family != core.Fungible || w.local.positions != nil) && !validWriteLeafVersion(w.binding.leafVersion) {
		return errSupplyAccounting
	}
	increase := o.name != core.BuiltInFunctionESDTLocalBurn && o.name != core.BuiltInFunctionESDTNFTBurn
	after, err := s.accounting.advance(w.binding.actionNonce, increase, effect.Quantity, w.binding.cumulativeCap, r.maxAmountBytes)
	if err != nil {
		return err
	}
	before, err := nativePositionBalance(o.storage, o.guard, origin, s.token, s.family, effect.Nonce, r.maxAmountBytes)
	if err != nil {
		return err
	}
	if o.name == core.BuiltInFunctionESDTNFTCreate {
		next, err := core.SafeAddUint64(effect.PreviousNonce, 1)
		if err != nil || next != effect.Nonce || before.Sign() != 0 {
			return errSupplyAccounting
		}
	}
	expected := new(big.Int).Set(before)
	if increase {
		expected.Add(expected, effect.Quantity)
	} else {
		expected.Sub(expected, effect.Quantity)
	}
	if !supplyIntegerFits(expected, r.maxAmountBytes) {
		return errSupplyAccounting
	}
	if w.local.positions != nil {
		key, err := r.positionKey(s.token, s.family, effect.Nonce, s.origin)
		if err != nil {
			return err
		}
		w.position = positionLeafChange{key: key, before: positionBalanceBytes(before), final: positionBalanceBytes(expected)}
	}
	w.effect, w.expectedOriginBalance = effect, expected
	w.supplyKey, err = r.outerKey(supplyStatePrefix, s.token)
	if err != nil {
		return err
	}
	next := *s
	next.accounting = after
	// The nonce must be consumed before the native primitive runs. Both the
	// outer record and any child are in the primitive's original journal.
	if s.family != core.Fungible {
		return w.stageNonceSupply(o.name, next)
	}
	account, err := r.codec.state.systemAccount()
	if err != nil {
		return err
	}
	raw, _, err := account.RetrieveValue(w.supplyKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, w.local.supplyRaw) {
		return errSupplyAccounting
	}
	w.successor, err = r.encodeSupplyRecord(&next)
	if err != nil {
		return err
	}
	if err = account.SaveKeyValue(w.supplyKey, w.successor); err != nil {
		return err
	}
	return w.db.SaveAccount(account)
}

func (w *supplyNativeWrite) stageNonceSupply(function string, next initializedSupplyState) error {
	r := w.reader.records
	version := *w.binding.leafVersion
	key, err := r.nonceKey(next.token, next.family, w.effect.Nonce)
	if err != nil {
		return err
	}
	w.successor, err = w.db.StageDerivedProtectedChildTrie(core.SystemAccountAddress, w.supplyKey, w.local.supplyRaw, [][]byte{key},
		func(previous []core.TrieData) ([]core.TrieData, error) {
			if !bytes.Equal(previous[0].Key, key) {
				return nil, errSupplyAccounting
			}
			var prior *nonceSupply
			if len(previous[0].Value) != 0 {
				if previous[0].Version != version {
					return nil, errSupplyAccounting
				}
				value, err := r.decodeNonceValue(next.family, previous[0].Value)
				if err != nil {
					return nil, err
				}
				prior = &value
			}
			value, err := r.nonceSupplyAfter(next.family, function, prior, w.effect.Quantity, w.binding.nonceCap)
			if err != nil {
				return nil, err
			}
			raw, err := r.nonceValue(next.family, value)
			if err != nil {
				return nil, err
			}
			return []core.TrieData{{Key: key, Value: raw, Version: version}}, nil
		},
		func(root []byte) ([]byte, error) {
			next.nonceRoot = root
			return r.encodeSupplyRecord(&next)
		})
	return err
}

func (w *supplyNativeWrite) finish(o *supplyNativeOperation, origin vmcommon.UserAccountHandler, output *vmcommon.VMOutput) error {
	s := w.local.supply
	r := w.reader.records
	after, err := nativePositionBalance(o.storage, o.guard, origin, s.token, s.family, w.effect.Nonce, r.maxAmountBytes)
	if err != nil {
		return err
	}
	if after.Cmp(w.expectedOriginBalance) != 0 {
		return errSupplyAccounting
	}
	if o.name == core.BuiltInFunctionESDTNFTCreate &&
		(len(output.ReturnData) != 1 || !bytes.Equal(output.ReturnData[0], new(big.Int).SetUint64(w.effect.Nonce).Bytes())) {
		return errSupplyAccounting
	}
	raw, err := w.reader.current.current.read(w.supplyKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, w.successor) {
		return errSupplyAccounting
	}
	if w.local.positions == nil {
		return nil
	}
	return r.writePositionMap(w.db, w.local, []positionLeafChange{w.position}, 1, w.binding.leafVersion)
}

func nativePositionBalance(storage vmcommon.SimpleESDTNFTStorageHandler, guard *routeNativeGuard, account vmcommon.UserAccountHandler,
	token []byte, family core.ESDTType, nonce uint64, maxAmountBytes int) (*big.Int, error) {
	if check.IfNil(storage) || check.IfNil(account) {
		return nil, errSetupLocalState
	}
	key := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), token...)
	current, missing, err := storage.GetESDTNFTTokenOnDestination(account, key, nonce)
	if guard.first != nil {
		return nil, guard.first
	}
	if err != nil {
		return nil, err
	}
	if current == nil || !supplyIntegerFits(current.Value, maxAmountBytes) ||
		missing && current.Value.Sign() != 0 || !missing && current.Type != uint32(family) {
		return nil, errSetupLocalState
	}
	return new(big.Int).Set(current.Value), nil
}

func positionBalanceBytes(value *big.Int) []byte {
	if value.Sign() == 0 {
		return nil
	}
	return value.Bytes()
}

func validWriteLeafVersion(admitted *core.TrieNodeVersion) bool {
	return admitted != nil && (*admitted == core.NotSpecified || *admitted == core.AutoBalanceEnabled)
}

// writePositionMap is called once for the token's final map inside the native
// owner's write set. Its predecessor balances come from the native store.
func (r *rootLeafRecords) writePositionMap(db *state.AccountsDB, local localSetupState,
	changes []positionLeafChange, maxKeys int, admittedVersion *core.TrieNodeVersion) error {
	if db == nil || !validWriteLeafVersion(admittedVersion) || len(local.positionRaw) == 0 || len(changes) == 0 {
		return errSetupLocalState
	}
	total, version, changed, err := r.positionMapAfter(local.positions, changes, maxKeys)
	if err != nil {
		return err
	}
	key, err := r.outerKey(positionTrackingPrefix, local.positions.token)
	if err != nil {
		return err
	}
	keys := make([][]byte, len(changes))
	for i := range changes {
		keys[i] = changes[i].key
	}
	leafVersion := *admittedVersion
	verify := func(previous []core.TrieData) error {
		for i, leaf := range previous {
			if !bytes.Equal(leaf.Key, changes[i].key) || !bytes.Equal(leaf.Value, changes[i].before) ||
				len(leaf.Value) != 0 && leaf.Version != leafVersion {
				return errSetupLocalState
			}
		}
		return nil
	}
	if !changed {
		previous, err := db.ReadProtectedChildLeaves(core.SystemAccountAddress, key, local.positionRaw, keys)
		if err != nil {
			return err
		}
		return verify(previous)
	}
	_, err = db.StageDerivedProtectedChildTrie(core.SystemAccountAddress, key, local.positionRaw, keys,
		func(previous []core.TrieData) ([]core.TrieData, error) {
			if err := verify(previous); err != nil {
				return nil, err
			}
			updates := make([]core.TrieData, len(changes))
			for i, change := range changes {
				updates[i] = core.TrieData{Key: change.key, Value: change.final, Version: leafVersion}
			}
			return updates, nil
		},
		func(root []byte) ([]byte, error) {
			next := *local.positions
			next.root, next.quantity, next.version = root, total, version
			return r.encodePositionRecord(&next)
		})
	return err
}
