package drwa

import (
	"bytes"
	"errors"
	"math/big"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

var errSetupLocalState = errors.New("invalid DRWA initialized local setup state")

// quantityAfter calculates ONLY the detached token-unit successor. maxBytes
// comes from the admitted resource profile, never an untrusted request. Native
// operation/family/role/factor checks still own admission, including zero rules.
// The effect owner must co-journal its exact leaf/root/version successor with
// this quantity and the native ESDT delta. Use positionMapAfter for the final
// map version; this calculation does not publish a successor.
func (p *initializedPositionState) quantityAfter(credit bool, quantity *big.Int, maxBytes int) (*big.Int, error) {
	if p == nil || !supplyIntegerFits(p.quantity, maxBytes) || !supplyIntegerFits(quantity, maxBytes) {
		return nil, errSetupLocalState
	}
	next := new(big.Int).Set(p.quantity)
	if credit {
		next.Add(next, quantity)
	} else {
		if next.Cmp(quantity) < 0 {
			return nil, errSetupLocalState
		}
		next.Sub(next, quantity)
	}
	if !supplyIntegerFits(next, maxBytes) {
		return nil, errSetupLocalState
	}
	return next, nil
}

// positionLeafChange is one key's authenticated predecessor and final value
// for a single original operation. Nil before means authenticated absence.
// Empty final is the native deletion instruction.
type positionLeafChange struct {
	key, before, final []byte
}

// positionMapAfter advances at most once for the operation's entire map at
// this locator. The owner authenticates each native leg before folding it into
// this sorted, unique vector and publishes the native root in its own journal.
func (r *rootLeafRecords) positionMapAfter(prior *initializedPositionState, changes []positionLeafChange,
	maxKeys int) (*big.Int, uint64, bool, error) {
	if !r.validPositionRecord(prior) || maxKeys <= 0 || len(changes) > maxKeys {
		return nil, 0, false, errSetupLocalState
	}
	var removed, added big.Int
	changed := false
	for i, change := range changes {
		if i > 0 && bytes.Compare(changes[i-1].key, change.key) >= 0 {
			return nil, 0, false, errSetupLocalState
		}
		if _, _, err := r.decodePositionKey(change.key, prior.token, prior.family); err != nil {
			return nil, 0, false, errSetupLocalState
		}
		if change.before != nil {
			q, err := r.decodeQuantityValue(change.before)
			if err != nil {
				return nil, 0, false, errSetupLocalState
			}
			removed.Add(&removed, q)
			if removed.Cmp(prior.quantity) > 0 {
				return nil, 0, false, errSetupLocalState
			}
		}
		q, err := r.decodeUnsigned(change.final)
		if err != nil {
			return nil, 0, false, errSetupLocalState
		}
		added.Add(&added, q)
		if !supplyIntegerFits(&added, r.maxAmountBytes) {
			return nil, 0, false, errSetupLocalState
		}
		changed = changed || !bytes.Equal(change.before, change.final)
	}
	total := new(big.Int).Sub(prior.quantity, &removed)
	total.Add(total, &added)
	if !supplyIntegerFits(total, r.maxAmountBytes) {
		return nil, 0, false, errSetupLocalState
	}
	if !changed {
		return total, prior.version, false, nil
	}
	next, err := core.SafeAddUint64(prior.version, 1)
	if err != nil {
		return nil, 0, false, errSetupLocalState
	}
	return total, next, true, nil
}

// A nil member means NOT locally required, never a zero/uninitialized record.
// These detached fields/hashes are an ephemeral read baseline, not authority,
// operation permission, an all-shard barrier or a reusable readiness token.
type localSetupState struct {
	supply                   *initializedSupplyState
	positions                *initializedPositionState
	supplyHash, positionHash []byte
	supplyRaw, positionRaw   []byte
}

// VerifyLocalSetupState proves canonical LOCAL initialization/application and
// the exact current-epoch dependencies/continuity/per-type grammar. Mere DB
// presence or matching a hash does not suffice. Requalification must retain the
// same initialized tracking/supply lineage, never manufacture zero again.
// On non-origin shards the reader checks local absence before omitting supply
// from the proof. No remote lookup or canonical provider default is installed.
type setupLocalStateHost interface {
	VerifyLocalSetupState(context *HeaderTimeContext, view lifecycleReadView, supply, positions []byte) error
	IsInterfaceNil() bool
}

type setupLocalStateReader struct {
	current *currentLifecycleReader
	host    setupLocalStateHost
	records *rootLeafRecords
}

func newSetupLocalStateReader(current *currentLifecycleReader, host setupLocalStateHost, maxAmountBytes int) (*setupLocalStateReader, error) {
	if current == nil || current.current == nil || check.IfNil(host) ||
		current.coordinator.SelfId() >= current.coordinator.NumberOfShards() {
		return nil, errSetupLocalState
	}
	records, err := newRootLeafRecords(current.current.codec, maxAmountBytes)
	if err != nil {
		return nil, errSetupLocalState
	}
	return &setupLocalStateReader{current, host, records}, nil
}

func (r *setupLocalStateReader) decodeSupply(view lifecycleReadView, raw []byte) (*initializedSupplyState, error) {
	s, err := r.records.decodeSupplyRecord(raw)
	if err != nil || !bytes.Equal(s.token, view.token) || uint32(s.family) != view.tokenType ||
		!bytes.Equal(s.origin, view.supplyOrigin) || s.originShard != view.supplyOriginShard {
		return nil, errSetupLocalState
	}
	return s, nil
}

func (r *setupLocalStateReader) decodePositions(view lifecycleReadView, raw []byte) (*initializedPositionState, error) {
	p, err := r.records.decodePositionRecord(raw)
	if err != nil || !bytes.Equal(p.token, view.token) || uint32(p.family) != view.tokenType {
		return nil, errSetupLocalState
	}
	return p, nil
}

func (r *setupLocalStateReader) readMember(key []byte, required bool) ([]byte, error) {
	if required {
		return r.current.current.read(key)
	}
	account, err := r.current.current.codec.state.systemAccount()
	if err != nil {
		return nil, err
	}
	raw, _, err := account.RetrieveValue(bytes.Clone(key))
	if err != nil {
		return nil, err
	}
	if len(raw) != 0 {
		return nil, errSetupLocalState
	}
	return nil, nil
}

// withInitializedState adds the prescribed local state dependency to the SAME
// original current/header owner. Consumer operation/lifecycle/factor and native
// route admission remain separate. A legitimate token-effect consumer MUST
// validate/co-journal its exact successor/root/version/conservation; this reader
// neither writes that successor nor authorizes arbitrary mutation. No remote
// ready shard, all-shard ACK or observation label substitutes for local proof.
func (r *setupLocalStateReader) withInitializedState(context *HeaderTimeContext, token []byte, epoch uint64, hash []byte,
	execute func(lifecycleReadView, localSetupState) (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
	if r == nil || execute == nil {
		return nil, errSetupLocalState
	}
	return r.current.withCurrent(context, token, epoch, hash, func(view lifecycleReadView) (*vmcommon.VMOutput, error) {
		c := r.current.current.codec
		family := core.ESDTType(view.tokenType)
		if family != core.Fungible && !nonceFamily(family) {
			return nil, errSetupLocalState
		}
		supplyKey, err := r.records.outerKey(supplyStatePrefix, view.token)
		if err != nil {
			return nil, err
		}
		positionKey, err := r.records.outerKey(positionTrackingPrefix, view.token)
		if err != nil {
			return nil, err
		}
		supplyRequired := r.current.coordinator.SelfId() == view.supplyOriginShard
		positionRequired := bytes.Equal(view.closurePlan, []byte("preserve-and-close"))
		var supply, positions []byte
		var local localSetupState
		// Bind presence and absence at their actual loci before proof evaluation.
		err = verifyRegistrationState(r.current.boundary.stores, func() error {
			var e error
			supply, e = r.readMember(supplyKey, supplyRequired)
			if e != nil {
				return e
			}
			positions, e = r.readMember(positionKey, positionRequired)
			if e != nil {
				return e
			}
			if supplyRequired {
				local.supply, e = r.decodeSupply(view, supply)
				if e != nil {
					return e
				}
				local.supplyHash = bytes.Clone(c.hasher.Compute(string(supply)))
			}
			if positionRequired {
				local.positions, e = r.decodePositions(view, positions)
				if e != nil {
					return e
				}
				local.positionHash = bytes.Clone(c.hasher.Compute(string(positions)))
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		err = verifyRegistrationState(r.current.boundary.stores, func() error {
			return r.host.VerifyLocalSetupState(context, cloneLifecycleReadView(view), bytes.Clone(supply), bytes.Clone(positions))
		})
		if err != nil {
			return nil, err
		}
		currentSupply, err := r.readMember(supplyKey, supplyRequired)
		if err != nil {
			return nil, err
		}
		currentPositions, err := r.readMember(positionKey, positionRequired)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(currentSupply, supply) || !bytes.Equal(currentPositions, positions) {
			return nil, errSetupLocalState
		}
		local.supplyRaw, local.positionRaw = bytes.Clone(supply), bytes.Clone(positions)
		return execute(view, local)
	})
}
