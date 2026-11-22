package drwa

import (
	"bytes"
	"errors"
	"math/big"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/common"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

var errSetupInitialization = errors.New("invalid DRWA setup initialization")

// The native profile owner supplies the admitted per-type EMPTY_ROOT; a generic
// account root, nil default or a locally invented hash cannot replace it.
// ReserveInitialization authenticates and co-journals capacity/prepaid work for
// exactly these new records under the current native operation. It may update
// its own budget records, never the target records or current lifecycle bundle.
// Neither method establishes canonical application or authorizes a readiness
// ACK. The actual root/resource providers remain first-use integration gates.
type setupInitializationHost interface {
	EmptyRoot(tokenType uint32, position bool) ([]byte, error)
	ReserveInitialization(token []byte, epoch uint64, hash []byte, keys, values [][]byte) error
	IsInterfaceNil() bool
}

type setupInitialization struct {
	current *currentLifecycleReader
	host    setupInitializationHost
	records *rootLeafRecords
}

func newSetupInitialization(current *currentLifecycleReader, host setupInitializationHost, maxAmountBytes int) (*setupInitialization, error) {
	if current == nil || current.current == nil || current.boundary == nil || check.IfNil(host) {
		return nil, errSetupInitialization
	}
	records, err := newRootLeafRecords(current.current.codec, maxAmountBytes)
	if err != nil {
		return nil, errSetupInitialization
	}
	return &setupInitialization{current: current, host: host, records: records}, nil
}

// initializeOwned runs in the original owning operation. Only the initial current
// epoch's SETUP is eligible; requalification cannot reset supply/positions.
// A later canonical local-application check must commit these exact hashes in
// SETUP_READY_ACK. This writer emits no ACK and does not call state canonical.
func (s *setupInitialization) initializeOwned(operation *rollbackOperation, context *HeaderTimeContext,
	token []byte, epoch uint64, hash []byte) (*vmcommon.VMOutput, error) {
	if s == nil || s.current == nil {
		return nil, errSetupInitialization
	}
	if operation == nil {
		return nil, errCurrentLifecycle
	}
	r := s.current
	var output *vmcommon.VMOutput
	err := operation.withWrite(r.boundary, r.current.codec.state.accounts, func() error {
		if epoch != 1 || r.coordinator.SelfId() >= r.coordinator.NumberOfShards() {
			return errSetupInitialization
		}
		var err error
		output, err = s.initializeState(context, token, epoch, hash)
		return err
	})
	if err != nil {
		return nil, err
	}
	return output, nil
}

func (s *setupInitialization) initializeState(context *HeaderTimeContext, token []byte, epoch uint64, hash []byte) (*vmcommon.VMOutput, error) {
	r := s.current
	return r.withCurrent(context, token, epoch, hash, func(view lifecycleReadView) (*vmcommon.VMOutput, error) {
		if view.activation != "Active" || view.lifecycle != "SETUP" {
			return nil, errSetupInitialization
		}
		codec := r.current.codec
		family := core.ESDTType(view.tokenType)
		if family != core.Fungible && !nonceFamily(family) {
			return nil, errSetupInitialization
		}
		supplyKey, err := s.records.outerKey(supplyStatePrefix, view.token)
		if err != nil {
			return nil, err
		}
		positionKey, err := s.records.outerKey(positionTrackingPrefix, view.token)
		if err != nil {
			return nil, err
		}
		// Absence is a prerequisite for initialization, never an implicit zero
		// interpretation. Refuse even an equal populated record instead of reset.
		absent := func() error {
			account, e := codec.state.systemAccount()
			if e != nil {
				return e
			}
			for _, key := range [][]byte{supplyKey, positionKey} {
				value, _, e := account.RetrieveValue(bytes.Clone(key))
				if e != nil {
					return e
				}
				if len(value) > codec.maxBytes || len(value) != 0 {
					return errSetupInitialization
				}
			}
			return nil
		}
		if err = absent(); err != nil {
			return nil, err
		}
		emptyRoot := func(position bool) ([]byte, error) {
			var root []byte
			e := verifyRegistrationState(r.boundary.stores, func() error {
				var inner error
				root, inner = s.host.EmptyRoot(view.tokenType, position)
				return inner
			})
			if e != nil {
				return nil, e
			}
			if !bytes.Equal(root, common.EmptyTrieHash) {
				return nil, errSetupInitialization
			}
			return bytes.Clone(root), nil
		}
		var keys, values [][]byte
		if r.coordinator.SelfId() == view.supplyOriginShard {
			var nonceRoot []byte
			if nonceFamily(family) {
				nonceRoot, err = emptyRoot(false)
				if err != nil {
					return nil, err
				}
			}
			value, e := s.records.encodeSupplyRecord(&initializedSupplyState{
				token: view.token, family: family, origin: view.supplyOrigin, originShard: view.supplyOriginShard,
				accounting: newSupplyAccounting(), nonceRoot: nonceRoot,
			})
			if e != nil {
				return nil, e
			}
			keys, values = append(keys, supplyKey), append(values, value)
		}
		if bytes.Equal(view.closurePlan, []byte("preserve-and-close")) {
			root, e := emptyRoot(true)
			if e != nil {
				return nil, e
			}
			value, e := s.records.encodePositionRecord(&initializedPositionState{
				token: view.token, family: family, root: root, quantity: new(big.Int),
			})
			if e != nil {
				return nil, e
			}
			keys, values = append(keys, positionKey), append(values, value)
		}
		// Non-origin burn-and-retire shards have no such local accumulators.
		// Their full dependency/readiness proof still remains mandatory.
		if len(keys) == 0 {
			return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
		}
		clones := func(items [][]byte) [][]byte {
			out := make([][]byte, len(items))
			for i := range items {
				out[i] = bytes.Clone(items[i])
			}
			return out
		}
		if err = s.host.ReserveInitialization(bytes.Clone(view.token), view.cebEpoch, bytes.Clone(view.cebHash), clones(keys), clones(values)); err != nil {
			return nil, err
		}
		if err = absent(); err != nil {
			return nil, err
		}
		// Reload after the resource owner's native budget writes; never save a
		// stale system account over them. Every write shares the original journal.
		account, err := codec.state.systemAccount()
		if err != nil {
			return nil, err
		}
		for i := range keys {
			if err = account.SaveKeyValue(keys[i], values[i]); err != nil {
				return nil, err
			}
		}
		if err = codec.state.accounts.SaveAccount(account); err != nil {
			return nil, err
		}
		return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
	})
}
