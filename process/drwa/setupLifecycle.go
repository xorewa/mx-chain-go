package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

var errSetupLifecycle = errors.New("invalid DRWA setup lifecycle transition")

type setupPhaseEvidence struct{ binding, commitment []byte }

// VerifySetupTransition authenticates the EXACT PA-authorized predecessor and
// successor under the current CEB, complete installed dependencies and lawful
// purpose. It interprets the canonical phase bodies, not an arbitrary COMPLETE
// bitmap: sealing requires setup-ready; OPEN requires seal plus quiescence,
// including metachain's OWN zero-open-effect proof. It proves all required
// admin/role/manager/EOA/false-global-burn facts, canonical bound SupplyState and
// preserve tracking, and NORMAL/inactive current token emergency head for OPEN.
// The current provider/canonical phase/authority/profile inputs have no default.
// ReserveSetupTransition co-journals retained growth and prepaid propagation/ACK
// work; shortening OPEN cannot recycle the prior retained slot's charge.
type setupLifecycleHost interface {
	VerifySetupTransition(context *HeaderTimeContext, view lifecycleReadView, next string, phases []setupPhaseEvidence, certificates []byte) error
	ReserveSetupTransition(token []byte, epoch uint64, hash, predecessor, successor []byte) error
	IsInterfaceNil() bool
}

type setupLifecycle struct {
	current *currentLifecycleReader
	phases  *convergenceRecords
	host    setupLifecycleHost
}

func newSetupLifecycle(current *currentLifecycleReader, phaseHost convergenceHost, host setupLifecycleHost) (*setupLifecycle, error) {
	if current == nil || current.current == nil || current.boundary == nil || check.IfNil(host) ||
		check.IfNil(phaseHost) || current.coordinator.SelfId() != core.MetachainShardId {
		return nil, errSetupLifecycle
	}
	c := current.current.codec
	phases, err := newConvergenceRecords(c.state.accounts, current.boundary, c.marshaller, c.hasher,
		c.maxBytes, int(current.coordinator.NumberOfShards()), phaseHost)
	if err != nil {
		return nil, err
	}
	return &setupLifecycle{current, phases, host}, nil
}

func cloneLifecycleReadView(v lifecycleReadView) lifecycleReadView {
	v.token, v.cebHash = bytes.Clone(v.token), bytes.Clone(v.cebHash)
	v.closurePlan, v.supplyOrigin = bytes.Clone(v.closurePlan), bytes.Clone(v.supplyOrigin)
	return v
}

// completed requires the existing canonical phase owner and its durable parent
// receipt, not an indexer label, all-bits value or self-asserted local ACK. The
// exact setup family/phase/lineage meaning is checked by VerifySetupTransition.
func (s *setupLifecycle) completed(t convergenceTransition, v lifecycleReadView) (setupPhaseEvidence, []byte, []byte, error) {
	// A nil context is reserved for CEB currentization, which cannot supply
	// setup readiness, sealing or quiescence evidence.
	if t.context == nil || !bytes.Equal(t.token, v.token) || t.version != v.cebEpoch ||
		len(t.shards) != int(s.current.coordinator.NumberOfShards()) {
		return setupPhaseEvidence{}, nil, nil, errSetupLifecycle
	}
	for i, shard := range t.shards {
		if shard != uint32(i) {
			return setupPhaseEvidence{}, nil, nil, errSetupLifecycle
		}
	}
	key, binding, err := s.phases.encode(t)
	if err != nil {
		return setupPhaseEvidence{}, nil, nil, err
	}
	var commitment, value []byte
	err = verifyRegistrationState(s.current.boundary.stores, func() error {
		if e := s.phases.host.VerifyTransition(bytes.Clone(binding)); e != nil {
			return e
		}
		p, e := s.phases.load(key, binding, len(t.shards))
		if e != nil {
			return e
		}
		if p.status != "COMPLETE" || !p.full() {
			return errSetupLifecycle
		}
		if e = s.phases.verifyParent(key, binding, len(t.shards), p); e != nil {
			return e
		}
		commitment = bytes.Clone(p.commitment)
		value, e = s.phases.read(key)
		return e
	})
	return setupPhaseEvidence{bytes.Clone(binding), commitment}, key, value, err
}

// advanceOwned has exactly two monotonic transitions. No in-place unseal, ordinary
// resume, currentization or retired/closed-state escape is provided. Actual
// phase and authority providers must be admitted before any native positive.
func (s *setupLifecycle) advanceOwned(operation *rollbackOperation, context *HeaderTimeContext, token []byte, epoch uint64, hash []byte,
	next string, transitions []convergenceTransition, certificates []byte) (*vmcommon.VMOutput, error) {
	if s == nil || s.current == nil {
		return nil, errSetupLifecycle
	}
	if operation == nil {
		return nil, errCurrentLifecycle
	}
	var output *vmcommon.VMOutput
	r := s.current
	err := operation.withWrite(r.boundary, r.current.codec.state.accounts, func() error {
		if len(certificates) == 0 {
			return errSetupLifecycle
		}
		var err error
		output, err = s.advanceState(context, token, epoch, hash, next, transitions, certificates)
		return err
	})
	if err != nil {
		return nil, err
	}
	return output, nil
}

func (s *setupLifecycle) advanceState(context *HeaderTimeContext, token []byte, epoch uint64, hash []byte,
	next string, transitions []convergenceTransition, certificates []byte) (*vmcommon.VMOutput, error) {
	prior, count := "", 0
	switch next {
	case "SETUP_SEALED":
		prior, count = "SETUP", 1
	case "OPEN":
		prior, count = "SETUP_SEALED", 2
	default:
		return nil, errSetupLifecycle
	}
	if len(transitions) != count {
		return nil, errSetupLifecycle
	}
	c := s.current.current.codec
	if _, err := c.frame(certificates); err != nil {
		return nil, err
	}
	certificates = bytes.Clone(certificates)
	var key, predecessor, successor []byte
	var baselines []setupPhaseEvidence
	var phaseKeys, phaseValues [][]byte
	var view lifecycleReadView
	return s.current.withCurrentAndApply(context, token, epoch, hash, func(v lifecycleReadView) (*vmcommon.VMOutput, error) {
		if v.activation != "Active" || v.lifecycle != prior {
			return nil, errSetupLifecycle
		}
		view = cloneLifecycleReadView(v)
		for _, t := range transitions {
			e, k, value, err := s.completed(t, v)
			if err != nil {
				return nil, err
			}
			for _, old := range baselines {
				if bytes.Equal(old.binding, e.binding) {
					return nil, errSetupLifecycle
				}
			}
			baselines, phaseKeys, phaseValues = append(baselines, e), append(phaseKeys, k), append(phaseValues, value)
		}
		proofs := make([]setupPhaseEvidence, len(baselines))
		for i, e := range baselines {
			proofs[i] = setupPhaseEvidence{bytes.Clone(e.binding), bytes.Clone(e.commitment)}
		}
		err := verifyRegistrationState(s.current.boundary.stores, func() error {
			return s.host.VerifySetupTransition(context, cloneLifecycleReadView(v), next, proofs, bytes.Clone(certificates))
		})
		if err != nil {
			return nil, err
		}
		identity, err := c.frame(v.token)
		if err != nil {
			return nil, err
		}
		key = append([]byte(lifecycleRecordPrefix), identity...)
		predecessor, err = c.frame(v.token, binary.BigEndian.AppendUint64(nil, v.cebEpoch), []byte(prior))
		if err != nil {
			return nil, err
		}
		successor, err = c.frame(v.token, binary.BigEndian.AppendUint64(nil, v.cebEpoch), []byte(next))
		if err != nil {
			return nil, err
		}
		if err = s.host.ReserveSetupTransition(bytes.Clone(v.token), v.cebEpoch, bytes.Clone(v.cebHash), bytes.Clone(predecessor), bytes.Clone(successor)); err != nil {
			return nil, err
		}
		return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
	}, func() error {
		// Reauthenticate the SAME receipts after every foreign resource callback.
		// No callback may manufacture a new baseline or erase a required parent.
		for i, t := range transitions {
			e, k, value, err := s.completed(t, view)
			if err != nil {
				return err
			}
			if !bytes.Equal(k, phaseKeys[i]) || !bytes.Equal(value, phaseValues[i]) ||
				!bytes.Equal(e.binding, baselines[i].binding) || !bytes.Equal(e.commitment, baselines[i].commitment) {
				return errSetupLifecycle
			}
		}
		// Resource admission is a native writer. Re-read the actual admin,
		// supply, plane and restriction premises too, not only phase receipts.
		proofs := make([]setupPhaseEvidence, len(baselines))
		for i, e := range baselines {
			proofs[i] = setupPhaseEvidence{bytes.Clone(e.binding), bytes.Clone(e.commitment)}
		}
		if err := verifyRegistrationState(s.current.boundary.stores, func() error {
			return s.host.VerifySetupTransition(context, cloneLifecycleReadView(view), next, proofs, bytes.Clone(certificates))
		}); err != nil {
			return err
		}
		account, err := c.state.systemAccount()
		if err != nil {
			return err
		}
		old, _, err := account.RetrieveValue(bytes.Clone(key))
		if err != nil {
			return err
		}
		if !bytes.Equal(old, predecessor) {
			return errSetupLifecycle
		}
		if err = account.SaveKeyValue(key, successor); err != nil {
			return err
		}
		return c.state.accounts.SaveAccount(account)
	})
}
