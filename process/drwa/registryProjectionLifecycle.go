package drwa

import (
	"bytes"
	"encoding/binary"
	"sort"
	"sync"

	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// committedRegistry is the DRWA-defined in-memory projection in Part A
// L4863-4888. It is neither another registry nor a persistence journal. Its
// initial publication requires a successful native materialization commit;
// subsequent publications apply only authenticated newly added members.
//
// Native commit is not tracker admission or canonical finality. The future
// native owner must reconcile this projection on replacement/recreation and
// supply independently admitted context/epoch/root retention before use. No
// production importer or ordinary dispatch is installed by this component.
type committedRegistry struct {
	mut     sync.RWMutex
	anchor  metaRegistryAnchor
	members map[string]struct{}
	active  *registryCandidate
}

func copyRegistryAnchor(a *metaRegistryAnchor) metaRegistryAnchor {
	return metaRegistryAnchor{candidateHash: bytes.Clone(a.candidateHash), metaHash: bytes.Clone(a.metaHash),
		executedHash: bytes.Clone(a.executedHash), root: bytes.Clone(a.root), nonce: a.nonce, round: a.round, epoch: a.epoch}
}

// commitProjection transfers the privately owned prepared map after the actual
// native store commit. Abort/failed commit cannot manufacture this receipt.
// The initial O(N) reconstruction was already confined to startup/sync/integrity.
func (m *registryMaterialization) commitProjection() (*committedRegistry, error) {
	m.mut.Lock()
	defer m.mut.Unlock()
	m.owner.mut.Lock()
	available := m.owner.checkAvailable()
	m.owner.mut.Unlock()
	if available != nil {
		return nil, available
	}
	if m.members == nil {
		return nil, errInvalidRegistryTransport
	}
	if _, _, err := m.owner.Commit(); err != nil {
		return nil, err
	}
	return &committedRegistry{anchor: copyRegistryAnchor(&m.required), members: m.members}, nil
}

// registryCandidate is a DRWA-defined block-local view. Only its newly added
// identifiers are stored here; ordinary lookup never walks the full registry.
// Count-based completeness has the same sole atomic global-producer prerequisite
// as registryTransport. The owner still owes actual native before-first-effect
// dispatch, scheduler dependencies and AN-03; this is an unwired construction.
type registryCandidate struct {
	parent   *committedRegistry
	before   metaRegistryAnchor
	after    metaRegistryAnchor
	added    map[string]struct{}
	material *registryMaterialization
	ready    bool
}

// prepareDelta authenticates only the count and exact new entries at the new
// candidate's selected meta result. The native caller must establish that this
// context continues the committed context; comparing supplied fields is not
// canonical ancestry. No ordinary identifier is quarantined and no state is
// mutated/published by proof preparation.
func (c *committedRegistry) prepareDelta(t *registryTransport, before, after *metaRegistryAnchor,
	countProof AccountItemWitness, members []registryMemberWitness) (*registryCandidate, error) {
	c.mut.RLock()
	defer c.mut.RUnlock()
	if t == nil || before == nil || after == nil || c.active != nil || !sameRegistryAnchor(&c.anchor, before) ||
		uint64(len(c.members)) > t.maxEver || uint64(len(members)) > t.maxEver-uint64(len(c.members)) {
		return nil, errInvalidRegistryTransport
	}
	remaining := t.proofByteLimit
	read := func(key []byte, w AccountItemWitness) ([]byte, error) {
		n, err := registryProofBytes(w, remaining)
		if err != nil {
			return nil, err
		}
		value, err := t.reader.readRegistryItem(after, key, w, remaining)
		if err != nil {
			return nil, err
		}
		remaining -= n
		return value, nil
	}
	value, err := read([]byte(registryCountKey), countProof)
	if err != nil {
		return nil, err
	}
	if len(value) != 8 {
		return nil, errInvalidRegistryTransport
	}
	count := binary.BigEndian.Uint64(value)
	old := uint64(len(c.members))
	if count < old || count > t.maxEver || count-old != uint64(len(members)) {
		return nil, errInvalidRegistryTransport
	}
	added := make(map[string]struct{}, len(members))
	for _, member := range members {
		if !vmcommon.ValidateToken(member.tokenID) {
			return nil, errInvalidRegistryTransport
		}
		id := string(member.tokenID)
		if _, exists := c.members[id]; exists {
			return nil, errInvalidRegistryTransport
		}
		if _, exists := added[id]; exists {
			return nil, errInvalidRegistryTransport
		}
		value, err = read(append([]byte(registryMemberKeyPrefix), member.tokenID...), member.proof)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(value, []byte{1}) {
			return nil, errInvalidRegistryTransport
		}
		added[id] = struct{}{}
	}
	return &registryCandidate{parent: c, before: copyRegistryAnchor(before), after: copyRegistryAnchor(after), added: added}, nil
}

// stage is an isolated execution-shard import, using a committed/exclusively
// owned native user-account store. Native saves and visibility share the same
// contained operation. On failure no view is published; a failed rollback keeps
// this parent occupied until authoritative native recovery succeeds.
func (v *registryCandidate) stage(accounts state.AccountsAdapter) error {
	c := v.parent
	c.mut.Lock()
	defer c.mut.Unlock()
	if v.material != nil || c.active != nil || !sameRegistryAnchor(&c.anchor, &v.before) {
		return errInvalidRegistryTransport
	}
	m, err := newRegistryMaterialization(accounts, &v.after)
	if err != nil {
		return err
	}
	v.material = m
	c.active = v
	ids := make([]string, 0, len(v.added))
	for id := range v.added {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	err = m.owner.Execute(func() (*vmcommon.VMOutput, error) {
		for _, id := range ids {
			if err := m.state.materializeMembership([]byte(id)); err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	if err != nil {
		m.owner.mut.Lock()
		if m.owner.failure == nil {
			c.active = nil
		}
		m.owner.mut.Unlock()
		return err
	}
	v.ready = true
	return nil
}

// classify can be read inside an existing contained operation (nested native
// work belongs to that operation). It never admits a second Execute and does
// not claim to serialize external account aliases. The native executor must
// serialize classification with effects and declared scheduler dependencies.
func (v *registryCandidate) classify(candidateHash, tokenID []byte) (bool, error) {
	c := v.parent
	c.mut.RLock()
	defer c.mut.RUnlock()
	if c.active != v || v.material == nil {
		return false, errInvalidMetaContext
	}
	v.material.owner.mut.Lock()
	defer v.material.owner.mut.Unlock()
	if v.material.owner.failure != nil {
		return false, v.material.owner.failure
	}
	if v.material.owner.closed {
		return false, ErrExecutionClosed
	}
	if !v.ready || !bytes.Equal(candidateHash, v.after.candidateHash) {
		return false, errInvalidMetaContext
	}
	id := string(tokenID)
	_, old := c.members[id]
	_, added := v.added[id]
	return old || added, nil
}

// commit forwards the contained native roots and VM outputs only after native
// persistence and projection publication succeed. Its caller still owns native
// block finalization; this receipt cannot establish canonical finality.
func (v *registryCandidate) commit() ([][]byte, []*vmcommon.VMOutput, error) {
	c := v.parent
	c.mut.Lock()
	defer c.mut.Unlock()
	if c.active != v || v.material == nil {
		return nil, nil, errInvalidRegistryTransport
	}
	v.material.owner.mut.Lock()
	available := v.material.owner.checkAvailable()
	v.material.owner.mut.Unlock()
	if available != nil {
		return nil, nil, available
	}
	if !v.ready {
		return nil, nil, errInvalidRegistryTransport
	}
	roots, outputs, err := v.material.owner.Commit()
	if err != nil {
		return nil, nil, err
	}
	for id := range v.added {
		c.members[id] = struct{}{}
	}
	c.anchor = copyRegistryAnchor(&v.after)
	c.active = nil
	v.ready = false
	return roots, outputs, nil
}

func (v *registryCandidate) abort() error {
	c := v.parent
	c.mut.Lock()
	defer c.mut.Unlock()
	if c.active != v || v.material == nil {
		return errInvalidRegistryTransport
	}
	if err := v.material.abort(); err != nil {
		return err
	}
	c.active = nil
	v.ready = false
	return nil
}

func (v *registryCandidate) recover() error {
	c := v.parent
	c.mut.Lock()
	defer c.mut.Unlock()
	if c.active != v || v.material == nil {
		return errInvalidRegistryTransport
	}
	if err := v.material.owner.Recover(); err != nil {
		return err
	}
	c.active = nil
	v.ready = false
	return nil
}
