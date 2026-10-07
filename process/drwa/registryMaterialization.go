package drwa

import (
	"bytes"
	"context"
	"sort"
	"sync"

	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// registryMaterialization owns one isolated startup/sync/integrity reconstruction
// boundary, not the incremental per-block projection (Part A L4863-4888). The
// selected required anchor and complete transport projection must already have
// their native context authority. No production importer is installed yet.
//
// The account store must be exclusively owned, with the L26 system account/data
// trie already provisioned. This owner couples local membership saves to T04
// containment and publishes its in-memory view only after every save succeeds.
// It never increments the metachain count or creates registration authority.
// Later native dispatch must classify before account/fee/metadata/token effects;
// calling this component after dispatch is not AN-03 admission.
type registryMaterialization struct {
	mut      sync.RWMutex
	state    *protectedState
	owner    *RollbackContainment
	required metaRegistryAnchor
	members  map[string]struct{}
}

func newRegistryMaterialization(accounts state.AccountsAdapter, required *metaRegistryAnchor) (*registryMaterialization, error) {
	if required == nil || len(required.candidateHash) == 0 || len(required.metaHash) == 0 ||
		len(required.executedHash) == 0 || len(required.root) == 0 {
		return nil, errInvalidMetaContext
	}
	s, err := newProtectedState(accounts)
	if err != nil {
		return nil, err
	}
	u, err := s.systemAccount()
	if err != nil {
		return nil, err
	}
	if len(u.GetRootHash()) == 0 {
		return nil, errInvalidMembership
	}
	owner, err := NewRollbackContainment(accounts)
	if err != nil {
		return nil, err
	}
	return &registryMaterialization{state: s, owner: owner, required: metaRegistryAnchor{
		candidateHash: bytes.Clone(required.candidateHash), metaHash: bytes.Clone(required.metaHash),
		executedHash: bytes.Clone(required.executedHash), root: bytes.Clone(required.root),
		nonce: required.nonce, round: required.round, epoch: required.epoch}}, nil
}

func sameRegistryAnchor(a, b *metaRegistryAnchor) bool {
	return bytes.Equal(a.candidateHash, b.candidateHash) && bytes.Equal(a.metaHash, b.metaHash) &&
		bytes.Equal(a.executedHash, b.executedHash) && bytes.Equal(a.root, b.root) &&
		a.nonce == b.nonce && a.round == b.round && a.epoch == b.epoch
}

// prepare is one reconstruction operation. This is not a per-block full-set
// import. Authenticated completeness depends on the qualified count producer;
// transport's package-private result is the only admissible input. Stable input
// ownership is required until this call returns, as for native proof reading.
func (m *registryMaterialization) prepare(ctx context.Context, view *registryProjection) error {
	m.mut.Lock()
	defer m.mut.Unlock()
	m.owner.mut.Lock()
	available := m.owner.checkAvailable()
	m.owner.mut.Unlock()
	if available != nil {
		return available
	}
	if m.members != nil || view == nil || view.members == nil || !sameRegistryAnchor(&m.required, &view.anchor) {
		return errInvalidRegistryTransport
	}
	if err := m.checkLocalMembership(ctx, view); err != nil {
		return err
	}
	ids := make([]string, 0, len(view.members))
	for id := range view.members {
		ids = append(ids, id)
	}
	// Native journal order must not depend on Go map iteration.
	sort.Strings(ids)
	if err := m.owner.Execute(func() (*vmcommon.VMOutput, error) {
		for _, id := range ids {
			if err := m.state.materializeMembership([]byte(id)); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}); err != nil {
		return err
	}
	m.members = make(map[string]struct{}, len(ids))
	for _, id := range ids {
		m.members[id] = struct{}{}
	}
	return nil
}

// checkLocalMembership reads the sole local writer's native ordinal records
// only at reconstruction. Its work is bounded by the authenticated complete
// global projection, itself bounded by max_ever_regulated_tokens. Unrelated
// system-account leaves are never enumerated (Part A L4874-4881; MT-01).
// Index completeness requires the native writer/count invariant; an arbitrary
// forged canonical store or an old unindexed experimental layout is not admitted.
func (m *registryMaterialization) checkLocalMembership(ctx context.Context, view *registryProjection) error {
	if ctx == nil {
		return errInvalidRegistryTransport
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	account, err := m.state.systemAccount()
	if err != nil {
		return err
	}
	count, err := readLocalMembershipCount(account)
	if err != nil {
		return err
	}
	if count > uint64(len(view.members)) {
		return errInvalidRegistryTransport
	}
	seen := make(map[string]struct{}, count)
	for ordinal := uint64(0); ordinal < count; ordinal++ {
		if err = ctx.Err(); err != nil {
			return err
		}
		id, _, readError := account.RetrieveValue(localMembershipEntryKey(ordinal))
		if readError != nil {
			return readError
		}
		_, present := view.members[string(id)]
		_, duplicate := seen[string(id)]
		if !present || duplicate || !vmcommon.ValidateToken(id) {
			return errInvalidRegistryTransport
		}
		key, e := membershipKey(id)
		if e != nil {
			return e
		}
		marked, e := readMembership(account, key)
		if e != nil {
			return e
		}
		if !marked {
			return errInvalidRegistryTransport
		}
		seen[string(id)] = struct{}{}
	}
	return nil
}

// classify reads memory only. A closed/failed owner, an unprepared view or a
// different candidate never supplies ordinary absence. This private handle is
// invalid after native commit, abort or authoritative recovery. It does not
// authenticate a caller-provided candidate hash or establish native finality.
func (m *registryMaterialization) classify(candidateHash, tokenID []byte) (bool, error) {
	m.mut.RLock()
	defer m.mut.RUnlock()
	m.owner.mut.Lock()
	defer m.owner.mut.Unlock()
	if err := m.owner.checkAvailable(); err != nil {
		return false, err
	}
	if m.members == nil || !bytes.Equal(candidateHash, m.required.candidateHash) {
		return false, errInvalidMetaContext
	}
	_, present := m.members[string(tokenID)]
	return present, nil
}

// abort composes the native zero-snapshot path with handle invalidation. Even a
// failed rollback invalidates the view; recovery remains the T04 owner operation.
// No delta is inferred from a failed rollback's journal length or error.
func (m *registryMaterialization) abort() error {
	m.mut.Lock()
	defer m.mut.Unlock()
	m.owner.mut.Lock()
	defer m.owner.mut.Unlock()
	if err := m.owner.checkAvailable(); err != nil {
		return err
	}
	m.owner.outputs = nil
	if err := m.state.accounts.RevertToSnapshot(0); err != nil {
		m.owner.failure = err
		return err
	}
	m.owner.closed = true
	return nil
}
