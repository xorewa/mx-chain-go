package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// EXPERIMENTAL physical representation of the existing ConvergenceState.
// GAS-backed phase contexts reuse the owning action and immutable digest.
// No allocated release prefix/codec, additional nonce or production importer.
const convergencePrefix = core.ProtectedKeyPrefix + "DRWA@convergence@"

var errConvergence = errors.New("invalid DRWA convergence construction")

type convergenceTransition struct {
	action, digest, token, target, dependencies, requiredSet []byte
	version                                                  uint64
	shards                                                   []uint32
	context                                                  *convergencePhaseContext
}

// convergencePhaseContext is DRWA's experimental containing context, not a
// wire field or a new identity. The native owner resolves every byte against
// its canonical family/phase, original source/outcome and lawful successor
// lineage. predecessor is the exact durable prerequisite receipt commitment.
// No family or phase value is allocated here. A nil context retains ONLY the
// existing CEB_CURRENTIZATION/CURRENT_ACK representation; an explicit context
// cannot name that pair. Every other pair requires an explicit context, which
// never defaults a missing coordinate to that family or phase.
type convergencePhaseContext struct {
	family, phase, lineage, predecessor []byte
}

// convergenceHost belongs to the exclusive native metachain GAS/phase owner.
// No default exists. VerifyTransition binds the FULL immutable authoritative
// GAS/action/phase/CEB/dependency body and exact configured required shard set.
// VerifyAck proves payload membership in the complete producing result and the
// authenticated S/result/root/H/M/B relation under the qualified route predicate;
// its returned producer is independent of the payload's claimed shard. It also
// proves exact local application and every required dependency, not presence.
// Admission positively authenticates canonical phase creation and non-reuse,
// co-journals its durable creation receipt, and reserves retained capacity AND
// prepaid full fan-out/ACK/parent work. Missing progress is not that evidence;
// after compaction/loss the retained owner receipt must prevent recreation.
// The immutable lineage binds original source/outcome and any lawful successor;
// parent checks include metachain's OWN required evidence, separately from the
// execution-shard bitmap. These obligations have no permissive default host.
// Complete and VerifyParent operate on that SAME parent's durable phase receipt
// within the same T04 stores. Actual G3/funding/ACK producers remain unwired gates.
type convergenceHost interface {
	VerifyTransition(binding []byte) error
	Admission(binding []byte, retainedBytes uint64) error
	VerifyAck(binding, ack, evidence []byte) (uint32, error)
	Complete(binding, commitment []byte) (*vmcommon.VMOutput, error)
	VerifyParent(binding, commitment []byte) error
	IsInterfaceNil() bool
}

type convergenceRecords struct {
	codec     *registrationRecords
	boundary  *RollbackContainment
	host      convergenceHost
	maxShards int
}

type convergenceProgress struct {
	status     string
	bitmap     []byte
	acks       [][]byte
	commitment []byte
}

func newConvergenceRecords(accounts state.AccountsAdapter, boundary *RollbackContainment,
	marshaller marshal.Marshalizer, hasher hashing.Hasher, maxBytes, maxShards int,
	host convergenceHost) (*convergenceRecords, error) {
	if boundary == nil || check.IfNil(host) || maxShards <= 0 || maxShards > maxBytes/6 {
		return nil, errConvergence
	}
	owned := false
	for _, store := range boundary.stores {
		if store == accounts {
			owned = true
		}
	}
	if !owned {
		return nil, errConvergence
	}
	codec, err := newRegistrationRecords(accounts, marshaller, hasher, maxBytes)
	if err != nil {
		return nil, err
	}
	return &convergenceRecords{codec: codec, boundary: boundary, host: host, maxShards: maxShards}, nil
}

func (r *convergenceRecords) encode(t convergenceTransition) (key, binding []byte, err error) {
	if len(t.token) > r.codec.maxBytes || !vmcommon.ValidateToken(t.token) ||
		len(t.action) != r.codec.hasher.Size() || len(t.digest) != r.codec.hasher.Size() ||
		len(t.target) != r.codec.hasher.Size() || len(t.dependencies) != r.codec.hasher.Size() ||
		len(t.requiredSet) != r.codec.hasher.Size() || len(t.shards) == 0 || len(t.shards) > r.maxShards {
		return nil, nil, errConvergence
	}
	ids := make([][]byte, len(t.shards))
	for i, shard := range t.shards {
		if shard == core.MetachainShardId || i > 0 && shard <= t.shards[i-1] {
			return nil, nil, errConvergence
		}
		ids[i] = binary.BigEndian.AppendUint32(nil, shard)
	}
	set, err := r.codec.frame(ids...)
	if err != nil || !bytes.Equal(r.codec.hasher.Compute(string(set)), t.requiredSet) {
		return nil, nil, errConvergence
	}
	family, phase := []byte("CEB_CURRENTIZATION"), []byte("CURRENT_ACK")
	var extra [][]byte
	if t.context != nil {
		c := t.context
		if len(c.family) == 0 || len(c.phase) == 0 || len(c.lineage) == 0 || len(c.predecessor) != r.codec.hasher.Size() {
			return nil, nil, errConvergence
		}
		if bytes.Equal(c.family, family) && bytes.Equal(c.phase, phase) {
			return nil, nil, errConvergence
		}
		family, phase = c.family, c.phase
		extra = [][]byte{c.lineage, c.predecessor}
	}
	fields := [][]byte{family, t.action, t.digest, phase, t.token,
		binary.BigEndian.AppendUint64(nil, t.version), t.target, t.dependencies, t.requiredSet, set}
	binding, err = r.codec.frame(append(fields, extra...)...)
	if err != nil {
		return nil, nil, err
	}
	identityFields := [][]byte{family, t.action, phase}
	if t.context != nil {
		identityFields = append(identityFields, t.context.lineage)
	}
	identity, err := r.codec.frame(identityFields...)
	return append([]byte(convergencePrefix), identity...), binding, err
}

func (r *convergenceRecords) value(binding []byte, p *convergenceProgress) ([]byte, error) {
	acks, err := r.codec.frame(p.acks...)
	if err != nil {
		return nil, err
	}
	preimage, err := r.codec.frame(binding, p.bitmap, acks)
	if err != nil {
		return nil, err
	}
	p.commitment = r.codec.hasher.Compute(string(preimage))
	return r.codec.frame(binding, []byte(p.status), p.bitmap, acks, p.commitment)
}

func (r *convergenceRecords) read(key []byte) ([]byte, error) {
	account, err := r.codec.state.systemAccount()
	if err != nil {
		return nil, err
	}
	value, _, err := account.RetrieveValue(bytes.Clone(key))
	if err != nil {
		return nil, err
	}
	if len(value) > r.codec.maxBytes {
		return nil, errConvergence
	}
	return bytes.Clone(value), nil
}

func (r *convergenceRecords) load(key, binding []byte, count int) (*convergenceProgress, error) {
	value, err := r.read(key)
	if err != nil {
		return nil, err
	}
	f, err := r.codec.unframe(value, 5)
	if err != nil || !bytes.Equal(f[0], binding) || len(f[2]) != common.GetBitmapSize(count) {
		return nil, errConvergence
	}
	acks, err := r.codec.unframe(f[3], count)
	if err != nil {
		return nil, errConvergence
	}
	if count%8 != 0 && f[2][len(f[2])-1]&byte(0xff<<uint(count%8)) != 0 {
		return nil, errConvergence
	}
	p := &convergenceProgress{status: string(f[1]), bitmap: f[2], acks: acks}
	for i, ack := range acks {
		set := p.bitmap[i/8]&(1<<uint(i%8)) != 0
		if set && len(ack) != r.codec.hasher.Size() || !set && len(ack) != 0 {
			return nil, errConvergence
		}
	}
	if p.status != "PENDING" && p.status != "COMPLETE" || p.status == "COMPLETE" && !p.full() {
		return nil, errConvergence
	}
	canonical, err := r.value(binding, p)
	if err != nil || !bytes.Equal(canonical, value) {
		return nil, errConvergence
	}
	return p, nil
}

func (p *convergenceProgress) full() bool {
	for i := range p.acks {
		if p.bitmap[i/8]&(1<<uint(i%8)) == 0 {
			return false
		}
	}
	return true
}

func (r *convergenceRecords) save(key, binding []byte, p *convergenceProgress) error {
	value, err := r.value(binding, p)
	if err != nil {
		return err
	}
	// Reload after host parent effects: no stale account can overwrite its writes.
	account, err := r.codec.state.systemAccount()
	if err != nil {
		return err
	}
	if err = account.SaveKeyValue(key, value); err != nil {
		return err
	}
	return r.codec.state.accounts.SaveAccount(account)
}

func (r *convergenceRecords) verifyParent(key, binding []byte, count int, p *convergenceProgress) error {
	if err := r.host.VerifyParent(bytes.Clone(binding), bytes.Clone(p.commitment)); err != nil {
		return err
	}
	current, err := r.load(key, binding, count)
	if err != nil || current.status != p.status || !bytes.Equal(current.commitment, p.commitment) {
		return errConvergence
	}
	return nil
}

// Reuse the bounded native reader around each authentication callback; a
// later verifier must never consume a progress baseline made by an earlier one.
func (r *convergenceRecords) verifyState(key []byte, verify func() error) error {
	before, err := r.read(key)
	if err != nil {
		return err
	}
	if err = verify(); err != nil {
		return err
	}
	after, err := r.read(key)
	if err != nil {
		return err
	}
	if !bytes.Equal(before, after) {
		return errConvergence
	}
	return nil
}

func (r *convergenceRecords) create(t convergenceTransition) error {
	key, binding, err := r.encode(t)
	if err != nil {
		return err
	}
	count := len(t.shards)
	// Ensure the full retained state fits BEFORE host/admission work or creation.
	bound := &convergenceProgress{status: "COMPLETE", bitmap: make([]byte, common.GetBitmapSize(count)), acks: make([][]byte, count)}
	for i := range bound.acks {
		bound.bitmap[i/8] |= 1 << uint(i%8)
		bound.acks[i] = make([]byte, r.codec.hasher.Size())
	}
	value, err := r.value(binding, bound)
	if err != nil {
		return err
	}
	retained := uint64(len(key)) + uint64(len(value))
	return r.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		if e := r.verifyState(key, func() error { return r.host.VerifyTransition(bytes.Clone(binding)) }); e != nil {
			return nil, e
		}
		old, e := r.read(key)
		if e != nil {
			return nil, e
		}
		if len(old) != 0 {
			p, e := r.load(key, binding, count)
			if e == nil && p.status == "COMPLETE" {
				e = r.verifyParent(key, binding, count, p)
			}
			return nil, e
		}
		if e = r.host.Admission(bytes.Clone(binding), retained); e != nil {
			return nil, e
		}
		current, e := r.read(key)
		if e != nil {
			return nil, e
		}
		if len(current) != 0 {
			return nil, errConvergence
		}
		return nil, r.save(key, binding, &convergenceProgress{status: "PENDING",
			bitmap: make([]byte, common.GetBitmapSize(count)), acks: make([][]byte, count)})
	})
}

func (r *convergenceRecords) acknowledge(t convergenceTransition, shard uint32, localExecution, evidence []byte) error {
	key, binding, err := r.encode(t)
	if err != nil {
		return err
	}
	if len(localExecution) != r.codec.hasher.Size() || len(evidence) == 0 || len(evidence) > r.codec.maxBytes {
		return errConvergence
	}
	index := -1
	for i, required := range t.shards {
		if required == shard {
			index = i
		}
	}
	if index < 0 {
		return errConvergence
	}
	count := len(t.shards)
	ack, err := r.codec.frame(binding, binary.BigEndian.AppendUint32(nil, shard), localExecution)
	if err != nil {
		return err
	}
	evidence = bytes.Clone(evidence)
	return r.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		if e := r.verifyState(key, func() error { return r.host.VerifyTransition(bytes.Clone(binding)) }); e != nil {
			return nil, e
		}
		var producer uint32
		e := r.verifyState(key, func() error {
			var err error
			producer, err = r.host.VerifyAck(bytes.Clone(binding), bytes.Clone(ack), bytes.Clone(evidence))
			return err
		})
		if e != nil {
			return nil, e
		}
		if producer != shard {
			return nil, errConvergence
		}
		p, e := r.load(key, binding, count)
		if e != nil {
			return nil, e
		}
		credited := p.bitmap[index/8]&(1<<uint(index%8)) != 0
		if credited && !bytes.Equal(p.acks[index], r.codec.hasher.Compute(string(ack))) {
			return nil, errConvergence
		}
		if p.status == "COMPLETE" {
			return nil, r.verifyParent(key, binding, count, p)
		}
		if credited {
			return nil, nil // authenticate before recognizing the existing credit
		}
		p.bitmap[index/8] |= 1 << uint(index%8)
		p.acks[index] = r.codec.hasher.Compute(string(ack))
		return nil, r.save(key, binding, p)
	})
}

// observe reauthenticates the same canonical owner/context used by state and
// ACK matching. No API/indexer label or current target hash substitutes for a
// retained phase. Completed observations also require the durable parent.
// Returned progress is detached; it is not lifecycle or finality permission.
func (r *convergenceRecords) observe(t convergenceTransition) (binding []byte, progress *convergenceProgress, err error) {
	key, encoded, err := r.encode(t)
	if err != nil {
		return nil, nil, err
	}
	count := len(t.shards)
	err = r.boundary.execute(func() ([]*vmcommon.VMOutput, error) {
		if e := r.verifyState(key, func() error { return r.host.VerifyTransition(bytes.Clone(encoded)) }); e != nil {
			return nil, e
		}
		p, e := r.load(key, encoded, count)
		if e != nil {
			return nil, e
		}
		if p.status == "COMPLETE" {
			if e = r.verifyParent(key, encoded, count, p); e != nil {
				return nil, e
			}
		}
		binding, progress = bytes.Clone(encoded), p
		return nil, nil
	})
	if err != nil {
		return nil, nil, err
	}
	return binding, progress, nil
}

func (r *convergenceRecords) complete(t convergenceTransition) error {
	key, binding, err := r.encode(t)
	if err != nil {
		return err
	}
	count := len(t.shards)
	return r.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		if e := r.verifyState(key, func() error { return r.host.VerifyTransition(bytes.Clone(binding)) }); e != nil {
			return nil, e
		}
		p, e := r.load(key, binding, count)
		if e != nil {
			return nil, e
		}
		if p.status == "COMPLETE" {
			return nil, r.verifyParent(key, binding, count, p)
		}
		if !p.full() {
			return nil, errConvergence
		}
		output, e := r.host.Complete(bytes.Clone(binding), bytes.Clone(p.commitment))
		if e != nil {
			return nil, e
		}
		if output == nil || output.ReturnCode != vmcommon.Ok {
			return nil, errConvergence
		}
		if e = r.verifyParent(key, binding, count, p); e != nil {
			return nil, e
		}
		p.status = "COMPLETE"
		return output, r.save(key, binding, p)
	})
}
