package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// EXPERIMENTAL storage/framing only, not AR28 release allocations. This is
// Part A §3.4's existing GAS and ActiveGovernedActionSet, not another registry.
const governedActionPrefix = core.ProtectedKeyPrefix + "DRWA@governedAction@"

var errGovernedActionRecord = errors.New("invalid DRWA governed action construction")

type governedActionProposal struct {
	subject, class, token, payload, bindings []byte
	nonce                                    uint64
	earliest, until                          HeaderMilliseconds
}

// The exclusive native metachain owner must supply this host; none is provided.
// It validates COMPLETE class bodies, purposes/current generations, admitted
// limits/rate/retention/funding and canonical initialization/cleanup provenance.
// Protected eligibility and arm/local kind come from that retained class and
// lawful authority, never a requester-selected category or arbitrary bool.
// ApplyStart owns the entire native first effect or one bound projection output.
// All its stores/accounting must be inside the SAME T04 boundary. Hosts cannot
// invalidate a leased header or retain/mutate borrowed aliases during effects.
// Actual T42/G3/authority/codec/funding hosts remain first-consumer gates.
type governedActionHost interface {
	Initialize(identity, token []byte) error
	Proposal(envelope []byte, retainedBytes uint64) (minimum, maximum HeaderMilliseconds, protected bool, err error)
	Authorize(id, digest, envelope, certificates []byte) error
	Start(id, digest, envelope, certificates []byte) (arm bool, lifetime HeaderMilliseconds, err error)
	ApplyStart(id, digest, envelope []byte, arm bool, expiry HeaderMilliseconds) (*vmcommon.VMOutput, error)
	Cleanup(id, envelope []byte, status, reason string, evidence []byte) error
	IsInterfaceNil() bool
}

type governedActionRecords struct {
	codec                      *registrationRecords
	boundary                   *RollbackContainment
	host                       governedActionHost
	domain                     []byte
	total, ordinary, protected uint64
}

type governedActionRecord struct {
	envelope, digest, id []byte
	proposal             governedActionProposal
	window               governedActionWindow
	status, reason       string
	protected            bool
	started, expiry      HeaderMilliseconds
}

type governedActionMember struct {
	id        []byte
	protected bool
}

func newGovernedActionRecords(accounts state.AccountsAdapter, boundary *RollbackContainment,
	marshaller marshal.Marshalizer, hasher hashing.Hasher, maxBytes int, domain []byte,
	total, ordinary, protected uint64, host governedActionHost) (*governedActionRecords, error) {
	if boundary == nil || check.IfNil(host) || len(domain) == 0 || len(domain) > maxBytes || total == 0 {
		return nil, errGovernedActionRecord
	}
	sum, err := core.SafeAddUint64(ordinary, protected)
	if err != nil || sum != total {
		return nil, errGovernedActionRecord
	}
	owned := false
	for _, store := range boundary.stores {
		owned = owned || store == accounts
	}
	if !owned {
		return nil, errGovernedActionRecord
	}
	codec, err := newRegistrationRecords(accounts, marshaller, hasher, maxBytes)
	if err != nil {
		return nil, err
	}
	return &governedActionRecords{codec: codec, boundary: boundary, host: host,
		domain: bytes.Clone(domain), total: total, ordinary: ordinary, protected: protected}, nil
}

func (g *governedActionRecords) key(kind string, fields ...[]byte) ([]byte, error) {
	encoded, err := g.codec.frame(fields...)
	return append([]byte(governedActionPrefix+kind+"@"), encoded...), err
}

func (g *governedActionRecords) read(key []byte) ([]byte, error) {
	a, err := g.codec.state.systemAccount()
	if err != nil {
		return nil, err
	}
	value, _, err := a.RetrieveValue(key)
	if err != nil {
		return nil, err
	}
	if len(value) > g.codec.maxBytes {
		return nil, errGovernedActionRecord
	}
	return bytes.Clone(value), nil
}

type governedActionWrite struct{ key, value []byte }

func (g *governedActionRecords) save(writes ...governedActionWrite) error {
	// Reload after callbacks/native effects: do not overwrite their other fields.
	a, err := g.codec.state.systemAccount()
	if err != nil {
		return err
	}
	for _, w := range writes {
		if err = a.SaveKeyValue(w.key, w.value); err != nil {
			return err
		}
	}
	return g.codec.state.accounts.SaveAccount(a)
}

func (g *governedActionRecords) unchanged(snapshot ...governedActionWrite) error {
	for _, s := range snapshot {
		current, err := g.read(s.key)
		if err != nil {
			return err
		}
		if !bytes.Equal(current, s.value) {
			return errGovernedActionRecord
		}
	}
	return nil
}

func (g *governedActionRecords) lease(context *HeaderTimeContext) (func(), error) {
	if _, err := governedTimeAt(context, core.MetachainShardId); err != nil {
		return nil, err
	}
	context.owner.mut.RLock()
	if context.owner.current != context {
		context.owner.mut.RUnlock()
		return nil, ErrInactiveHeaderTime
	}
	return context.owner.mut.RUnlock, nil
}

func (g *governedActionRecords) aggregate(members []governedActionMember) ([]byte, error) {
	if uint64(len(members)) > g.total || len(members) > g.codec.maxBytes/2 {
		return nil, errGovernedActionRecord
	}
	fields := make([][]byte, 0, len(members))
	var ordinary uint64
	for i, m := range members {
		if len(m.id) != g.codec.hasher.Size() || i > 0 && bytes.Compare(members[i-1].id, m.id) >= 0 {
			return nil, errGovernedActionRecord
		}
		category := byte(0)
		if m.protected {
			category = 1
		} else {
			ordinary++
		}
		v, err := g.codec.frame(m.id, []byte{category})
		if err != nil {
			return nil, err
		}
		fields = append(fields, v)
	}
	if ordinary > g.ordinary || uint64(len(members))-ordinary > g.protected {
		return nil, errGovernedActionRecord
	}
	entries, err := g.codec.frame(fields...)
	if err != nil {
		return nil, err
	}
	return g.codec.frame(binary.BigEndian.AppendUint64(nil, uint64(len(members))),
		binary.BigEndian.AppendUint64(nil, ordinary), g.codec.hasher.Compute(string(entries)), entries)
}

func (g *governedActionRecords) members(value []byte) ([]governedActionMember, error) {
	f, err := g.codec.unframe(value, 4)
	if err != nil || len(f[0]) != 8 || len(f[1]) != 8 || len(f[2]) != g.codec.hasher.Size() {
		return nil, errGovernedActionRecord
	}
	count := binary.BigEndian.Uint64(f[0])
	if count > g.total || count > uint64(g.codec.maxBytes/2) {
		return nil, errGovernedActionRecord
	}
	var entries [][]byte
	if count == 0 {
		if len(f[3]) != 0 {
			return nil, errGovernedActionRecord
		}
	} else if entries, err = g.codec.unframe(f[3], int(count)); err != nil {
		return nil, err
	}
	result := make([]governedActionMember, 0, len(entries))
	for _, entry := range entries {
		e, err := g.codec.unframe(entry, 2)
		if err != nil || len(e[1]) != 1 || e[1][0] > 1 {
			return nil, errGovernedActionRecord
		}
		result = append(result, governedActionMember{id: bytes.Clone(e[0]), protected: e[1][0] == 1})
	}
	canonical, err := g.aggregate(result)
	if err != nil || !bytes.Equal(canonical, value) {
		return nil, errGovernedActionRecord
	}
	return result, nil
}

// initialize is ONLY the explicit admitted activation/genesis/migration owner.
// No proposal calls it, and repeated initialization cannot reset a live counter.
func (g *governedActionRecords) initialize(context *HeaderTimeContext, subject, class, token []byte) error {
	if len(subject) == 0 || len(class) == 0 || len(token) > g.codec.maxBytes ||
		len(token) != 0 && !vmcommon.ValidateToken(token) {
		return errGovernedActionRecord
	}
	identity, err := g.codec.frame(g.domain, subject, class)
	if err != nil {
		return err
	}
	// External initialization can hold the caller's original buffers. Retain
	// the authenticated input after bounded framing and before any callback.
	subject, class, token = bytes.Clone(subject), bytes.Clone(class), bytes.Clone(token)
	return g.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		counterKey, err := g.key("nonce", g.domain, subject, class)
		if err != nil {
			return nil, err
		}
		counter, err := g.read(counterKey)
		if err != nil {
			return nil, err
		}
		snapshot := []governedActionWrite{{counterKey, counter}}
		if len(token) != 0 {
			key, err := g.key("active", g.domain, token)
			if err != nil {
				return nil, err
			}
			value, err := g.read(key)
			if err != nil {
				return nil, err
			}
			snapshot = append(snapshot, governedActionWrite{key, value})
		}
		if err = g.host.Initialize(bytes.Clone(identity), bytes.Clone(token)); err != nil {
			return nil, err
		}
		if err = g.unchanged(snapshot...); err != nil {
			return nil, err
		}
		release, err := g.lease(context)
		if err != nil {
			return nil, err
		}
		defer release()
		if len(counter) != 0 && len(counter) != 8 {
			return nil, errGovernedActionRecord
		}
		var writes []governedActionWrite
		if len(counter) == 0 {
			writes = append(writes, governedActionWrite{counterKey, make([]byte, 8)})
		}
		if len(token) != 0 {
			key, err := g.key("active", g.domain, token)
			if err != nil {
				return nil, err
			}
			v, err := g.read(key)
			if err != nil {
				return nil, err
			}
			if len(v) == 0 {
				v, err = g.aggregate(nil)
				if err != nil {
					return nil, err
				}
				writes = append(writes, governedActionWrite{key, v})
			} else if _, err = g.members(v); err != nil {
				return nil, err
			}
		}
		if len(writes) == 0 {
			return nil, nil
		}
		return nil, g.save(writes...)
	})
}

func (g *governedActionRecords) envelope(p governedActionProposal, proposed HeaderMilliseconds) ([]byte, error) {
	if len(p.subject) == 0 || len(p.class) == 0 || len(p.payload) == 0 || len(p.bindings) == 0 ||
		len(p.token) > g.codec.maxBytes || len(p.token) != 0 && !vmcommon.ValidateToken(p.token) {
		return nil, errGovernedActionRecord
	}
	return g.codec.frame(g.domain, p.subject, p.class, p.token, binary.BigEndian.AppendUint64(nil, p.nonce),
		binary.BigEndian.AppendUint64(nil, uint64(proposed)), binary.BigEndian.AppendUint64(nil, uint64(p.earliest)),
		binary.BigEndian.AppendUint64(nil, uint64(p.until)), p.payload, p.bindings)
}

func (g *governedActionRecords) identity(envelope []byte, p governedActionProposal) (digest, id []byte) {
	// Both preimages are experimental physical allocations. The GAS domain is
	// prescribed by Part A; the complete immutable envelope is never a display hash.
	digest = g.codec.hasher.Compute("DRWA/GAS/PAYLOAD/v1" + string(envelope))
	id = g.codec.hasher.Compute("DRWA/GAS/v1" + string(g.domain) + string(p.subject) +
		string(p.class) + string(binary.BigEndian.AppendUint64(nil, p.nonce)) + string(digest))
	return
}

func (g *governedActionRecords) encode(r *governedActionRecord) ([]byte, error) {
	category := byte(0)
	if r.protected {
		category = 1
	}
	return g.codec.frame(r.envelope, r.digest, []byte(r.status), []byte{category},
		binary.BigEndian.AppendUint64(nil, uint64(r.started)), binary.BigEndian.AppendUint64(nil, uint64(r.expiry)), []byte(r.reason))
}

func (g *governedActionRecords) load(id []byte) (*governedActionRecord, []byte, []byte, error) {
	if len(id) != g.codec.hasher.Size() {
		return nil, nil, nil, errGovernedActionRecord
	}
	key, err := g.key("action", g.domain, id)
	if err != nil {
		return nil, nil, nil, err
	}
	v, err := g.read(key)
	if err != nil {
		return nil, nil, nil, err
	}
	f, err := g.codec.unframe(v, 7)
	if err != nil || len(f[1]) != g.codec.hasher.Size() || len(f[3]) != 1 || f[3][0] > 1 || len(f[4]) != 8 || len(f[5]) != 8 {
		return nil, nil, nil, errGovernedActionRecord
	}
	e, err := g.codec.unframe(f[0], 10)
	if err != nil || !bytes.Equal(e[0], g.domain) || len(e[4]) != 8 || len(e[5]) != 8 || len(e[6]) != 8 || len(e[7]) != 8 {
		return nil, nil, nil, errGovernedActionRecord
	}
	p := governedActionProposal{subject: e[1], class: e[2], token: e[3], nonce: binary.BigEndian.Uint64(e[4]),
		earliest: HeaderMilliseconds(binary.BigEndian.Uint64(e[6])), until: HeaderMilliseconds(binary.BigEndian.Uint64(e[7])), payload: e[8], bindings: e[9]}
	proposed := HeaderMilliseconds(binary.BigEndian.Uint64(e[5]))
	canonical, err := g.envelope(p, proposed)
	digest, expected := g.identity(f[0], p)
	if err != nil || !bytes.Equal(canonical, f[0]) || !bytes.Equal(digest, f[1]) || !bytes.Equal(expected, id) || p.earliest < proposed || p.until <= p.earliest {
		return nil, nil, nil, errGovernedActionRecord
	}
	r := &governedActionRecord{envelope: bytes.Clone(f[0]), digest: digest, id: bytes.Clone(id), proposal: p,
		window: governedActionWindow{proposedAt: proposed, earliest: p.earliest, validUntil: p.until},
		status: string(f[2]), reason: string(f[6]), protected: f[3][0] == 1,
		started: HeaderMilliseconds(binary.BigEndian.Uint64(f[4])), expiry: HeaderMilliseconds(binary.BigEndian.Uint64(f[5]))}
	valid := (r.status == "PROPOSED" || r.status == "EXECUTABLE") && r.started == 0 && r.expiry == 0 && r.reason == "" ||
		r.status == "IN_PROGRESS" && r.started >= p.earliest && r.started < p.until && (r.expiry == 0 || r.expiry >= r.started) && r.reason == "" ||
		r.status == "EXPIRED" && r.started == 0 && r.expiry == 0 && r.reason == "EXPIRED" ||
		r.status == "CANCELLED" && r.started == 0 && r.expiry == 0 && r.reason == "STALE_BINDING"
	if !valid {
		return nil, nil, nil, errGovernedActionRecord
	}
	// Every retained GAS was created with an advanced explicit class counter.
	// Missing/restored counters cannot revive an old action's replay domain.
	counterKey, err := g.key("nonce", g.domain, p.subject, p.class)
	if err != nil {
		return nil, nil, nil, err
	}
	counter, err := g.read(counterKey)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(counter) != 8 || binary.BigEndian.Uint64(counter) <= p.nonce {
		return nil, nil, nil, errGovernedActionRecord
	}
	return r, key, v, nil
}

func (g *governedActionRecords) counterSnapshot(r *governedActionRecord) (governedActionWrite, error) {
	key, err := g.key("nonce", g.domain, r.proposal.subject, r.proposal.class)
	if err != nil {
		return governedActionWrite{}, err
	}
	value, err := g.read(key)
	return governedActionWrite{key, value}, err
}

func (g *governedActionRecords) active(r *governedActionRecord) ([]governedActionMember, []byte, []byte, error) {
	if len(r.proposal.token) == 0 {
		return nil, nil, nil, nil
	}
	key, err := g.key("active", g.domain, r.proposal.token)
	if err != nil {
		return nil, nil, nil, err
	}
	v, err := g.read(key)
	if err != nil {
		return nil, nil, nil, err
	}
	m, err := g.members(v)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, member := range m {
		if bytes.Equal(member.id, r.id) && member.protected == r.protected {
			return m, key, v, nil
		}
	}
	return nil, nil, nil, errGovernedActionRecord
}

func (g *governedActionRecords) propose(context *HeaderTimeContext, p governedActionProposal) ([]byte, error) {
	var result []byte
	err := g.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		time, err := governedTimeAt(context, core.MetachainShardId)
		if err != nil {
			return nil, err
		}
		envelope, err := g.envelope(p, time)
		if err != nil {
			return nil, err
		}
		digest, id := g.identity(envelope, p)
		r := &governedActionRecord{envelope: envelope, digest: digest, id: id, proposal: p, status: "PROPOSED"}
		// Prove every future retained shape fits before verifier/new-state work.
		if _, err = g.codec.frame(envelope, digest, []byte("IN_PROGRESS"), []byte{0}, make([]byte, 8), make([]byte, 8), []byte("STALE_BINDING")); err != nil {
			return nil, err
		}
		counterKey, err := g.key("nonce", g.domain, p.subject, p.class)
		if err != nil {
			return nil, err
		}
		counter, err := g.read(counterKey)
		if err != nil {
			return nil, err
		}
		if len(counter) != 8 || binary.BigEndian.Uint64(counter) != p.nonce {
			return nil, errGovernedActionRecord
		}
		next, err := core.SafeAddUint64(p.nonce, 1)
		if err != nil {
			return nil, err
		}
		actionKey, err := g.key("action", g.domain, id)
		if err != nil {
			return nil, err
		}
		existing, err := g.read(actionKey)
		if err != nil {
			return nil, err
		}
		if len(existing) != 0 {
			return nil, errGovernedActionRecord
		}
		snapshot := []governedActionWrite{{counterKey, counter}, {actionKey, nil}}
		var activeKey, oldAggregate, newAggregate []byte
		var members []governedActionMember
		encoded, err := g.encode(r)
		if err != nil {
			return nil, err
		}
		retained := uint64(len(actionKey) + len(encoded))
		if len(p.token) != 0 {
			activeKey, err = g.key("active", g.domain, p.token)
			if err != nil {
				return nil, err
			}
			oldAggregate, err = g.read(activeKey)
			if err != nil {
				return nil, err
			}
			members, err = g.members(oldAggregate)
			if err != nil {
				return nil, err
			}
			if uint64(len(members)) >= g.total {
				return nil, errGovernedActionRecord
			}
			snapshot = append(snapshot, governedActionWrite{activeKey, oldAggregate})
			// The category's encoded width is identical; aggregate length delta
			// does not depend on which category the mandatory host resolves.
			entry, err := g.codec.frame(id, []byte{0})
			if err != nil {
				return nil, err
			}
			// Canonical nested native Batch varints can grow at a boundary.
			fields, err := g.codec.unframe(oldAggregate, 4)
			if err != nil {
				return nil, err
			}
			entryFrame, err := g.codec.frame(entry)
			if err != nil {
				return nil, err
			}
			nested := append(bytes.Clone(fields[3]), entryFrame...)
			probe, err := g.codec.frame(make([]byte, 8), make([]byte, 8), digest, nested)
			if err != nil {
				return nil, err
			}
			retained += uint64(len(probe) - len(oldAggregate))
		}
		minimum, maximum, protected, err := g.host.Proposal(bytes.Clone(envelope), retained)
		if err != nil {
			return nil, err
		}
		window, err := newGovernedActionWindow(context, minimum, maximum, p.earliest, p.until)
		if err != nil || window.proposedAt != time {
			if err != nil {
				return nil, err
			}
			return nil, ErrInactiveHeaderTime
		}
		r.protected, r.window = protected, *window
		encoded, err = g.encode(r)
		if err != nil {
			return nil, err
		}
		if len(p.token) != 0 {
			members = append(members, governedActionMember{id: id, protected: protected})
			sort.Slice(members, func(i, j int) bool { return bytes.Compare(members[i].id, members[j].id) < 0 })
			newAggregate, err = g.aggregate(members)
			if err != nil {
				return nil, err
			}
		}
		release, err := g.lease(context)
		if err != nil {
			return nil, err
		}
		defer release()
		if err = g.unchanged(snapshot...); err != nil {
			return nil, err
		}
		writes := []governedActionWrite{{counterKey, binary.BigEndian.AppendUint64(nil, next)}, {actionKey, encoded}}
		if len(activeKey) != 0 {
			writes = append(writes, governedActionWrite{activeKey, newAggregate})
		}
		if err = g.save(writes...); err != nil {
			return nil, err
		}
		result = bytes.Clone(id)
		return nil, nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (g *governedActionRecords) authorize(context *HeaderTimeContext, id, certificates []byte) error {
	return g.transition(context, id, certificates, false)
}

func (g *governedActionRecords) start(context *HeaderTimeContext, id, certificates []byte) error {
	return g.transition(context, id, certificates, true)
}

func (g *governedActionRecords) transition(context *HeaderTimeContext, id, certificates []byte, start bool) error {
	if len(certificates) > g.codec.maxBytes {
		return errGovernedActionRecord
	}
	return g.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		r, key, value, err := g.load(id)
		if err != nil {
			return nil, err
		}
		if start && r.status != "EXECUTABLE" || !start && r.status != "PROPOSED" && r.status != "EXECUTABLE" {
			return nil, errGovernedActionRecord
		}
		if err = r.window.mayStart(context); err != nil {
			return nil, err
		}
		_, activeKey, activeValue, err := g.active(r)
		if err != nil {
			return nil, err
		}
		snapshot := []governedActionWrite{{key, value}}
		counter, err := g.counterSnapshot(r)
		if err != nil {
			return nil, err
		}
		snapshot = append(snapshot, counter)
		if len(activeKey) != 0 {
			snapshot = append(snapshot, governedActionWrite{activeKey, activeValue})
		}
		var arm bool
		var lifetime HeaderMilliseconds
		if start {
			arm, lifetime, err = g.host.Start(bytes.Clone(id), bytes.Clone(r.digest), bytes.Clone(r.envelope), bytes.Clone(certificates))
		} else {
			err = g.host.Authorize(bytes.Clone(id), bytes.Clone(r.digest), bytes.Clone(r.envelope), bytes.Clone(certificates))
		}
		if err != nil {
			return nil, err
		}
		release, err := g.lease(context)
		if err != nil {
			return nil, err
		}
		defer release()
		if err = g.unchanged(snapshot...); err != nil {
			return nil, err
		}
		if !start && r.status == "EXECUTABLE" {
			return nil, nil
		}
		r.status = "EXECUTABLE"
		var output *vmcommon.VMOutput
		if start {
			r.status, r.started = "IN_PROGRESS", HeaderMilliseconds(context.timestamp)
			if arm {
				expiry, err := core.SafeAddUint64(context.timestamp, uint64(lifetime))
				if err != nil {
					return nil, err
				}
				r.expiry = HeaderMilliseconds(expiry)
			}
			output, err = g.host.ApplyStart(bytes.Clone(id), bytes.Clone(r.digest), bytes.Clone(r.envelope), arm, r.expiry)
			if err != nil {
				return nil, err
			}
			if output == nil || output.ReturnCode != vmcommon.Ok {
				return nil, errGovernedActionRecord
			}
			if err = g.unchanged(snapshot...); err != nil {
				return nil, err
			}
		}
		encoded, err := g.encode(r)
		if err != nil {
			return nil, err
		}
		if err = g.save(governedActionWrite{key, encoded}); err != nil {
			return nil, err
		}
		return output, nil
	})
}

// Only the two specified proof-driven UNSTARTED cleanup paths are exposed.
// No discretionary cancellation, IN_PROGRESS TTL, UNUSED ACK or compensation
// can enter here. Actual class-specific terminal removal remains its owner.
func (g *governedActionRecords) cleanup(context *HeaderTimeContext, id []byte, reason string, evidence []byte) error {
	if reason != "EXPIRED" && reason != "STALE_BINDING" || len(evidence) > g.codec.maxBytes {
		return errGovernedActionRecord
	}
	return g.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		r, key, value, err := g.load(id)
		if err != nil {
			return nil, err
		}
		if r.status != "PROPOSED" && r.status != "EXECUTABLE" {
			return nil, errGovernedActionRecord
		}
		time, err := governedTimeAt(context, core.MetachainShardId)
		if err != nil {
			return nil, err
		}
		if reason == "EXPIRED" && time < r.window.validUntil {
			return nil, errGovernedActionTime
		}
		members, activeKey, activeValue, err := g.active(r)
		if err != nil {
			return nil, err
		}
		snapshot := []governedActionWrite{{key, value}}
		counter, err := g.counterSnapshot(r)
		if err != nil {
			return nil, err
		}
		snapshot = append(snapshot, counter)
		if len(activeKey) != 0 {
			snapshot = append(snapshot, governedActionWrite{activeKey, activeValue})
		}
		if err = g.host.Cleanup(bytes.Clone(id), bytes.Clone(r.envelope), r.status, reason, bytes.Clone(evidence)); err != nil {
			return nil, err
		}
		release, err := g.lease(context)
		if err != nil {
			return nil, err
		}
		defer release()
		if err = g.unchanged(snapshot...); err != nil {
			return nil, err
		}
		r.status, r.reason = "CANCELLED", reason
		if reason == "EXPIRED" {
			r.status = "EXPIRED"
		}
		encoded, err := g.encode(r)
		if err != nil {
			return nil, err
		}
		writes := []governedActionWrite{{key, encoded}}
		if len(activeKey) != 0 {
			remaining := make([]governedActionMember, 0, len(members)-1)
			for _, m := range members {
				if !bytes.Equal(m.id, id) {
					remaining = append(remaining, m)
				}
			}
			aggregate, err := g.aggregate(remaining)
			if err != nil {
				return nil, err
			}
			writes = append(writes, governedActionWrite{activeKey, aggregate})
		}
		return nil, g.save(writes...)
	})
}
