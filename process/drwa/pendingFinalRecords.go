package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// Experimental physical representations of Part A §6.1's existing namespaces.
// No release allocation, native importer, ordinary route or global pending scan.
const pendingFinalPrefix = core.ProtectedKeyPrefix + "DRWA@head@"

var errPendingFinal = errors.New("invalid DRWA pending/final construction")

type pendingFinalCandidate struct {
	key, predecessor, body, origin []byte
	version                        uint64
}

// pendingFinalHost has no default. It belongs to the exclusive native owner.
// Admit validates the COMPLETE class-specific body, locus, current F07 material,
// account/control/authority/certificates, lifecycle and resource/funding rules.
// Initialize co-journals required first-write holder/nonce state and reserves
// finalization work. Canonical proves exact origin/result/root/item membership
// and authenticated route-specific S/H/M/B permission. It must NOT interpret
// AccountsDB presence, API labels or a local detector as settlement permission.
// Observe constructs the exact authoritative native observation; it cannot
// publish outputs outside the same consuming-block rollback boundary.
// Actual host implementations/ingress/import order remain first-consumer gates.
type pendingFinalHost interface {
	Admit(candidate []byte) error
	Initialize(candidate []byte) (*vmcommon.VMOutput, error)
	Canonical(candidate, evidence []byte) error
	Observe(candidate []byte) (*vmcommon.VMOutput, error)
	IsInterfaceNil() bool
}

type pendingFinalRecords struct {
	codec    *registrationRecords
	boundary *RollbackContainment
	host     pendingFinalHost
}

func newPendingFinalRecords(accounts state.AccountsAdapter, boundary *RollbackContainment,
	marshaller marshal.Marshalizer, hasher hashing.Hasher, maxBytes int, host pendingFinalHost) (*pendingFinalRecords, error) {
	if boundary == nil || check.IfNil(host) {
		return nil, errPendingFinal
	}
	owned := false
	for _, store := range boundary.stores {
		owned = owned || store == accounts
	}
	if !owned {
		return nil, errPendingFinal
	}
	codec, err := newRegistrationRecords(accounts, marshaller, hasher, maxBytes)
	if err != nil {
		return nil, err
	}
	return &pendingFinalRecords{codec: codec, boundary: boundary, host: host}, nil
}

func (r *pendingFinalRecords) encode(c pendingFinalCandidate) ([]byte, error) {
	if len(c.key) == 0 || len(c.body) == 0 || len(c.origin) == 0 ||
		len(c.predecessor) != 0 && len(c.predecessor) != r.codec.hasher.Size() {
		return nil, errPendingFinal
	}
	return r.codec.frame(c.key, binary.BigEndian.AppendUint64(nil, c.version), c.predecessor, c.body, c.origin)
}

func (r *pendingFinalRecords) decode(encoded, key []byte) error {
	f, err := r.codec.unframe(encoded, 5)
	if err != nil {
		return err
	}
	if !bytes.Equal(f[0], key) || len(f[1]) != 8 {
		return errPendingFinal
	}
	_, err = r.encode(pendingFinalCandidate{key: f[0], version: binary.BigEndian.Uint64(f[1]),
		predecessor: f[2], body: f[3], origin: f[4]})
	return err
}

func (r *pendingFinalRecords) key(kind string, fields ...[]byte) ([]byte, error) {
	framed, err := r.codec.frame(fields...)
	if err != nil {
		return nil, err
	}
	return append([]byte(pendingFinalPrefix+kind+"@"), framed...), nil
}

func (r *pendingFinalRecords) read(key []byte) ([]byte, error) {
	a, err := r.codec.state.systemAccount()
	if err != nil {
		return nil, err
	}
	v, _, err := a.RetrieveValue(bytes.Clone(key))
	if err != nil || len(v) > r.codec.maxBytes {
		if err != nil {
			return nil, err
		}
		return nil, errPendingFinal
	}
	return bytes.Clone(v), nil
}

// final reads ONLY the current final head. It supplies no positive authority;
// the gate must still enforce the complete decision's current admission rules.
func (r *pendingFinalRecords) final(key []byte) (encoded, commitment []byte, err error) {
	if len(key) == 0 {
		return nil, nil, errPendingFinal
	}
	k, err := r.key("final", key)
	if err != nil {
		return nil, nil, err
	}
	encoded, err = r.read(k)
	if err != nil || len(encoded) == 0 {
		return encoded, nil, err
	}
	if err = r.decode(encoded, key); err != nil {
		return nil, nil, err
	}
	return encoded, r.codec.hasher.Compute(string(encoded)), nil
}

// check reloads state after external callbacks. Exclusive native ownership is
// still required: this comparison is not a globally atomic snapshot mechanism.
func (r *pendingFinalRecords) check(c pendingFinalCandidate, encoded []byte, promoted bool) error {
	final, digest, err := r.final(c.key)
	if err != nil {
		return err
	}
	pendingKey, err := r.key("pending", c.key)
	if err != nil {
		return err
	}
	pending, err := r.read(pendingKey)
	if err != nil {
		return err
	}
	itemKey, err := r.key("item", c.origin, c.key)
	if err != nil {
		return err
	}
	item, err := r.read(itemKey)
	if err != nil {
		return err
	}
	if promoted {
		if !bytes.Equal(final, encoded) || len(pending) != 0 || len(item) != 0 {
			return errPendingFinal
		}
		return nil
	}
	if !bytes.Equal(digest, c.predecessor) || !bytes.Equal(pending, encoded) ||
		!bytes.Equal(item, r.codec.hasher.Compute(string(encoded))) {
		return errPendingFinal
	}
	return nil
}

// A verifier authenticates the operation; it cannot stage or promote this
// record itself, including manufacturing an otherwise valid duplicate. Other
// co-journaled state remains permitted under the existing exclusive owner.
func (r *pendingFinalRecords) verifyState(c pendingFinalCandidate, verify func() error) error {
	return r.verifyStates([]pendingFinalCandidate{c}, verify)
}

func (r *pendingFinalRecords) verifyStates(candidates []pendingFinalCandidate, verify func() error) error {
	kinds := []string{"final", "pending", "item"}
	keys := make([][]byte, 0, len(candidates)*len(kinds))
	before := make([][]byte, 0, cap(keys))
	for _, c := range candidates {
		fields := [][][]byte{{c.key}, {c.key}, {c.origin, c.key}}
		for i, kind := range kinds {
			key, err := r.key(kind, fields[i]...)
			if err != nil {
				return err
			}
			value, err := r.read(key)
			if err != nil {
				return err
			}
			keys = append(keys, key)
			before = append(before, value)
		}
	}
	if err := verify(); err != nil {
		return err
	}
	for i, key := range keys {
		current, err := r.read(key)
		if err != nil {
			return err
		}
		if !bytes.Equal(current, before[i]) {
			return errPendingFinal
		}
	}
	return nil
}

func (r *pendingFinalRecords) save(c pendingFinalCandidate, encoded []byte, promote bool) error {
	pendingKey, err := r.key("pending", c.key)
	if err != nil {
		return err
	}
	itemKey, err := r.key("item", c.origin, c.key)
	if err != nil {
		return err
	}
	a, err := r.codec.state.systemAccount()
	if err != nil {
		return err
	}
	values := [][]byte{encoded, r.codec.hasher.Compute(string(encoded))}
	keys := [][]byte{pendingKey, itemKey}
	if promote {
		finalKey, e := r.key("final", c.key)
		if e != nil {
			return e
		}
		keys = append(keys, finalKey)
		values = [][]byte{nil, nil, encoded}
	}
	for i, key := range keys {
		if err = a.SaveKeyValue(key, values[i]); err != nil {
			return err
		}
	}
	return r.codec.state.accounts.SaveAccount(a)
}

func (r *pendingFinalRecords) stage(candidate pendingFinalCandidate) error {
	encoded, err := r.encode(candidate)
	if err != nil {
		return err
	}
	// Decode retained encoding to own all caller buffers before host callbacks.
	f, err := r.codec.unframe(encoded, 5)
	if err != nil {
		return err
	}
	c := pendingFinalCandidate{key: bytes.Clone(f[0]), version: candidate.version,
		predecessor: bytes.Clone(f[2]), body: bytes.Clone(f[3]), origin: bytes.Clone(f[4])}
	return r.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		if e := r.verifyState(c, func() error { return r.host.Admit(bytes.Clone(encoded)) }); e != nil {
			return nil, e
		}
		final, digest, e := r.final(c.key)
		if e != nil {
			return nil, e
		}
		if bytes.Equal(final, encoded) {
			return nil, r.check(c, encoded, true)
		}
		if !bytes.Equal(digest, c.predecessor) {
			return nil, errPendingFinal
		}
		pk, e := r.key("pending", c.key)
		if e != nil {
			return nil, e
		}
		pending, e := r.read(pk)
		if e != nil {
			return nil, e
		}
		if len(pending) != 0 {
			return nil, r.check(c, encoded, false)
		}
		ik, e := r.key("item", c.origin, c.key)
		if e != nil {
			return nil, e
		}
		item, e := r.read(ik)
		if e != nil || len(item) != 0 {
			if e != nil {
				return nil, e
			}
			return nil, errPendingFinal
		}
		output, e := r.host.Initialize(bytes.Clone(encoded))
		if e != nil {
			return nil, e
		}
		if output == nil || output.ReturnCode != vmcommon.Ok {
			return nil, errPendingFinal
		}
		// Callback cannot replace the predecessor or install another candidate.
		current, _, e := r.final(c.key)
		if e != nil {
			return nil, e
		}
		if !bytes.Equal(current, final) {
			return nil, errPendingFinal
		}
		for _, key := range [][]byte{pk, ik} {
			v, readErr := r.read(key)
			if readErr != nil {
				return nil, readErr
			}
			if len(v) != 0 {
				return nil, errPendingFinal
			}
		}
		return output, r.save(c, encoded, false)
	})
}

// promote accepts one bounded item supplied by the qualified native importer,
// never scans a registry. No actual native route calls this private prototype.
func (r *pendingFinalRecords) promote(candidate pendingFinalCandidate, evidence []byte) error {
	prepared, err := r.preparePromotion(candidate, evidence)
	if err != nil {
		return err
	}
	return r.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		return r.applyPromotion(prepared, func(verify func() error) error {
			return r.verifyState(prepared.candidate, verify)
		})
	})
}

type pendingFinalPromotion struct {
	candidate pendingFinalCandidate
	evidence  []byte
}

type preparedFinalPromotion struct {
	candidate pendingFinalCandidate
	encoded   []byte
	evidence  []byte
}

func (r *pendingFinalRecords) preparePromotion(candidate pendingFinalCandidate, evidence []byte) (preparedFinalPromotion, error) {
	encoded, err := r.encode(candidate)
	if err != nil {
		return preparedFinalPromotion{}, err
	}
	if len(evidence) == 0 || len(evidence) > r.codec.maxBytes {
		return preparedFinalPromotion{}, errPendingFinal
	}
	f, err := r.codec.unframe(encoded, 5)
	if err != nil {
		return preparedFinalPromotion{}, err
	}
	c := pendingFinalCandidate{key: bytes.Clone(f[0]), version: candidate.version,
		predecessor: bytes.Clone(f[2]), body: bytes.Clone(f[3]), origin: bytes.Clone(f[4])}
	return preparedFinalPromotion{candidate: c, encoded: encoded, evidence: bytes.Clone(evidence)}, nil
}

// promoteResult consumes the COMPLETE ordered item commitments selected by the
// qualified native finalized-result producer, not a requester or pool scan.
// committedItems and both limits belong to that authenticated result/profile;
// this private storage operation cannot establish their provenance. Every item
// still requires the host's exact origin/result/root/item/M/B witness check.
// One failed item rolls back the entire import and all its observations.
func (r *pendingFinalRecords) promoteResult(items []pendingFinalPromotion, committedItems [][]byte,
	maxItems, byteLimit int) error {
	if maxItems <= 0 || byteLimit <= 0 || len(items) > maxItems || len(items) != len(committedItems) {
		return errPendingFinal
	}
	prepared := make([]preparedFinalPromotion, 0, len(items))
	candidates := make([]pendingFinalCandidate, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	remaining := byteLimit
	for i, item := range items {
		p, err := r.preparePromotion(item.candidate, item.evidence)
		if err != nil {
			return err
		}
		if len(p.encoded) > remaining {
			return errPendingFinal
		}
		remaining -= len(p.encoded)
		if len(p.evidence) > remaining || !bytes.Equal(r.codec.hasher.Compute(string(p.encoded)), committedItems[i]) {
			return errPendingFinal
		}
		remaining -= len(p.evidence)
		if _, duplicate := seen[string(p.candidate.key)]; duplicate {
			return errPendingFinal
		}
		if i > 0 && !bytes.Equal(p.candidate.origin, candidates[0].origin) {
			return errPendingFinal
		}
		seen[string(p.candidate.key)] = struct{}{}
		prepared = append(prepared, p)
		candidates = append(candidates, p.candidate)
	}
	return r.boundary.execute(func() ([]*vmcommon.VMOutput, error) {
		outputs := make([]*vmcommon.VMOutput, 0, len(prepared))
		for _, p := range prepared {
			output, err := r.applyPromotion(p, func(verify func() error) error {
				return r.verifyStates(candidates, verify)
			})
			if err != nil {
				return nil, err
			}
			if output != nil {
				outputs = append(outputs, output)
			}
		}
		return outputs, nil
	})
}

func (r *pendingFinalRecords) applyPromotion(p preparedFinalPromotion, verify func(func() error) error) (*vmcommon.VMOutput, error) {
	c, encoded, evidence := p.candidate, p.encoded, p.evidence
	if e := verify(func() error { return r.host.Canonical(bytes.Clone(encoded), bytes.Clone(evidence)) }); e != nil {
		return nil, e
	}
	final, _, e := r.final(c.key)
	if e != nil {
		return nil, e
	}
	if bytes.Equal(final, encoded) {
		return nil, r.check(c, encoded, true)
	}
	if e = r.check(c, encoded, false); e != nil {
		return nil, e
	}
	var output *vmcommon.VMOutput
	e = verify(func() error {
		var err error
		output, err = r.host.Observe(bytes.Clone(encoded))
		return err
	})
	if e != nil {
		return nil, e
	}
	if output == nil || output.ReturnCode != vmcommon.Ok {
		return nil, errPendingFinal
	}
	if e = r.check(c, encoded, false); e != nil {
		return nil, e
	}
	return output, r.save(c, encoded, true)
}
