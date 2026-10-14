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

// DRWA-defined EXPERIMENTAL storage/preimage domains, not Part B L346 release
// allocations. All records use the existing native protected system-account
// trie and existing bounded Batch framing. No ordinary dispatcher imports this.
const scopedAdmissionPrefix = core.ProtectedKeyPrefix + "DRWA@scopedAdmission@"

var errScopedAdmission = errors.New("invalid DRWA scoped admission construction")

// scopedAdmissionMandates is owned by protected ingress, not by the requester.
// Verify must authenticate the EXACT scope, purpose, predecessor and digest.
// ENROLL additionally requires the actual native creating sender, lawful initial
// business appointment and successor possession; SUCCESSOR requires lawful
// scoped succession/recovery AND separate successor possession. ADMISSION and
// WITHDRAW require their distinct current lawful purposes and every prescribed
// independent approval. Routine signing alone grants no withdrawal mandate.
//
// There is deliberately no default implementation or caller boolean. The real
// native producer/constitution adapter remains a first-consumer prerequisite.
// Synthetic test implementations establish no real appointment or admission.
type scopedAdmissionMandates interface {
	Verify(purpose string, scope, predecessor, digest, evidence []byte) error
	IsInterfaceNil() bool
}

type scopedAdmissionLimits struct {
	recordBytes                                int
	records, retainedBytes, newRecordsPerEpoch uint64
}

// scopedAdmissionRecords is an unwired F04/M47 construction (A L1260-1312,
// E.8). Its operation owner supplies native evaluated-header context, canonical
// state and exclusive stores. T04 owns every mutation, save and output. The
// admission reader reloads native state instead of retaining an allow cache.
// Native Commit alone is NOT canonical effectivity or a finality proof.
type scopedAdmissionRecords struct {
	codec    *registrationRecords
	boundary *RollbackContainment
	mandates scopedAdmissionMandates
	domain   []byte
	limits   scopedAdmissionLimits
}

func newScopedAdmissionRecords(accounts state.AccountsAdapter, boundary *RollbackContainment,
	marshaller marshal.Marshalizer, hasher hashing.Hasher, domain []byte,
	limits scopedAdmissionLimits, mandates scopedAdmissionMandates) (*scopedAdmissionRecords, error) {
	if boundary == nil || check.IfNil(mandates) || len(domain) == 0 ||
		limits.records == 0 || limits.retainedBytes == 0 || limits.newRecordsPerEpoch == 0 {
		return nil, errScopedAdmission
	}
	owned := false
	for _, store := range boundary.stores {
		if store == accounts {
			owned = true
		}
	}
	if !owned {
		return nil, errScopedAdmission
	}
	codec, err := newRegistrationRecords(accounts, marshaller, hasher, limits.recordBytes)
	if err != nil {
		return nil, err
	}
	if len(domain) > limits.recordBytes {
		return nil, errScopedAdmission
	}
	return &scopedAdmissionRecords{codec: codec, boundary: boundary, mandates: mandates,
		domain: bytes.Clone(domain), limits: limits}, nil
}

// scope is exactly L37's native creating-owner/programme/domain tuple. Neither
// an issuer name, a relayer nor recovery changes its immutable owner component.
func (s *scopedAdmissionRecords) scope(owner, program []byte) ([]byte, error) {
	if len(owner) != len(core.SystemAccountAddress) || len(program) == 0 {
		return nil, errScopedAdmission
	}
	return s.codec.frame(s.domain, owner, program)
}

func (s *scopedAdmissionRecords) key(kind string, identity []byte) []byte {
	return append([]byte(scopedAdmissionPrefix+kind+"@"), identity...)
}

func (s *scopedAdmissionRecords) digest(kind string, fields ...[]byte) ([]byte, error) {
	all := append([][]byte{[]byte("DRWA/SCOPED_ADMISSION/" + kind + "/candidate1"), s.domain}, fields...)
	value, err := s.codec.frame(all...)
	if err != nil {
		return nil, err
	}
	return s.codec.hasher.Compute(string(value)), nil
}

func (s *scopedAdmissionRecords) current(account state.UserAccountHandler, scope []byte) ([]byte, error) {
	id, err := s.digest("SCOPE", scope)
	if err != nil {
		return nil, err
	}
	value, _, err := account.RetrieveValue(s.key("current", id))
	if err != nil {
		return nil, err
	}
	f, err := s.codec.unframe(value, 2)
	if err != nil || !bytes.Equal(f[0], scope) || len(f[1]) != s.codec.hasher.Size() {
		return nil, errScopedAdmission
	}
	version, _, err := account.RetrieveValue(s.key("version", f[1]))
	if err != nil {
		return nil, err
	}
	v, err := s.codec.unframe(version, 3)
	if err != nil || !bytes.Equal(v[0], scope) || len(v[2]) == 0 ||
		len(v[1]) != 0 && len(v[1]) != s.codec.hasher.Size() {
		return nil, errScopedAdmission
	}
	expected, err := s.digest("VERSION", v...)
	if err != nil || !bytes.Equal(expected, f[1]) {
		return nil, errScopedAdmission
	}
	return bytes.Clone(f[1]), nil
}

func scopedAdmissionTime(context *HeaderTimeContext) (HeaderMilliseconds, uint32, error) {
	if context == nil {
		return 0, 0, errScopedAdmission
	}
	_, shard := context.HeaderIdentity()
	if shard != core.MetachainShardId {
		return 0, 0, errScopedAdmission
	}
	time, err := context.Milliseconds()
	return time, context.epoch, err
}

// Retain T05's existing operation capability through native reads/writes. Its
// owner cannot Reset/Begin/End midway through a retained mutation. Acquire only
// AFTER external mandate verification, which may invalidate that capability.
// Native installer/whole-consumer ownership remains T42's separate obligation.
func scopedAdmissionLease(context *HeaderTimeContext) (func(), error) {
	if _, _, err := scopedAdmissionTime(context); err != nil {
		return nil, err
	}
	context.owner.mut.RLock()
	if context.owner.current != context {
		context.owner.mut.RUnlock()
		return nil, ErrInactiveHeaderTime
	}
	return context.owner.mut.RUnlock, nil
}

type scopedAdmissionWrite struct{ key, value []byte }

// Capture only this operation's owned predecessors, including its retained
// budget. An unrelated native key is not an authority or duplicate baseline.
func (s *scopedAdmissionRecords) verifyState(keys [][]byte, verify func() error) error {
	read := func(key []byte) ([]byte, error) {
		account, err := s.codec.state.systemAccount()
		if err != nil {
			return nil, err
		}
		value, _, err := account.RetrieveValue(key)
		if err != nil {
			return nil, err
		}
		if len(value) > s.limits.recordBytes {
			return nil, errScopedAdmission
		}
		return bytes.Clone(value), nil
	}
	keys = append(keys, []byte(scopedAdmissionPrefix+"budget"))
	values := make([][]byte, len(keys))
	for i, key := range keys {
		value, err := read(key)
		if err != nil {
			return err
		}
		values[i] = value
	}
	if err := verify(); err != nil {
		return err
	}
	for i, key := range keys {
		value, err := read(key)
		if err != nil {
			return err
		}
		if !bytes.Equal(values[i], value) {
			return errScopedAdmission
		}
	}
	return nil
}

// retain counts EVERY newly retained key/value, including current pointers,
// immutable versions, decisions and withdrawal/replay tombstones. No deletion,
// abandoned-record recycling, per-owner reservation or fee-based capacity claim.
// The fixed budget record must be explicitly provisioned by the eventual native
// genesis/initialization owner. Missing/corrupt counters NEVER mean zero.
// Rate is per evaluated-header epoch, persisted with native state and rollback.
func (s *scopedAdmissionRecords) retain(account state.UserAccountHandler, epoch uint32,
	writes ...scopedAdmissionWrite) error {
	budgetKey := []byte(scopedAdmissionPrefix + "budget")
	encoded, _, err := account.RetrieveValue(budgetKey)
	if err != nil {
		return err
	}
	if len(encoded) != 32 {
		return errScopedAdmission
	}
	count, size := binary.BigEndian.Uint64(encoded), binary.BigEndian.Uint64(encoded[8:])
	rateEpoch, rate := binary.BigEndian.Uint64(encoded[16:]), binary.BigEndian.Uint64(encoded[24:])
	if count == 0 || size < uint64(len(budgetKey)+32) || count > s.limits.records || size > s.limits.retainedBytes || rate > s.limits.newRecordsPerEpoch || uint64(epoch) < rateEpoch {
		return errScopedAdmission
	}
	if uint64(epoch) > rateEpoch {
		rateEpoch, rate = uint64(epoch), 0
	}
	seen := make(map[string]struct{}, len(writes))
	for _, write := range writes {
		if _, duplicate := seen[string(write.key)]; duplicate {
			return errScopedAdmission
		}
		seen[string(write.key)] = struct{}{}
		old, _, e := account.RetrieveValue(write.key)
		if e != nil {
			return e
		}
		// Updates are only fixed-size current-version pointers. Their actual
		// retained byte delta is still charged; new immutable keys count once.
		delta := uint64(len(write.value))
		if len(old) == 0 {
			if count == s.limits.records || rate == s.limits.newRecordsPerEpoch {
				return errScopedAdmission
			}
			count++
			rate++
			delta += uint64(len(write.key))
		} else {
			if len(old) != len(write.value) {
				return errScopedAdmission
			}
			delta = 0
		}
		if delta > s.limits.retainedBytes-size {
			return errScopedAdmission
		}
		size += delta
	}
	for _, write := range writes {
		if err = account.SaveKeyValue(write.key, bytes.Clone(write.value)); err != nil {
			return err
		}
	}
	budget := make([]byte, 32)
	binary.BigEndian.PutUint64(budget, count)
	binary.BigEndian.PutUint64(budget[8:], size)
	binary.BigEndian.PutUint64(budget[16:], rateEpoch)
	binary.BigEndian.PutUint64(budget[24:], rate)
	if err = account.SaveKeyValue(budgetKey, budget); err != nil {
		return err
	}
	return s.codec.state.accounts.SaveAccount(account)
}

// install retains an exact initial/successor body only after its separate
// lawful mandate and successor-possession verifier succeeds. Body publication
// never changes an operational token CEB: this pointer is pre-token scope only.
func (s *scopedAdmissionRecords) install(context *HeaderTimeContext, owner, program, predecessor, body, evidence []byte) error {
	if len(evidence) == 0 || len(evidence) > s.limits.recordBytes {
		return errScopedAdmission
	}
	_, epoch, err := scopedAdmissionTime(context)
	if err != nil {
		return err
	}
	scope, err := s.scope(owner, program)
	if err != nil || len(body) == 0 {
		return errScopedAdmission
	}
	if len(predecessor) != 0 && len(predecessor) != s.codec.hasher.Size() {
		return errScopedAdmission
	}
	predecessor = bytes.Clone(predecessor)
	encoded, err := s.codec.frame(scope, predecessor, body)
	if err != nil {
		return err
	}
	id, err := s.digest("VERSION", scope, predecessor, body)
	if err != nil {
		return err
	}
	scopeID, err := s.digest("SCOPE", scope)
	if err != nil {
		return err
	}
	pointer, err := s.codec.frame(scope, id)
	if err != nil {
		return err
	}
	purpose := "SUCCESSOR"
	if len(predecessor) == 0 {
		purpose = "ENROLL"
	}
	return s.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		if _, _, e := scopedAdmissionTime(context); e != nil {
			return nil, e
		}
		keys := [][]byte{s.key("version", id), s.key("current", scopeID)}
		if len(predecessor) != 0 {
			keys = append(keys, s.key("version", predecessor))
		}
		if e := s.verifyState(keys, func() error {
			return s.mandates.Verify(purpose, bytes.Clone(scope), bytes.Clone(predecessor), bytes.Clone(id), bytes.Clone(evidence))
		}); e != nil {
			return nil, e
		}
		release, e := scopedAdmissionLease(context)
		if e != nil {
			return nil, e
		}
		defer release()
		// The mandate adapter is an external call. Reacquire the native account
		// before resolving its current pointer, immutable record and budget.
		account, e := s.codec.state.systemAccount()
		if e != nil {
			return nil, e
		}
		old, _, e := account.RetrieveValue(s.key("version", id))
		if e != nil {
			return nil, e
		}
		if len(old) != 0 {
			if !bytes.Equal(old, encoded) {
				return nil, errScopedAdmission
			}
			// Exact retained resubmission never switches back to an old version.
			return nil, nil
		}
		if len(predecessor) == 0 {
			old, _, e = account.RetrieveValue(s.key("current", scopeID))
			if e != nil {
				return nil, e
			}
			if len(old) != 0 {
				return nil, errScopedAdmission
			}
		} else {
			current, e := s.current(account, scope)
			if e != nil || !bytes.Equal(current, predecessor) {
				return nil, errScopedAdmission
			}
		}
		e = s.retain(account, epoch, scopedAdmissionWrite{s.key("version", id), encoded}, scopedAdmissionWrite{s.key("current", scopeID), pointer})
		return nil, e
	})
}

// Decision fields follow the explicit admission subject/binding (A L1283-1312).
// validUntil is admission expiry, not a guessed certificate lifetime. The fresh
// REGISTER_TOKEN/ACTIVATE certificates, class lifetime, other independent roles,
// canonical-final intent, fee economics and readiness belong to their consumers.
type scopedAdmissionDecision struct {
	owner, program, issuer, version, commitment, authority []byte
	validUntil                                             HeaderMilliseconds
}

func (s *scopedAdmissionRecords) decisionBody(d scopedAdmissionDecision) ([]byte, []byte, error) {
	scope, err := s.scope(d.owner, d.program)
	if err != nil || len(d.issuer) != len(core.SystemAccountAddress) || len(d.version) == 0 || len(d.commitment) == 0 || len(d.authority) != s.codec.hasher.Size() {
		return nil, nil, errScopedAdmission
	}
	expiry := binary.BigEndian.AppendUint64(nil, uint64(d.validUntil))
	encoded, err := s.codec.frame(scope, d.issuer, d.version, d.commitment, d.authority, expiry)
	return scope, encoded, err
}

// Identity is separate from immutable payload: conflicting bodies under the
// SAME decision/version must deny rather than obtain another record slot.
func (s *scopedAdmissionRecords) decisionID(scope []byte, d scopedAdmissionDecision) ([]byte, error) {
	return s.digest("DECISION", scope, d.issuer, d.version)
}

func (s *scopedAdmissionRecords) admit(context *HeaderTimeContext, d scopedAdmissionDecision, evidence []byte) error {
	if len(evidence) == 0 || len(evidence) > s.limits.recordBytes {
		return errScopedAdmission
	}
	time, epoch, err := scopedAdmissionTime(context)
	if err != nil {
		return err
	}
	if time > d.validUntil {
		return errScopedAdmission
	}
	scope, body, err := s.decisionBody(d)
	if err != nil {
		return err
	}
	id, err := s.decisionID(scope, d)
	if err != nil {
		return err
	}
	payload, err := s.digest("ADMISSION", body)
	if err != nil {
		return err
	}
	return s.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		if _, _, e := scopedAdmissionTime(context); e != nil {
			return nil, e
		}
		account, e := s.codec.state.systemAccount()
		if e != nil {
			return nil, e
		}
		current, e := s.current(account, scope)
		if e != nil || !bytes.Equal(current, d.authority) {
			return nil, errScopedAdmission
		}
		scopeID, e := s.digest("SCOPE", scope)
		if e != nil {
			return nil, e
		}
		if e = s.verifyState([][]byte{s.key("current", scopeID), s.key("version", current), s.key("decision", id), s.key("withdrawn", id)}, func() error {
			return s.mandates.Verify("ADMISSION", bytes.Clone(scope), bytes.Clone(current), bytes.Clone(payload), bytes.Clone(evidence))
		}); e != nil {
			return nil, e
		}
		release, e := scopedAdmissionLease(context)
		if e != nil {
			return nil, e
		}
		defer release()
		account, e = s.codec.state.systemAccount()
		if e != nil {
			return nil, e
		}
		current, e = s.current(account, scope)
		if e != nil || !bytes.Equal(current, d.authority) {
			return nil, errScopedAdmission
		}
		old, _, e := account.RetrieveValue(s.key("decision", id))
		if e != nil {
			return nil, e
		}
		if len(old) != 0 {
			if !bytes.Equal(old, body) {
				return nil, errScopedAdmission
			}
			return nil, nil // no rewrite and no clearing a withdrawal
		}
		e = s.retain(account, epoch, scopedAdmissionWrite{s.key("decision", id), body})
		return nil, e
	})
}

func (s *scopedAdmissionRecords) withdraw(context *HeaderTimeContext, d scopedAdmissionDecision, evidence []byte) error {
	if len(evidence) == 0 || len(evidence) > s.limits.recordBytes {
		return errScopedAdmission
	}
	_, epoch, err := scopedAdmissionTime(context)
	if err != nil {
		return err
	}
	scope, body, err := s.decisionBody(d)
	if err != nil {
		return err
	}
	id, err := s.decisionID(scope, d)
	if err != nil {
		return err
	}
	return s.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		if _, _, e := scopedAdmissionTime(context); e != nil {
			return nil, e
		}
		account, e := s.codec.state.systemAccount()
		if e != nil {
			return nil, e
		}
		stored, _, e := account.RetrieveValue(s.key("decision", id))
		if e != nil {
			return nil, e
		}
		if !bytes.Equal(stored, body) {
			return nil, errScopedAdmission
		}
		current, e := s.current(account, scope)
		if e != nil {
			return nil, e
		}
		digest, e := s.digest("WITHDRAW", scope, id, body, current)
		if e != nil {
			return nil, e
		}
		scopeID, e := s.digest("SCOPE", scope)
		if e != nil {
			return nil, e
		}
		if e = s.verifyState([][]byte{s.key("current", scopeID), s.key("version", current), s.key("decision", id), s.key("withdrawn", id)}, func() error {
			return s.mandates.Verify("WITHDRAW", bytes.Clone(scope), bytes.Clone(current), bytes.Clone(digest), bytes.Clone(evidence))
		}); e != nil {
			return nil, e
		}
		release, e := scopedAdmissionLease(context)
		if e != nil {
			return nil, e
		}
		defer release()
		account, e = s.codec.state.systemAccount()
		if e != nil {
			return nil, e
		}
		verifiedCurrent, e := s.current(account, scope)
		if e != nil || !bytes.Equal(verifiedCurrent, current) {
			return nil, errScopedAdmission
		}
		stored, _, e = account.RetrieveValue(s.key("decision", id))
		if e != nil {
			return nil, e
		}
		if !bytes.Equal(stored, body) {
			return nil, errScopedAdmission
		}
		old, _, e := account.RetrieveValue(s.key("withdrawn", id))
		if e != nil {
			return nil, e
		}
		if len(old) != 0 {
			if !bytes.Equal(old, body) {
				return nil, errScopedAdmission
			}
			return nil, nil
		}
		// Exact permanent tombstone includes immutable decision bytes. There
		// is no TTL, erase, issuer-wide flag or reopening operation.
		e = s.retain(account, epoch, scopedAdmissionWrite{s.key("withdrawn", id), body})
		return nil, e
	})
}

// checkDecision is a read-only prerequisite. It authorizes neither registration
// nor activation by itself. The operation owner must call it inside the SAME
// serialized T04 execution before its effect; a prior successful call is not a
// capability. No outstanding certificate can override the retained tombstone.
func (s *scopedAdmissionRecords) checkDecision(context *HeaderTimeContext, d scopedAdmissionDecision) error {
	time, _, err := scopedAdmissionTime(context)
	if err != nil {
		return err
	}
	release, err := scopedAdmissionLease(context)
	if err != nil {
		return err
	}
	defer release()
	if time > d.validUntil {
		return errScopedAdmission
	}
	scope, body, err := s.decisionBody(d)
	if err != nil {
		return err
	}
	id, err := s.decisionID(scope, d)
	if err != nil {
		return err
	}
	account, err := s.codec.state.systemAccount()
	if err != nil {
		return err
	}
	current, err := s.current(account, scope)
	if err != nil || !bytes.Equal(current, d.authority) {
		return errScopedAdmission
	}
	stored, _, err := account.RetrieveValue(s.key("decision", id))
	if err != nil {
		return err
	}
	if !bytes.Equal(stored, body) {
		return errScopedAdmission
	}
	withdrawn, _, err := account.RetrieveValue(s.key("withdrawn", id))
	if err != nil {
		return err
	}
	if len(withdrawn) != 0 {
		return errScopedAdmission
	}
	return nil
}
