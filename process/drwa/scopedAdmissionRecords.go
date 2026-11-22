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
	codec      *registrationRecords
	boundary   *RollbackContainment
	mandates   scopedAdmissionMandates
	domain     []byte
	limits     scopedAdmissionLimits
	timeSource HeaderTimeSource
}

func newScopedAdmissionRecords(accounts state.AccountsAdapter, boundary *RollbackContainment,
	marshaller marshal.Marshalizer, hasher hashing.Hasher, domain []byte,
	limits scopedAdmissionLimits, mandates scopedAdmissionMandates, timeSource HeaderTimeSource) (*scopedAdmissionRecords, error) {
	if boundary == nil || check.IfNil(mandates) || check.IfNil(timeSource) || timeSource.GetAccountsAdapter() != accounts || len(domain) == 0 ||
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
		domain: bytes.Clone(domain), limits: limits, timeSource: timeSource}, nil
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
	time, epoch, release, err := context.Lease()
	if err != nil {
		return 0, 0, err
	}
	defer release()
	return time, epoch, nil
}

// Retain T05's existing operation capability through native reads/writes. Its
// owner cannot Reset/Begin/End midway through a retained mutation. Acquire only
// AFTER external mandate verification, which may invalidate that capability.
// The bound native owner additionally leases its actual header through the
// whole consumer callback, with a final invalidation check inside T04.
func scopedAdmissionLease(context *HeaderTimeContext) (func(), error) {
	if _, _, err := scopedAdmissionTime(context); err != nil {
		return nil, err
	}
	_, _, release, err := context.Lease()
	return release, err
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
	return s.retainRecords(account, epoch, false, writes...)
}

// The same chain-global budget also accounts for registration's permanent
// intent/association/activation records. Only its explicitly selected writer
// permits positive retained-byte growth on OPEN -> CONSUMED; ordinary scope
// pointers keep their existing fixed-size rule. No decrement or recycling.
func (s *scopedAdmissionRecords) retainRecords(account state.UserAccountHandler, epoch uint32, allowGrowth bool,
	writes ...scopedAdmissionWrite) error {
	// A72: only the original fresh-genesis writer may stage this immutable
	// class. Reject the whole ordinary batch before budget/account effects,
	// including same-size replacement, empty deletion and a late bad entry.
	for _, write := range writes {
		if bytes.HasPrefix(write.key, []byte(scopedAdmissionPrefix+"initial@")) {
			return errScopedAdmission
		}
	}
	budgetKey := []byte(scopedAdmissionPrefix + "budget")
	encoded, err := s.retainedBudget(account, epoch)
	if err != nil {
		return err
	}
	count, size := binary.BigEndian.Uint64(encoded), binary.BigEndian.Uint64(encoded[8:])
	rateEpoch, rate := binary.BigEndian.Uint64(encoded[16:]), binary.BigEndian.Uint64(encoded[24:])
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
			if len(old) != len(write.value) && (!allowGrowth || len(write.value) < len(old)) {
				return errScopedAdmission
			}
			delta = uint64(len(write.value) - len(old))
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
	return executeWithHeaderTime(s.boundary, s.timeSource, context, func() (*vmcommon.VMOutput, error) {
		if _, _, e := scopedAdmissionTime(context); e != nil {
			return nil, e
		}
		keys := [][]byte{s.key("version", id), s.key("current", scopeID)}
		if len(predecessor) != 0 {
			keys = append(keys, s.key("version", predecessor))
		}
		if e := s.verifyMandateState(keys, func() error {
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

func (s *scopedAdmissionRecords) verifyMandateState(keys [][]byte, verify func() error) error {
	// The outer operation rolls back any verifier-side writes to its stores.
	// The owned writes and their checks follow this read-only interval.
	return verifyReadOnlyNativeState(s.boundary.stores, func() error {
		return s.verifyState(keys, verify)
	}, errScopedAdmission)
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
	return executeWithHeaderTime(s.boundary, s.timeSource, context, func() (*vmcommon.VMOutput, error) {
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
		if e = s.verifyMandateState([][]byte{s.key("current", scopeID), s.key("version", current), s.key("decision", id), s.key("withdrawn", id)}, func() error {
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
	return executeWithHeaderTime(s.boundary, s.timeSource, context, func() (*vmcommon.VMOutput, error) {
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
		if e = s.verifyMandateState([][]byte{s.key("current", scopeID), s.key("version", current), s.key("decision", id), s.key("withdrawn", id)}, func() error {
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

// scopedAdmissionCurrentHead carries the native version-record reference
// authenticated for the admission purpose at this use. The original owner
// must obtain it during the same serialized operation. A scope-wide pointer,
// a requester-supplied reference or a prior successful read supplies no head.
type scopedAdmissionCurrentHead struct {
	context        *HeaderTimeContext
	accounts       state.AccountsAdapter
	scope, version []byte
}

// checkDecision is the read-only admission prerequisite. The operation owner
// must authenticate the head's purpose and lawful current lineage separately,
// then call this reader before any effect within the same T04 execution.
func (s *scopedAdmissionRecords) checkDecision(context *HeaderTimeContext, d scopedAdmissionDecision, head *scopedAdmissionCurrentHead) error {
	_, err := withHeaderTime(s.timeSource, context, func() (*vmcommon.VMOutput, error) {
		return nil, s.checkDecisionAt(context, d, head)
	})
	return err
}

func (s *scopedAdmissionRecords) checkDecisionAt(context *HeaderTimeContext, d scopedAdmissionDecision, head *scopedAdmissionCurrentHead) error {
	time, _, err := scopedAdmissionTime(context)
	if err != nil {
		return err
	}
	release, err := scopedAdmissionLease(context)
	if err != nil {
		return err
	}
	defer release()
	if time > d.validUntil || head == nil || head.context != context || head.accounts != s.codec.state.accounts {
		return errScopedAdmission
	}
	scope, body, err := s.decisionBody(d)
	if err != nil {
		return err
	}
	// A125: only the exact current authority can back this immutable decision.
	// A successor cannot certify the predecessor's decision into currentness.
	if !bytes.Equal(head.scope, scope) || !bytes.Equal(head.version, d.authority) {
		return errScopedAdmission
	}
	id, err := s.decisionID(scope, d)
	if err != nil {
		return err
	}
	account, err := s.codec.state.systemAccount()
	if err != nil {
		return err
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

// installInitialPurposePair is PRIVATE component construction, not a native
// admission provider or dispatcher. owner MUST be the original authenticated
// native creating EOA; original MUST be authenticated original-genesis G6.
// Those concrete producers are not supplied here. enrollmentEvidence holds
// two separately authenticated ENROLL mandates from that same owning context,
// NOT extra public arguments. The selected operation has exactly three args.
// A matching retained G6/body/hash alone establishes none of these facts.
func (s *scopedAdmissionRecords) installInitialPurposePair(context *HeaderTimeContext, owner, original []byte,
	arguments, enrollmentEvidence [][]byte, bodies *authorityBodyCodec, approval *registrationApprovalCodec,
	admissionRole, independentRole []byte) error {
	operation, err := s.prepareInitialPurposePair(context, owner, original, arguments, enrollmentEvidence, bodies, approval, admissionRole, independentRole)
	if err != nil {
		return err
	}
	return executeWithHeaderTime(s.boundary, s.timeSource, context, operation)
}

// installInitialPurposePairOwned borrows the already-running ORIGINAL native
// journal. The private journal lease supplies no issuer or genesis authority;
// those admission prerequisites and every existing proof remain mandatory.
func (s *scopedAdmissionRecords) installInitialPurposePairOwned(operation *rollbackOperation, context *HeaderTimeContext, owner, original []byte,
	arguments, enrollmentEvidence [][]byte, bodies *authorityBodyCodec, approval *registrationApprovalCodec,
	admissionRole, independentRole []byte) error {
	if s == nil || s.codec == nil || s.codec.state == nil {
		return errScopedAdmission
	}
	return operation.withWrite(s.boundary, s.codec.state.accounts, func() error {
		write, err := s.prepareInitialPurposePair(context, owner, original, arguments, enrollmentEvidence, bodies, approval, admissionRole, independentRole)
		if err != nil {
			return err
		}
		_, err = withHeaderTime(s.timeSource, context, write)
		return err
	})
}

func (s *scopedAdmissionRecords) prepareInitialPurposePair(context *HeaderTimeContext, owner, original []byte,
	arguments, enrollmentEvidence [][]byte, bodies *authorityBodyCodec, approval *registrationApprovalCodec,
	admissionRole, independentRole []byte) (func() (*vmcommon.VMOutput, error), error) {
	if s == nil || s.codec == nil || bodies == nil || approval == nil || bodies.source != s.codec || approval.source != s.codec ||
		check.IfNil(s.mandates) || len(arguments) != 3 || len(enrollmentEvidence) != 2 || len(original) == 0 || len(original) > s.limits.recordBytes {
		return nil, errScopedAdmission
	}
	for _, list := range [][][]byte{arguments, enrollmentEvidence} {
		for _, v := range list {
			if len(v) == 0 || len(v) > s.limits.recordBytes {
				return nil, errScopedAdmission
			}
		}
	}
	a, err := bodies.decodeInitial(original, admissionRole, independentRole)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(owner, a.owner) || !bytes.Equal(arguments[0], a.programme) {
		return nil, errScopedAdmission
	}
	// Freeze every callback-visible input before invoking a mandate producer.
	original = bytes.Clone(original)
	args := make([][]byte, 3)
	for i, v := range arguments {
		args[i] = bytes.Clone(v)
	}
	evidence := make([][]byte, 2)
	for i, v := range enrollmentEvidence {
		evidence[i] = bytes.Clone(v)
	}
	writes, err := s.initialPurposeWrites(a)
	if err != nil {
		return nil, err
	}
	scope, err := s.scope(a.owner, a.programme)
	if err != nil {
		return nil, err
	}
	identity, err := s.codec.frame(a.owner, a.programme)
	if err != nil {
		return nil, err
	}
	originalKey := s.key("initial", identity)
	keys := [][]byte{originalKey}
	for _, w := range writes {
		keys = append(keys, w.key)
	}
	return func() (*vmcommon.VMOutput, error) {
		at, epoch, err := scopedAdmissionTime(context)
		if err != nil {
			return nil, err
		}
		account, err := s.codec.state.systemAccount()
		if err != nil {
			return nil, err
		}
		retained, _, err := account.RetrieveValue(originalKey)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(retained, original) {
			return nil, errScopedAdmission
		}
		if err = approval.verifyInitialPossession(args[1], s.domain, a, false, at); err != nil {
			return nil, err
		}
		if err = approval.verifyInitialPossession(args[2], s.domain, a, true, at); err != nil {
			return nil, err
		}
		if err = s.verifyState(keys, func() error {
			for i := 0; i < 2; i++ {
				id := writes[2*i].key[len(scopedAdmissionPrefix+"version@"):]
				// Stop before the next verifier can observe writes made by this one.
				if e := verifyReadOnlyNativeState(s.boundary.stores, func() error {
					return s.mandates.Verify("ENROLL", bytes.Clone(scope), nil, bytes.Clone(id), bytes.Clone(evidence[i]))
				}, errScopedAdmission); e != nil {
					return e
				}
			}
			return nil
		}); err != nil {
			return nil, err
		}
		release, err := scopedAdmissionLease(context)
		if err != nil {
			return nil, err
		}
		defer release()
		account, err = s.codec.state.systemAccount()
		if err != nil {
			return nil, err
		}
		if _, err = s.retainedBudget(account, epoch); err != nil {
			return nil, err
		}
		present := 0
		for _, w := range writes {
			old, _, e := account.RetrieveValue(w.key)
			if e != nil {
				return nil, e
			}
			if len(old) != 0 {
				if !bytes.Equal(old, w.value) {
					return nil, errScopedAdmission
				}
				present++
			}
		}
		if present == len(writes) {
			return nil, nil
		} // exact re-authenticated duplicate; no budget/write
		if present != 0 {
			return nil, errScopedAdmission
		} // partial, corrupt or rotated; never reset
		return nil, s.retainRecords(account, epoch, false, writes...)
	}, nil
}

// retainedBudget validates the existing fixed budget without writing it. An
// exact duplicate must not roll its epoch forward or silently accept corruption.
func (s *scopedAdmissionRecords) retainedBudget(account state.UserAccountHandler, epoch uint32) ([]byte, error) {
	key := []byte(scopedAdmissionPrefix + "budget")
	encoded, _, err := account.RetrieveValue(key)
	if err != nil {
		return nil, err
	}
	if len(encoded) != 32 {
		return nil, errScopedAdmission
	}
	count, size := binary.BigEndian.Uint64(encoded), binary.BigEndian.Uint64(encoded[8:])
	rateEpoch, rate := binary.BigEndian.Uint64(encoded[16:]), binary.BigEndian.Uint64(encoded[24:])
	if count == 0 || size < uint64(len(key)+32) || count > s.limits.records || size > s.limits.retainedBytes || rate > s.limits.newRecordsPerEpoch || uint64(epoch) < rateEpoch {
		return nil, errScopedAdmission
	}
	return encoded, nil
}
