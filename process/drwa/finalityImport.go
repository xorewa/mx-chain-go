package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
	"sync"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// ErrFinalityImport is returned when the finalized-result import or a staging
// request cannot be served. During block execution it refuses the block on this
// node; it is never a reason to promote a part of the eligible set.
var ErrFinalityImport = errors.New("DRWA finalized-result import refused")

// FinalHeadObservation is the identifier of the native observation emitted
// when a pending record becomes the final head (Part A 6.1 step 4).
const FinalHeadObservation = "DRWAFinalHead"

const (
	finalityWorkKind = "work"
	finalitySealKind = "seal"
	finalityOpenKind = "open"
)

// FinalityEvidenceSource returns native objects the node already holds (pools,
// storage). It is a retrieval aid only: every returned object is re-encoded
// and accepted solely when its hash is the one committed by the block in
// execution or by a header reached from it. A missing object is an error.
type FinalityEvidenceSource interface {
	Header(shardID uint32, hash []byte) (data.HeaderHandler, error)
	Proof(shardID uint32, hash []byte) (data.HeaderProofHandler, error)
	IsInterfaceNil() bool
}

// FinalityRecordClass is supplied by the row that owns a protected record
// class. Admit validates the complete class-specific body and its authority;
// FinalizationGas is the finalization part of that operation's regulated gas
// profile, charged to the writing transaction (Part A 6.1; owner ruling of
// 26 November 2026). It receives the size of the record and the number of
// items the executing block has already registered, because the promotion of
// an origin re-reads the heads of all of its items around every item. No
// class is built in.
type FinalityRecordClass interface {
	Admit(key []byte, version uint64, predecessor, body []byte) error
	FinalizationGas(encodedLength int, registeredItems int) uint64
	IsInterfaceNil() bool
}

// ArgsFinalityImport holds the native dependencies of one block processor's
// import owner. MaxRecordBytes is the admitted deployment's record byte limit;
// it also bounds an origin's manifest, hence the items one block can register.
type ArgsFinalityImport struct {
	Accounts       state.AccountsAdapter
	Marshaller     marshal.Marshalizer
	Hasher         hashing.Hasher
	SelfShardID    uint32
	Source         FinalityEvidenceSource
	Validator      process.HeaderConstructionValidator
	Proofs         process.InterceptedHeaderSigVerifier
	Integrity      process.HeaderIntegrityVerifier
	Exclusions     common.RoundExclusionHandler
	Classes        map[string]FinalityRecordClass
	MaxRecordBytes int
}

// FinalityImport is the production owner of the pending/final namespaces of
// one block processor (Part A 6.1, AR-01). The block processor calls
// BeginBlock at the import phase of every V3 block execution, after the
// account stores are positioned at the parent's executed root and before the
// first transaction, and EndBlock when that execution is committed or
// reverted. Promotion is computed from the executing header's committed
// references only: see AR01_PROOF.md section 4 for the predicate. Everything
// it writes is account state of the executing block, so a replaced or failed
// block reverts promotion, staging and every dependent effect together.
type FinalityImport struct {
	mut          sync.Mutex
	args         ArgsFinalityImport
	reader       *canonicalResultReader
	prefixes     []string
	maxItems     int
	records      *pendingFinalRecords
	executing    []byte
	charge       func(uint64) error
	canonical    []byte
	evidence     []byte
	observations []*vmcommon.VMOutput
	committed    []*vmcommon.VMOutput
	header       data.HeaderHandler
	epoch        uint32
}

// NewFinalityImport creates the owner. It reads no state.
func NewFinalityImport(args ArgsFinalityImport) (*FinalityImport, error) {
	if check.IfNil(args.Accounts) || check.IfNil(args.Marshaller) || check.IfNil(args.Hasher) ||
		check.IfNil(args.Source) || args.MaxRecordBytes <= 0 || args.Hasher.Size() <= 0 {
		return nil, ErrFinalityImport
	}
	// A manifest is one framed list of item digests inside one record.
	maxItems := args.MaxRecordBytes / (args.Hasher.Size() + 2)
	if maxItems == 0 {
		return nil, ErrFinalityImport
	}
	// The context reader is used for the S/H/M/B relation and the result root
	// only. It has no proof trie: account-witness reads are refused.
	reader, err := newCanonicalResultReader(
		&ResultAccountReader{args: ArgsResultAccountReader{Marshaller: args.Marshaller, Hasher: args.Hasher}},
		args.Validator, args.Proofs, args.Integrity, args.Exclusions)
	if err != nil {
		return nil, err
	}
	classes := make(map[string]FinalityRecordClass, len(args.Classes))
	prefixes := make([]string, 0, len(args.Classes))
	for prefix, class := range args.Classes {
		if len(prefix) == 0 || check.IfNil(class) {
			return nil, ErrFinalityImport
		}
		classes[prefix] = class
		prefixes = append(prefixes, prefix)
	}
	// Longest prefix first, then lexical: class selection never depends on map order.
	sort.Slice(prefixes, func(i, j int) bool {
		if len(prefixes[i]) != len(prefixes[j]) {
			return len(prefixes[i]) > len(prefixes[j])
		}
		return prefixes[i] < prefixes[j]
	})
	args.Classes = classes
	return &FinalityImport{args: args, reader: reader, prefixes: prefixes, maxItems: maxItems}, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (f *FinalityImport) IsInterfaceNil() bool { return f == nil }

// BeginBlock runs the import phase for the block in execution.
func (f *FinalityImport) BeginBlock(header data.HeaderHandler, headerHash []byte) error {
	f.mut.Lock()
	defer f.mut.Unlock()
	f.close()
	if check.IfNil(header) || !header.IsHeaderV3() || header.GetShardID() != f.args.SelfShardID ||
		len(headerHash) != f.args.Hasher.Size() {
		return ErrFinalityImport
	}
	boundary, err := newNativeRollbackContainment(f.args.Accounts)
	if err != nil {
		return err
	}
	f.records, err = newPendingFinalRecords(f.args.Accounts, boundary, f.args.Marshaller, f.args.Hasher,
		f.args.MaxRecordBytes, (*finalityHost)(f))
	if err != nil {
		return err
	}
	open, err := f.open()
	if err != nil {
		f.close()
		return err
	}
	if open != 0 {
		if err = f.importResults(header, headerHash); err != nil {
			f.close()
			return err
		}
	}
	f.executing = bytes.Clone(headerHash)
	f.header, f.epoch = header, header.GetEpoch()
	return nil
}

// SelfShardID returns the shard of the block processor this owner serves.
func (f *FinalityImport) SelfShardID() uint32 { return f.args.SelfShardID }

// ExecutingBlock returns the committed hash, the exact header bytes and the
// epoch of the block opened by BeginBlock. It is the consuming boundary of a
// canonical result read made during that execution.
func (f *FinalityImport) ExecutingBlock() (hash, header []byte, epoch uint32, err error) {
	f.mut.Lock()
	defer f.mut.Unlock()
	if len(f.executing) == 0 || check.IfNil(f.header) {
		return nil, nil, 0, ErrFinalityImport
	}
	raw, err := f.args.Marshaller.Marshal(f.header)
	if err != nil {
		return nil, nil, 0, err
	}
	if !bytes.Equal(f.args.Hasher.Compute(string(raw)), f.executing) {
		return nil, nil, 0, ErrFinalityImport
	}
	return bytes.Clone(f.executing), raw, f.epoch, nil
}

// EndBlock closes the execution opened by BeginBlock. Observations are
// released only for a committed block.
func (f *FinalityImport) EndBlock(committed bool) {
	f.mut.Lock()
	defer f.mut.Unlock()
	if committed && f.records != nil {
		f.committed = f.observations
	}
	f.close()
}

// CommittedObservations returns the final-head observations of the last
// committed block execution. Their presentation belongs to the observation
// contract (tracker row SP2-80).
func (f *FinalityImport) CommittedObservations() []*vmcommon.VMOutput {
	f.mut.Lock()
	defer f.mut.Unlock()
	return append([]*vmcommon.VMOutput(nil), f.committed...)
}

func (f *FinalityImport) close() {
	f.records, f.executing, f.charge, f.canonical, f.evidence, f.observations = nil, nil, nil, nil, nil, nil
	f.header, f.epoch = nil, 0
}

// Stage registers the pending successor written by the protected operation in
// execution and its finalization item, filed under the executing block. The
// caller is the native owner of that operation, inside the transaction's own
// journal; charge consumes gas of the writing transaction and an error from it
// refuses the write. An exact retry is idempotent and is not charged again.
func (f *FinalityImport) Stage(key []byte, version uint64, predecessor, body []byte, charge func(uint64) error) error {
	f.mut.Lock()
	defer f.mut.Unlock()
	if f.records == nil || len(f.executing) == 0 || charge == nil {
		return ErrFinalityImport
	}
	operation, err := f.records.prepareStage(pendingFinalCandidate{
		key: key, version: version, predecessor: predecessor, body: body, origin: f.executing})
	if err != nil {
		return err
	}
	f.charge = charge
	defer func() { f.charge = nil }()
	return f.records.boundary.Execute(operation)
}

// Final returns the current final head of a record key and its commitment, or
// nothing when there is none. It reads committed-or-journaled account state of
// the executing store; a pending successor is never returned.
func (f *FinalityImport) Final(key []byte) (encoded, commitment []byte, err error) {
	f.mut.Lock()
	defer f.mut.Unlock()
	records := f.records
	if records == nil {
		records, err = newPendingFinalRecords(f.args.Accounts, &RollbackContainment{
			stores: []state.AccountsAdapter{f.args.Accounts}}, f.args.Marshaller, f.args.Hasher,
			f.args.MaxRecordBytes, (*finalityHost)(f))
		if err != nil {
			return nil, nil, err
		}
	}
	present, err := f.hasStorage()
	if err != nil || !present {
		return nil, nil, err
	}
	return records.final(key)
}

// hasStorage reports whether the system account exists in the current state.
// state.ErrAccNotFound is the native answer for an address that is absent from
// the account trie; every other error is a failed read and refuses the block.
func (f *FinalityImport) hasStorage() (bool, error) {
	_, err := f.args.Accounts.GetExistingAccount(bytes.Clone(core.SystemAccountAddress))
	if errors.Is(err, state.ErrAccNotFound) {
		return false, nil
	}
	return err == nil, err
}

// open is the number of origins that hold a non-empty finalization manifest.
// Zero means the import phase has no work and reads nothing else.
func (f *FinalityImport) open() (uint64, error) {
	present, err := f.hasStorage()
	if err != nil || !present {
		return 0, err
	}
	raw, err := f.get(finalityOpenKind)
	if err != nil || len(raw) == 0 {
		return 0, err
	}
	if len(raw) != 8 || binary.BigEndian.Uint64(raw) == 0 {
		return 0, ErrFinalityImport
	}
	return binary.BigEndian.Uint64(raw), nil
}

// get reads one DRWA-owned key of the pending/final namespace.
func (f *FinalityImport) get(kind string, fields ...[]byte) ([]byte, error) {
	key, err := f.records.key(kind, fields...)
	if err != nil {
		return nil, err
	}
	return f.records.read(key)
}

// put writes one DRWA-owned key of the pending/final namespace.
func (f *FinalityImport) put(value []byte, kind string, fields ...[]byte) error {
	key, err := f.records.key(kind, fields...)
	if err != nil {
		return err
	}
	a, err := f.records.codec.state.systemAccount()
	if err != nil {
		return err
	}
	if err = a.SaveKeyValue(key, value); err != nil {
		return err
	}
	return f.args.Accounts.SaveAccount(a)
}

func (f *FinalityImport) adjustOpen(delta int) error {
	current, err := f.open()
	if err != nil {
		return err
	}
	if delta < 0 && current == 0 || delta > 0 && current == ^uint64(0) {
		return ErrFinalityImport
	}
	next := current + uint64(int64(delta))
	if next == 0 {
		return f.put(nil, finalityOpenKind)
	}
	return f.put(binary.BigEndian.AppendUint64(nil, next), finalityOpenKind)
}

type finalityHeader struct {
	hash   []byte
	header data.HeaderHandler
	raw    []byte
	proof  []byte
}

// fetch returns the native header with the given hash. The bytes it returns
// are the ones every later check consumes.
func (f *FinalityImport) fetch(shardID uint32, hash []byte) (*finalityHeader, error) {
	header, err := f.args.Source.Header(shardID, hash)
	if err != nil {
		return nil, err
	}
	if check.IfNil(header) || header.GetShardID() != shardID {
		return nil, ErrFinalityImport
	}
	raw, err := f.args.Marshaller.Marshal(header)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(f.args.Hasher.Compute(string(raw)), hash) {
		return nil, ErrFinalityImport
	}
	return &finalityHeader{hash: bytes.Clone(hash), header: header, raw: raw}, nil
}

func (f *FinalityImport) fetchProofed(shardID uint32, hash []byte) (*finalityHeader, error) {
	out, err := f.fetch(shardID, hash)
	if err != nil {
		return nil, err
	}
	return out, f.attachProof(out)
}

func (f *FinalityImport) attachProof(h *finalityHeader) error {
	proof, err := f.args.Source.Proof(h.header.GetShardID(), h.hash)
	if err != nil {
		return err
	}
	if check.IfNil(proof) {
		return ErrFinalityImport
	}
	h.proof, err = f.args.Marshaller.Marshal(proof)
	return err
}

// importResults seals the parent's manifest root and promotes every origin
// result that the executing header's committed references make canonically
// final. It is called only while at least one manifest is open.
func (f *FinalityImport) importResults(header data.HeaderHandler, headerHash []byte) error {
	consumer, err := f.args.Marshaller.Marshal(header)
	if err != nil {
		return err
	}
	if !bytes.Equal(f.args.Hasher.Compute(string(consumer)), headerHash) {
		return ErrFinalityImport
	}
	if err = f.seal(header.GetPrevHash()); err != nil {
		return err
	}
	if shardHeader, isShard := header.(data.ShardHeaderHandler); isShard {
		return f.importShard(shardHeader, headerHash, consumer)
	}
	return f.importMeta(header, headerHash, consumer)
}

// seal records, for the block executed immediately before this one, the root
// under which its manifest was committed. The stores are at that root now.
func (f *FinalityImport) seal(parent []byte) error {
	if len(parent) == 0 {
		return nil
	}
	items, err := f.records.originItems(parent)
	if err != nil || len(items) == 0 {
		return err
	}
	sealed, err := f.get(finalitySealKind, parent)
	if err != nil {
		return err
	}
	if len(sealed) != 0 {
		return ErrFinalityImport
	}
	root, err := f.args.Accounts.RootHash()
	if err != nil {
		return err
	}
	return f.records.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		return nil, f.put(bytes.Clone(root), finalitySealKind, parent)
	})
}

// walk follows PrevHash from the anchor for at most count metachain headers.
// It stops, without error, at the first header that is not a V3 metachain
// header above genesis: nothing below it can carry a V3 execution result.
func (f *FinalityImport) walk(anchor []byte, count int) ([]*finalityHeader, error) {
	chain := make([]*finalityHeader, 0, count)
	for len(chain) < count {
		current, err := f.fetch(core.MetachainShardId, anchor)
		if err != nil {
			return nil, err
		}
		if _, ok := current.header.(*block.MetaBlockV3); !ok || current.header.GetNonce() == 0 {
			break
		}
		if err = f.attachProof(current); err != nil {
			return nil, err
		}
		chain = append(chain, current)
		anchor = current.header.GetPrevHash()
	}
	return chain, nil
}

func (f *FinalityImport) importShard(header data.ShardHeaderHandler, headerHash, consumer []byte) error {
	refs := header.GetMetaBlockHashes()
	if len(refs) == 0 {
		return nil
	}
	if len(refs) > process.MaxMetaHeadersAllowedInOneShardBlock {
		return ErrFinalityImport
	}
	chain, err := f.walk(refs[len(refs)-1], len(refs)+2)
	if err != nil {
		return err
	}
	for i := 0; i < len(refs) && i < len(chain); i++ {
		if !bytes.Equal(chain[i].hash, refs[len(refs)-1-i]) {
			return ErrFinalityImport
		}
	}
	for depth := len(chain) - 1; depth >= 2; depth-- {
		meta := chain[depth].header.(*block.MetaBlockV3)
		for _, executed := range meta.ShardInfo {
			if executed.ShardID != f.args.SelfShardID {
				continue
			}
			carrier := func() (*finalityHeader, error) { return f.carrier(meta, executed.HeaderHash) }
			if err = f.promote(headerHash, consumer, executed.HeaderHash, chain[:depth+1], carrier); err != nil {
				return err
			}
		}
	}
	return nil
}

// carrier opens the own-shard headers the metachain header proposes and
// returns the single one that carries the execution result of the origin.
func (f *FinalityImport) carrier(meta *block.MetaBlockV3, origin []byte) (*finalityHeader, error) {
	var found *finalityHeader
	for _, proposal := range meta.ShardInfoProposal {
		if proposal.ShardID != f.args.SelfShardID {
			continue
		}
		candidate, err := f.fetchProofed(f.args.SelfShardID, proposal.HeaderHash)
		if err != nil {
			return nil, err
		}
		for _, result := range candidate.header.GetExecutionResultsHandlers() {
			if check.IfNil(result) || !bytes.Equal(result.GetHeaderHash(), origin) {
				continue
			}
			if found != nil {
				return nil, ErrFinalityImport
			}
			found = candidate
		}
	}
	if found == nil {
		return nil, ErrFinalityImport
	}
	return found, nil
}

func (f *FinalityImport) importMeta(header data.HeaderHandler, headerHash, consumer []byte) error {
	chain, err := f.walk(header.GetPrevHash(), 3)
	if err != nil {
		return err
	}
	if len(chain) < 3 {
		return nil
	}
	carrying := chain[2]
	for _, result := range carrying.header.GetExecutionResultsHandlers() {
		carrier := func() (*finalityHeader, error) { return carrying, nil }
		if err = f.promote(headerHash, consumer, result.GetHeaderHash(), chain, carrier); err != nil {
			return err
		}
	}
	return nil
}

// promote does nothing when the origin holds no manifest in the current state.
// Otherwise the whole predicate must hold and the whole manifest is promoted.
func (f *FinalityImport) promote(headerHash, consumer, origin []byte, chain []*finalityHeader,
	carrier func() (*finalityHeader, error)) error {
	manifest, err := f.records.originItems(origin)
	if err != nil || len(manifest) == 0 {
		return err
	}
	carrying, err := carrier()
	if err != nil {
		return err
	}
	executed, err := f.fetch(f.args.SelfShardID, origin)
	if err != nil {
		return err
	}
	w := canonicalResultWitness{Consumer: consumer,
		Account: AccountItemWitness{Header: carrying.raw, ExecutedHeader: executed.raw}}
	if f.args.SelfShardID != core.MetachainShardId {
		w.HeaderProof = carrying.proof
	}
	for _, link := range chain {
		w.MetaHeaders = append(w.MetaHeaders, link.raw)
		w.MetaProofs = append(w.MetaProofs, link.proof)
	}
	projection, err := f.reader.readBoundedContext(headerHash, f.args.SelfShardID, f.args.SelfShardID, origin, w)
	if err != nil {
		return err
	}
	// The matching reference must be the header this block selected for the
	// origin, with both of its proofed descendants inside the supplied chain.
	if len(projection.metaHeaderHashes) != len(chain) {
		return ErrFinalityImport
	}
	root, err := f.reader.accounts.executionRoot(f.args.SelfShardID, w.Account)
	if err != nil {
		return err
	}
	sealed, err := f.get(finalitySealKind, origin)
	if err != nil {
		return err
	}
	if len(root) == 0 || !bytes.Equal(sealed, root) {
		return ErrFinalityImport
	}
	evidence := f.args.Hasher.Compute(string(bytes.Join([][]byte{
		headerHash, chain[len(chain)-1].hash, carrying.hash, origin, root}, nil)))
	items := make([]pendingFinalPromotion, 0, len(manifest))
	budget := 0
	for _, digest := range manifest {
		recordKey, e := f.get(finalityWorkKind, origin, digest)
		if e != nil {
			return e
		}
		encoded, e := f.get("pending", recordKey)
		if e != nil {
			return e
		}
		fields, e := f.records.codec.unframe(encoded, 5)
		if e != nil {
			return e
		}
		if len(fields[1]) != 8 || !bytes.Equal(fields[0], recordKey) || !bytes.Equal(fields[4], origin) {
			return ErrFinalityImport
		}
		items = append(items, pendingFinalPromotion{candidate: pendingFinalCandidate{
			key: fields[0], version: binary.BigEndian.Uint64(fields[1]), predecessor: fields[2],
			body: fields[3], origin: fields[4]}, evidence: evidence})
		budget += len(encoded) + len(evidence)
	}
	f.canonical, f.evidence = origin, evidence
	defer func() { f.canonical, f.evidence = nil, nil }()
	return f.records.promoteResult(items, manifest, f.maxItems, budget)
}

// finalityHost is the production pendingFinalHost. Its callbacks run inside
// the owner's journal operation with the owner's mutex held.
type finalityHost FinalityImport

// IsInterfaceNil returns true if there is no value under the interface
func (h *finalityHost) IsInterfaceNil() bool { return h == nil }

func (h *finalityHost) decode(candidate []byte) (FinalityRecordClass, [][]byte, error) {
	if h.records == nil {
		return nil, nil, ErrFinalityImport
	}
	fields, err := h.records.codec.unframe(candidate, 5)
	if err != nil {
		return nil, nil, err
	}
	if len(fields[1]) != 8 {
		return nil, nil, ErrFinalityImport
	}
	for _, prefix := range h.prefixes {
		if bytes.HasPrefix(fields[0], []byte(prefix)) {
			return h.args.Classes[prefix], fields, nil
		}
	}
	return nil, nil, ErrFinalityImport
}

// Admit accepts only a record of an installed class, filed under the block in
// execution, that the class owner admits.
func (h *finalityHost) Admit(candidate []byte) error {
	class, fields, err := h.decode(candidate)
	if err != nil {
		return err
	}
	if len(h.executing) == 0 || !bytes.Equal(fields[4], h.executing) {
		return ErrFinalityImport
	}
	return class.Admit(bytes.Clone(fields[0]), binary.BigEndian.Uint64(fields[1]), bytes.Clone(fields[2]), bytes.Clone(fields[3]))
}

// Initialize charges the finalization work to the writing transaction and
// files the item in the origin's bounded work set.
func (h *finalityHost) Initialize(candidate []byte) (*vmcommon.VMOutput, error) {
	class, fields, err := h.decode(candidate)
	if err != nil {
		return nil, err
	}
	f := (*FinalityImport)(h)
	registered, err := f.records.originItems(fields[4])
	if err != nil {
		return nil, err
	}
	if len(registered) >= f.maxItems {
		return nil, ErrFinalityImport
	}
	gas := class.FinalizationGas(len(candidate), len(registered))
	if gas == 0 || h.charge == nil {
		return nil, ErrFinalityImport
	}
	if err = h.charge(gas); err != nil {
		return nil, err
	}
	if len(registered) == 0 {
		if err = f.adjustOpen(1); err != nil {
			return nil, err
		}
	}
	err = f.put(bytes.Clone(fields[0]), finalityWorkKind, fields[4], f.args.Hasher.Compute(string(candidate)))
	if err != nil {
		return nil, err
	}
	return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 0}, nil
}

// Canonical accepts only the evidence the import phase derived for this
// origin from the executing header's committed references.
func (h *finalityHost) Canonical(candidate, evidence []byte) error {
	_, fields, err := h.decode(candidate)
	if err != nil {
		return err
	}
	if len(h.canonical) == 0 || len(h.evidence) == 0 || !bytes.Equal(fields[4], h.canonical) ||
		!bytes.Equal(evidence, h.evidence) {
		return ErrFinalityImport
	}
	return nil
}

// Observe builds the authoritative-state observation and terminalizes the
// finalization item; the last item of an origin closes its manifest.
func (h *finalityHost) Observe(candidate []byte) (*vmcommon.VMOutput, error) {
	_, fields, err := h.decode(candidate)
	if err != nil {
		return nil, err
	}
	f := (*FinalityImport)(h)
	digest := f.args.Hasher.Compute(string(candidate))
	registered, err := f.records.originItems(fields[4])
	if err != nil {
		return nil, err
	}
	if len(registered) == 0 {
		return nil, ErrFinalityImport
	}
	if err = f.put(nil, finalityWorkKind, fields[4], digest); err != nil {
		return nil, err
	}
	if len(registered) == 1 {
		if err = f.put(nil, finalitySealKind, fields[4]); err != nil {
			return nil, err
		}
		if err = f.adjustOpen(-1); err != nil {
			return nil, err
		}
	}
	output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, Logs: []*vmcommon.LogEntry{{
		Identifier: []byte(FinalHeadObservation),
		Address:    bytes.Clone(core.SystemAccountAddress),
		Topics:     [][]byte{bytes.Clone(fields[0]), bytes.Clone(fields[1]), digest, bytes.Clone(fields[4])},
	}}}
	f.observations = append(f.observations, output)
	return output, nil
}
