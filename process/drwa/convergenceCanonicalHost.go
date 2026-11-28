package drwa

import (
	"bytes"
	"encoding/binary"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	disabledStatistics "github.com/multiversx/mx-chain-go/common/statistics/disabled"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// EXPERIMENTAL storage domains of the production convergence host (Part B
// L344-346): not allocated release formats. They are separate from the live
// progress domain so that compaction of progress keeps the receipts.
const (
	convergenceReceiptPrefix     = core.ProtectedKeyPrefix + "DRWA@convergenceReceipt@"
	convergenceParentPrefix      = core.ProtectedKeyPrefix + "DRWA@convergenceParent@"
	convergenceEntitlementPrefix = core.ProtectedKeyPrefix + "DRWA@convergenceEntitlement@"
	convergenceAckPrefix         = core.ProtectedKeyPrefix + "DRWA@convergenceAck@"
)

// ConvergenceCompleteObservation identifies the native observation of a phase
// whose complete required set was acknowledged and whose parent receipt is durable.
const ConvergenceCompleteObservation = "DRWAConvergenceComplete"

// ConvergenceBinding is the decoded immutable context of one phase instance:
// the seven coordinates of Part A L1038-1052 (family, instance, phase, subject,
// target, dependencies, required shard set) plus the containing lineage.
type ConvergenceBinding struct {
	Family, Action, Digest, Phase, Token []byte
	Version                              uint64
	Target, Dependencies, RequiredSet    []byte
	Shards                               []uint32
	Lineage, Predecessor                 []byte
}

// ConvergenceFamilyOwner is supplied by the row that owns a family's producer.
// VerifyTransition authenticates the complete binding against that owner's
// authoritative state (the consumed intent, the governed action and its
// digest, the root lineage, the terminal plan) and its lawful predecessor. It
// is read-only. No owner is built in: a family without one is refused.
type ConvergenceFamilyOwner interface {
	VerifyTransition(binding ConvergenceBinding) error
	IsInterfaceNil() bool
}

// ConvergenceBlockSource names the metachain block in execution: its committed
// hash, its exact header bytes and its epoch. The finality import owner of the
// block processor is the production source.
type ConvergenceBlockSource interface {
	ExecutingBlock() (hash, header []byte, epoch uint32, err error)
	IsInterfaceNil() bool
}

// ArgsConvergenceHost holds the native dependencies of the production host.
// Limits is the chain-global retained budget of SP2-29. EvidenceBytes bounds
// one acknowledgement's whole evidence. No value has a default.
type ArgsConvergenceHost struct {
	Accounts      state.AccountsAdapter
	Records       *registrationRecords
	Reader        *canonicalResultReader
	Block         ConvergenceBlockSource
	Limits        RegistrationResourceLimits
	EvidenceBytes int
	Owners        map[string]ConvergenceFamilyOwner
}

// ConvergenceHost is the production convergenceHost of the metachain (Part A
// E.17.3). An acknowledgement counts only when the producing shard's own
// system account holds the exact acknowledgement item in an execution result
// that is canonically final for the block in execution, under SP2-22's
// S/result/root/H/M/B predicate. Phase creation and the parent receipt are
// retained records charged to the global budget before they are written.
type ConvergenceHost struct {
	args     ArgsConvergenceHost
	evidence *registrationRecords
	cache    *convergenceProofCache
}

// NewConvergenceHost creates the host. It reads no state.
func NewConvergenceHost(args ArgsConvergenceHost) (*ConvergenceHost, error) {
	if check.IfNil(args.Accounts) || args.Records == nil || args.Records.state == nil ||
		args.Records.state.accounts != args.Accounts || args.Reader == nil || check.IfNil(args.Block) ||
		args.Limits.Records == 0 || args.Limits.RetainedBytes == 0 || args.Limits.NewRecordsPerEpoch == 0 ||
		args.EvidenceBytes <= 0 {
		return nil, errConvergence
	}
	owners := make(map[string]ConvergenceFamilyOwner, len(args.Owners))
	for family, owner := range args.Owners {
		if _, admitted := convergenceFamilies[family]; !admitted || check.IfNil(owner) {
			return nil, errConvergence
		}
		owners[family] = owner
	}
	args.Owners = owners
	evidence := *args.Records
	evidence.maxBytes = args.EvidenceBytes
	return &ConvergenceHost{args: args, evidence: &evidence}, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (h *ConvergenceHost) IsInterfaceNil() bool { return h == nil }

// SetFamilyOwner installs the owner of one defined family, once, at node
// construction by the row that owns that family's producer.
func (h *ConvergenceHost) SetFamilyOwner(family string, owner ConvergenceFamilyOwner) error {
	if _, defined := convergenceFamilies[family]; !defined || check.IfNil(owner) {
		return errConvergence
	}
	if _, installed := h.args.Owners[family]; installed {
		return errConvergence
	}
	h.args.Owners[family] = owner
	return nil
}

func (h *ConvergenceHost) decode(binding []byte) (*ConvergenceBinding, error) {
	return decodeConvergenceBinding(h.args.Records, binding)
}

// decodeConvergenceBinding is the one decoder of a phase binding, for the
// metachain host and for a shard that applies the phase's object.
func decodeConvergenceBinding(codec *registrationRecords, binding []byte) (*ConvergenceBinding, error) {
	fields, err := registrationBoundedFields(codec, binding, 10, 12, codec.maxBytes)
	if err != nil || len(fields) == 11 || len(fields[5]) != 8 {
		return nil, errConvergence
	}
	ids, err := registrationBoundedFields(codec, fields[9], 1, codec.maxBytes/6, 4)
	if err != nil {
		return nil, errConvergence
	}
	b := &ConvergenceBinding{Family: fields[0], Action: fields[1], Digest: fields[2], Phase: fields[3], Token: fields[4],
		Version: binary.BigEndian.Uint64(fields[5]), Target: fields[6], Dependencies: fields[7], RequiredSet: fields[8]}
	for _, id := range ids {
		if len(id) != 4 {
			return nil, errConvergence
		}
		b.Shards = append(b.Shards, binary.BigEndian.Uint32(id))
	}
	if len(fields) == 12 {
		b.Lineage, b.Predecessor = fields[10], fields[11]
	}
	return b, nil
}

// identity is the same family-separated phase instance the progress key names.
func (h *ConvergenceHost) identity(b *ConvergenceBinding) ([]byte, error) {
	fields := [][]byte{b.Family, b.Action, b.Phase}
	if len(b.Lineage) != 0 {
		fields = append(fields, b.Lineage)
	}
	encoded, err := h.args.Records.frame(fields...)
	if err != nil {
		return nil, err
	}
	return h.args.Records.hasher.Compute(string(encoded)), nil
}

func (h *ConvergenceHost) admitted(binding []byte) (*ConvergenceBinding, *convergenceFamily, error) {
	b, err := h.decode(binding)
	if err != nil {
		return nil, nil, err
	}
	family, exists := convergenceFamilies[string(b.Family)]
	if !exists {
		return nil, nil, errConvergence
	}
	if _, exists = family.phases[string(b.Phase)]; !exists {
		return nil, nil, errConvergence
	}
	// The nil-context representation is reserved for the one legacy pair.
	if (len(b.Lineage) == 0) != (string(b.Family) == ConvergenceFamilyCEB && string(b.Phase) == "CURRENT_ACK") {
		return nil, nil, errConvergence
	}
	return b, family, nil
}

// VerifyTransition admits only a phase of an installed family whose owner
// authenticates the complete binding.
func (h *ConvergenceHost) VerifyTransition(binding []byte) error {
	b, _, err := h.admitted(binding)
	if err != nil {
		return err
	}
	owner, installed := h.args.Owners[string(b.Family)]
	if !installed {
		return errConvergence
	}
	return owner.VerifyTransition(*b)
}

func (h *ConvergenceHost) budget() *scopedAdmissionRecords {
	return &scopedAdmissionRecords{codec: h.args.Records, limits: scopedAdmissionLimits{recordBytes: h.args.Records.maxBytes,
		records: h.args.Limits.Records, retainedBytes: h.args.Limits.RetainedBytes, newRecordsPerEpoch: h.args.Limits.NewRecordsPerEpoch}}
}

func (h *ConvergenceHost) item(key []byte) (state.UserAccountHandler, []byte, error) {
	account, err := h.args.Records.state.systemAccount()
	if err != nil {
		return nil, nil, err
	}
	value, _, err := account.RetrieveValue(key)
	return account, value, err
}

// Admission is the canonical creation of one phase instance. It refuses a
// phase whose creation receipt exists (non-reuse, also after compaction of the
// live progress), consumes a single-use entitlement where the family has one,
// and charges the receipt and the complete retained progress record to the
// chain-global budget before either exists.
func (h *ConvergenceHost) Admission(binding []byte, retainedBytes uint64) error {
	b, family, err := h.admitted(binding)
	if err != nil {
		return err
	}
	_, _, epoch, err := h.args.Block.ExecutingBlock()
	if err != nil {
		return err
	}
	identity, err := h.identity(b)
	if err != nil {
		return err
	}
	hasher := h.args.Records.hasher
	receiptKey := append([]byte(convergenceReceiptPrefix), identity...)
	account, old, err := h.item(receiptKey)
	if err != nil {
		return err
	}
	if len(old) != 0 || retainedBytes == 0 {
		return errConvergence
	}
	writes := []scopedAdmissionWrite{{receiptKey, hasher.Compute(string(binding))}}
	if family.entitlement {
		// One cancelled or completed predecessor outcome entitles exactly one
		// successor instance of this family (IA-07).
		source, e := h.args.Records.frame(b.Family, b.Token, b.Predecessor)
		if e != nil {
			return e
		}
		key := append([]byte(convergenceEntitlementPrefix), hasher.Compute(string(source))...)
		used, _, e := account.RetrieveValue(key)
		if e != nil {
			return e
		}
		if len(used) != 0 {
			return errConvergence
		}
		writes = append(writes, scopedAdmissionWrite{key, identity})
	}
	budget := h.budget()
	if err = budget.retain(account, epoch, writes...); err != nil {
		return err
	}
	account, err = h.args.Records.state.systemAccount()
	if err != nil {
		return err
	}
	return budget.reserve(account, epoch, retainedBytes)
}

// ConvergenceAckItem returns the key and value of the acknowledgement item an
// execution shard holds in its own system account for one phase instance.
func convergenceAckItem(codec *registrationRecords, binding []byte, shard uint32) (key, value []byte, err error) {
	body, err := codec.frame(binding, binary.BigEndian.AppendUint32(nil, shard))
	if err != nil {
		return nil, nil, err
	}
	return append([]byte(convergenceAckPrefix), codec.hasher.Compute(string(binding))...), codec.hasher.Compute(string(body)), nil
}

func (h *ConvergenceHost) witness(evidence []byte) (canonicalResultWitness, error) {
	var w canonicalResultWitness
	fields, err := h.evidence.unframeBatch(true, evidence, 7)
	if err != nil {
		return w, errConvergence
	}
	lists := make([][][]byte, 4)
	for i, encoded := range fields[3:] {
		if len(encoded) == 0 {
			continue
		}
		if lists[i], err = registrationBoundedFields(h.evidence, encoded, 1, h.args.EvidenceBytes/2, h.args.EvidenceBytes); err != nil {
			return w, errConvergence
		}
	}
	w.Account = AccountItemWitness{ExecutedHeader: fields[0], Header: fields[1], AccountProof: lists[2], DataProof: lists[3]}
	w.HeaderProof, w.MetaHeaders, w.MetaProofs = fields[2], lists[0], lists[1]
	return w, nil
}

// VerifyAck authenticates one acknowledgement. The payload's shard is only a
// claim: the producer is established by the executed header of the evidence,
// which must be a header of that shard, canonically final for the block in
// execution. Its local execution identity is that executed header's hash.
func (h *ConvergenceHost) VerifyAck(binding, ack, evidence []byte) (uint32, error) {
	if _, _, err := h.admitted(binding); err != nil {
		return 0, err
	}
	codec := h.args.Records
	fields, err := codec.unframe(ack, 3)
	if err != nil || !bytes.Equal(fields[0], binding) || len(fields[1]) != 4 || len(fields[2]) != codec.hasher.Size() {
		return 0, errConvergence
	}
	shard := binary.BigEndian.Uint32(fields[1])
	if shard == core.MetachainShardId {
		return 0, errConvergence
	}
	w, err := h.witness(evidence)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(codec.hasher.Compute(string(w.Account.ExecutedHeader)), fields[2]) {
		return 0, errConvergence
	}
	key, expected, err := convergenceAckItem(codec, binding, shard)
	if err != nil {
		return 0, err
	}
	_, value, err := h.readFinalItem(shard, key, w)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(value, expected) {
		return 0, errConvergence
	}
	return shard, nil
}

// readFinalItem reads the value the system account of shard holds under key
// in the executed header of the witness, which must be canonically final for
// the block in execution under SP2-22's S/result/root/H/M/B predicate.
func (h *ConvergenceHost) readFinalItem(shard uint32, key []byte, w canonicalResultWitness) (origin, value []byte, err error) {
	origin = h.args.Records.hasher.Compute(string(w.Account.ExecutedHeader))
	committed, consumer, _, err := h.args.Block.ExecutingBlock()
	if err != nil {
		return nil, nil, err
	}
	w.Consumer = consumer
	if h.cache != nil {
		// Only the nodes of this evidence can complete this read.
		h.cache.nodes = make(map[string][]byte)
	}
	value, err = h.args.Reader.read(committed, core.MetachainShardId, shard, origin, key, w, h.args.EvidenceBytes)
	if err != nil {
		return nil, nil, err
	}
	return origin, value, nil
}

// ReadFinalItem is the same canonical-final read for the acknowledgement item
// of another owner (the applied-leg item of a protected admin leg): the value
// under key in the system account of an execution shard, proven by evidence
// in the form of EncodeConvergenceEvidence, with the hash of the executed
// shard header that holds it. The caller compares the value with what it
// expects; the host admits no phase and writes nothing here.
func (h *ConvergenceHost) ReadFinalItem(shard uint32, key, evidence []byte) (origin, value []byte, err error) {
	if shard == core.MetachainShardId || len(key) == 0 {
		return nil, nil, errConvergence
	}
	w, err := h.witness(evidence)
	if err != nil {
		return nil, nil, err
	}
	return h.readFinalItem(shard, key, w)
}

func (h *ConvergenceHost) parent(binding, commitment []byte) (key, value []byte, err error) {
	b, _, err := h.admitted(binding)
	if err != nil {
		return nil, nil, err
	}
	identity, err := h.identity(b)
	if err != nil {
		return nil, nil, err
	}
	hasher := h.args.Records.hasher
	if len(commitment) != hasher.Size() {
		return nil, nil, errConvergence
	}
	value, err = h.args.Records.frame(hasher.Compute(string(binding)), commitment)
	return append([]byte(convergenceParentPrefix), identity...), value, err
}

// Complete writes the durable parent receipt of a phase whose complete required
// set was acknowledged. The receipt binds the exact binding and the phase
// commitment; it is written once and charged to the global budget.
func (h *ConvergenceHost) Complete(binding, commitment []byte) (*vmcommon.VMOutput, error) {
	key, value, err := h.parent(binding, commitment)
	if err != nil {
		return nil, err
	}
	_, _, epoch, err := h.args.Block.ExecutingBlock()
	if err != nil {
		return nil, err
	}
	account, old, err := h.item(key)
	if err != nil {
		return nil, err
	}
	if len(old) != 0 {
		return nil, errConvergence
	}
	if err = h.budget().retain(account, epoch, scopedAdmissionWrite{key, value}); err != nil {
		return nil, err
	}
	return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, Logs: []*vmcommon.LogEntry{{
		Identifier: []byte(ConvergenceCompleteObservation),
		Address:    bytes.Clone(core.SystemAccountAddress),
		Topics:     [][]byte{bytes.Clone(key[len(convergenceParentPrefix):]), bytes.Clone(commitment)},
	}}}, nil
}

// VerifyParent requires the exact durable parent receipt.
func (h *ConvergenceHost) VerifyParent(binding, commitment []byte) error {
	key, value, err := h.parent(binding, commitment)
	if err != nil {
		return err
	}
	_, stored, err := h.item(key)
	if err != nil {
		return err
	}
	if !bytes.Equal(stored, value) {
		return errConvergence
	}
	return nil
}

// ConvergenceAckWriter is the execution-shard half: it records, in the shard's
// own system account and inside the journal of the operation that applied the
// phase's object locally, that this shard applied it. The row that delivers
// the object to the shard calls it after exact local application.
type ConvergenceAckWriter struct {
	records *registrationRecords
	shard   uint32
}

// NewConvergenceAckWriter creates the writer of one execution shard.
func NewConvergenceAckWriter(records *registrationRecords, shard uint32) (*ConvergenceAckWriter, error) {
	if records == nil || records.state == nil || shard == core.MetachainShardId {
		return nil, errConvergence
	}
	return &ConvergenceAckWriter{records: records, shard: shard}, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (w *ConvergenceAckWriter) IsInterfaceNil() bool { return w == nil }

// Acknowledge writes the item once. An exact repeat writes nothing; a
// different value under the same phase instance is refused.
func (w *ConvergenceAckWriter) Acknowledge(binding []byte) error {
	if len(binding) == 0 || len(binding) > w.records.maxBytes {
		return errConvergence
	}
	key, value, err := convergenceAckItem(w.records, binding, w.shard)
	if err != nil {
		return err
	}
	account, err := w.records.state.systemAccount()
	if err != nil {
		return err
	}
	old, _, err := account.RetrieveValue(key)
	if err != nil {
		return err
	}
	if len(old) != 0 {
		if !bytes.Equal(old, value) {
			return errConvergence
		}
		return nil
	}
	if err = account.SaveKeyValue(key, value); err != nil {
		return err
	}
	return w.records.state.accounts.SaveAccount(account)
}

// EncodeConvergenceEvidence frames the evidence of one acknowledgement. The
// consuming block's header is never part of it: the host takes that from the
// block in execution.
func encodeConvergenceEvidence(codec *registrationRecords, w canonicalResultWitness) ([]byte, error) {
	lists := make([][]byte, 4)
	for i, list := range [][][]byte{w.MetaHeaders, w.MetaProofs, w.Account.AccountProof, w.Account.DataProof} {
		if len(list) == 0 {
			continue
		}
		encoded, err := codec.frame(list...)
		if err != nil {
			return nil, err
		}
		lists[i] = encoded
	}
	return codec.frameBatch(true, w.Account.ExecutedHeader, w.Account.Header, w.HeaderProof, lists[0], lists[1], lists[2], lists[3])
}

// convergenceProofCache is the dedicated proof cache of the host's account
// reader: content-addressed nodes of the evidence in hand, held in memory for
// one read and never execution-state storage. It has no other source.
type convergenceProofCache struct {
	common.StorageManager
	nodes map[string][]byte
}

func (c *convergenceProofCache) Get(key []byte) ([]byte, error) {
	node, found := c.nodes[string(key)]
	if !found {
		return nil, ErrInvalidAccountWitness
	}
	return bytes.Clone(node), nil
}

func (c *convergenceProofCache) GetFromCurrentEpoch(key []byte) ([]byte, error) { return c.Get(key) }

func (c *convergenceProofCache) Put(key, value []byte) error {
	c.nodes[string(key)] = bytes.Clone(value)
	return nil
}

func (c *convergenceProofCache) GetIdentifier() string { return "DRWAConvergenceProofCache" }

func (c *convergenceProofCache) GetStateStatsHandler() common.StateStatisticsHandler {
	return disabledStatistics.NewStateStatistics()
}

func (c *convergenceProofCache) IsInterfaceNil() bool { return c == nil }

// ArgsNativeConvergenceHost holds what the metachain node's factory supplies.
type ArgsNativeConvergenceHost struct {
	Accounts             state.AccountsAdapter
	Marshaller           marshal.Marshalizer
	Hasher               hashing.Hasher
	EnableEpochsHandler  common.EnableEpochsHandler
	MaxTrieLevelInMemory uint
	Validator            process.HeaderConstructionValidator
	Proofs               process.InterceptedHeaderSigVerifier
	Integrity            process.HeaderIntegrityVerifier
	Exclusions           common.RoundExclusionHandler
	Block                ConvergenceBlockSource
	Limits               RegistrationResourceLimits
	RecordBytes          int
	EvidenceBytes        int
	Owners               map[string]ConvergenceFamilyOwner
}

// NewNativeConvergenceHost builds the production host of a metachain node from
// native dependencies: the canonical result reader of SP2-22 with an account
// reader over a dedicated in-memory proof cache.
func NewNativeConvergenceHost(args ArgsNativeConvergenceHost) (*ConvergenceHost, error) {
	records, err := newRegistrationRecords(args.Accounts, args.Marshaller, args.Hasher, args.RecordBytes)
	if err != nil {
		return nil, err
	}
	cache := &convergenceProofCache{nodes: make(map[string][]byte)}
	accounts, err := NewResultAccountReader(ArgsResultAccountReader{StorageManager: cache, Marshaller: args.Marshaller,
		Hasher: args.Hasher, EnableEpochsHandler: args.EnableEpochsHandler, MaxTrieLevelInMemory: args.MaxTrieLevelInMemory})
	if err != nil {
		return nil, err
	}
	reader, err := newCanonicalResultReader(accounts, args.Validator, args.Proofs, args.Integrity, args.Exclusions)
	if err != nil {
		return nil, err
	}
	host, err := NewConvergenceHost(ArgsConvergenceHost{Accounts: args.Accounts, Records: records, Reader: reader, Block: args.Block,
		Limits: args.Limits, EvidenceBytes: args.EvidenceBytes, Owners: args.Owners})
	if err != nil {
		return nil, err
	}
	host.cache = cache
	return host, nil
}
