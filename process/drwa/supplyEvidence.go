package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state"
)

// SP2-78: closure-bound evidence of the origin shard's SupplyState for the
// requalification cap check (Part A L2673-2686, L4056-4058). EXPERIMENTAL form.
//
// The supply-origin shard is the producer: after it is closed for one closure
// instance it writes, in its own system account, one item that binds the token,
// the current CEB, the owning action, the closure instance and the cumulative
// issued value of its exact SupplyState record. The metachain is the consumer:
// it accepts the value only from that item in an execution result of the
// origin shard that is canonically final for the block in execution, under
// SP2-22's result reading. A live remote read, a count/root-only quiescence
// acknowledgement or a caller's number is never the value.
//
// Live production (when a shard attests, under which closure) and the reader's
// own proofs stay with the consuming row, SP2-52.
const (
	supplyEvidencePrefix = core.ProtectedKeyPrefix + "DRWA@supplyEvidence@"
	supplyEvidenceTag    = "DRWA/SUPPLY_EVIDENCE/experimental1"
)

var errSupplyEvidence = errors.New("invalid DRWA supply evidence")

// SupplyEvidenceBinding is what the evidence is bound to: the token, the CEB
// current at closure (epoch and hash), the owning governed action, the closure
// instance and the supply-origin shard of that CEB.
type SupplyEvidenceBinding struct {
	Token       []byte
	CEBEpoch    uint64
	CEBHash     []byte
	Action      []byte
	Closure     uint64
	OriginShard uint32
}

func (b SupplyEvidenceBinding) encode(codec *registrationRecords) ([]byte, error) {
	if codec == nil || check.IfNil(codec.hasher) || len(b.Token) == 0 || b.CEBEpoch == 0 || len(b.CEBHash) != codec.hasher.Size() ||
		len(b.Action) == 0 || b.Closure == 0 || b.OriginShard == core.MetachainShardId {
		return nil, errSupplyEvidence
	}
	raw, err := codec.frameBatch(true, []byte(supplyEvidenceTag), b.Token, certificateNumber(b.CEBEpoch), b.CEBHash, b.Action,
		certificateNumber(b.Closure), binary.BigEndian.AppendUint32(nil, b.OriginShard))
	if err != nil {
		return nil, errSupplyEvidence
	}
	return raw, nil
}

// supplyEvidenceItem returns the key and value of the item for one binding:
// the key is the hash of the binding; the value frames that hash, the
// cumulative issued value and the hash of the exact SupplyState record.
func supplyEvidenceItem(codec *registrationRecords, binding []byte, cumulative *big.Int, supplyHash []byte) (key, value []byte, err error) {
	if cumulative == nil || cumulative.Sign() < 0 || len(supplyHash) != codec.hasher.Size() {
		return nil, nil, errSupplyEvidence
	}
	identity := codec.hasher.Compute(string(binding))
	value, err = codec.frameBatch(true, identity, cumulative.Bytes(), supplyHash)
	if err != nil {
		return nil, nil, errSupplyEvidence
	}
	return append([]byte(supplyEvidencePrefix), identity...), value, nil
}

// SupplyEvidenceWriter is the origin-shard half. The consuming row calls Attest
// inside the journal of the operation that established this shard's closure
// for the binding's closure instance.
type SupplyEvidenceWriter struct {
	records *registrationRecords
	leaves  *rootLeafRecords
	shard   uint32
}

// NewSupplyEvidenceWriter creates the writer of one execution shard.
func NewSupplyEvidenceWriter(records *registrationRecords, leaves *rootLeafRecords, shard uint32) (*SupplyEvidenceWriter, error) {
	if records == nil || records.state == nil || leaves == nil || leaves.codec == nil || shard == core.MetachainShardId {
		return nil, errSupplyEvidence
	}
	return &SupplyEvidenceWriter{records: records, leaves: leaves, shard: shard}, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (w *SupplyEvidenceWriter) IsInterfaceNil() bool { return w == nil }

// Attest writes the item once from the shard's own SupplyState record. It
// refuses a shard that is not the binding's origin, a token without a record,
// and a record of another token or origin shard. An exact repeat writes
// nothing; a different value under the same binding is refused, so a supply
// change after the attestation cannot replace the attested value.
func (w *SupplyEvidenceWriter) Attest(b SupplyEvidenceBinding) error {
	binding, err := b.encode(w.records)
	if err != nil {
		return err
	}
	if b.OriginShard != w.shard {
		return errSupplyEvidence
	}
	supplyKey, err := w.leaves.outerKey(supplyStatePrefix, b.Token)
	if err != nil {
		return errSupplyEvidence
	}
	account, err := w.records.state.systemAccount()
	if err != nil {
		return err
	}
	supplyRaw, _, err := account.RetrieveValue(supplyKey)
	if err != nil {
		return err
	}
	supply, err := w.leaves.decodeSupplyRecord(supplyRaw)
	if err != nil || !bytes.Equal(supply.token, b.Token) || supply.originShard != w.shard {
		return errSupplyEvidence
	}
	key, value, err := supplyEvidenceItem(w.records, binding, supply.accounting.cumulativeIssued, w.records.hasher.Compute(string(supplyRaw)))
	if err != nil {
		return err
	}
	old, _, err := account.RetrieveValue(key)
	if err != nil {
		return err
	}
	if len(old) != 0 {
		if !bytes.Equal(old, value) {
			return errSupplyEvidence
		}
		return nil
	}
	if err = account.SaveKeyValue(key, value); err != nil {
		return err
	}
	return w.records.state.accounts.SaveAccount(account)
}

// ArgsSupplyEvidenceVerifier holds the dependencies of the metachain half.
// EvidenceBytes bounds one presented evidence. No value has a default.
type ArgsSupplyEvidenceVerifier struct {
	Records       *registrationRecords
	Reader        *canonicalResultReader
	Block         ConvergenceBlockSource
	EvidenceBytes int
}

// SupplyEvidenceVerifier is the metachain half: the one object the cap
// validator of the consuming row calls.
type SupplyEvidenceVerifier struct {
	args     ArgsSupplyEvidenceVerifier
	evidence *registrationRecords
	cache    *convergenceProofCache
}

// NewSupplyEvidenceVerifier creates the verifier. It reads no state.
func NewSupplyEvidenceVerifier(args ArgsSupplyEvidenceVerifier) (*SupplyEvidenceVerifier, error) {
	if args.Records == nil || check.IfNil(args.Records.hasher) || args.Reader == nil || check.IfNil(args.Block) || args.EvidenceBytes <= 0 {
		return nil, errSupplyEvidence
	}
	evidence := *args.Records
	evidence.maxBytes = args.EvidenceBytes
	return &SupplyEvidenceVerifier{args: args, evidence: &evidence}, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (v *SupplyEvidenceVerifier) IsInterfaceNil() bool { return v == nil }

func (v *SupplyEvidenceVerifier) witness(evidence []byte) (canonicalResultWitness, error) {
	var w canonicalResultWitness
	fields, err := v.evidence.unframeBatch(true, evidence, 7)
	if err != nil {
		return w, errSupplyEvidence
	}
	lists := make([][][]byte, 4)
	for i, encoded := range fields[3:] {
		if len(encoded) == 0 {
			continue
		}
		if lists[i], err = registrationBoundedFields(v.evidence, encoded, 1, v.args.EvidenceBytes/2, v.args.EvidenceBytes); err != nil {
			return w, errSupplyEvidence
		}
	}
	w.Account = AccountItemWitness{ExecutedHeader: fields[0], Header: fields[1], AccountProof: lists[2], DataProof: lists[3]}
	w.HeaderProof, w.MetaHeaders, w.MetaProofs = fields[2], lists[0], lists[1]
	return w, nil
}

// CumulativeIssued returns the origin shard's cumulative issued value for
// exactly this binding. evidence is the witness of the item in the form of an
// acknowledgement's evidence (executed header, carrying header and its proof,
// metachain headers and proofs, account and data proofs). Evidence of another
// token, CEB, action, closure instance or shard, a result that is not
// canonically final for the block in execution, and an item whose value is not
// the canonical form are refused. It changes no state.
func (v *SupplyEvidenceVerifier) CumulativeIssued(b SupplyEvidenceBinding, evidence []byte) (*big.Int, error) {
	codec := v.args.Records
	binding, err := b.encode(codec)
	if err != nil {
		return nil, err
	}
	w, err := v.witness(evidence)
	if err != nil {
		return nil, err
	}
	committed, consumer, _, err := v.args.Block.ExecutingBlock()
	if err != nil {
		return nil, err
	}
	w.Consumer = consumer
	identity := codec.hasher.Compute(string(binding))
	if v.cache != nil {
		// Only the nodes of this evidence can complete this read.
		v.cache.nodes = make(map[string][]byte)
	}
	value, err := v.args.Reader.read(committed, core.MetachainShardId, b.OriginShard, codec.hasher.Compute(string(w.Account.ExecutedHeader)),
		append([]byte(supplyEvidencePrefix), identity...), w, v.args.EvidenceBytes)
	if err != nil {
		return nil, err
	}
	fields, err := codec.unframeBatch(true, value, 3)
	if err != nil || !bytes.Equal(fields[0], identity) || len(fields[2]) != codec.hasher.Size() {
		return nil, errSupplyEvidence
	}
	cumulative := new(big.Int).SetBytes(fields[1])
	if !bytes.Equal(cumulative.Bytes(), fields[1]) {
		return nil, errSupplyEvidence
	}
	return cumulative, nil
}

// ValidateCap is the supply-cap consistency rule at target CEB validation
// (Part A L2673-2677): a present cap must not be below the cumulative issued
// value of the origin's exact SupplyState for this closure. A nil cap is the
// explicit absence of max_cumulative_issued; the evidence is still required
// and returned, so the caller never proceeds on an unread value.
func (v *SupplyEvidenceVerifier) ValidateCap(b SupplyEvidenceBinding, maxCumulativeIssued *big.Int, evidence []byte) (*big.Int, error) {
	if maxCumulativeIssued != nil && maxCumulativeIssued.Sign() < 0 {
		return nil, errSupplyEvidence
	}
	cumulative, err := v.CumulativeIssued(b, evidence)
	if err != nil {
		return nil, err
	}
	if maxCumulativeIssued != nil && maxCumulativeIssued.Cmp(cumulative) < 0 {
		return nil, errSupplyEvidence
	}
	return cumulative, nil
}

// ArgsNativeSupplyEvidenceVerifier are the native dependencies of a metachain
// node's verifier: those of the canonical result reader, the block source and
// the two byte bounds of the admitted profile.
type ArgsNativeSupplyEvidenceVerifier struct {
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
	RecordBytes          int
	EvidenceBytes        int
}

// NewNativeSupplyEvidenceVerifier builds the production verifier of a
// metachain node: SP2-22's canonical result reader over a dedicated in-memory
// proof cache that holds only the nodes of the evidence in hand.
func NewNativeSupplyEvidenceVerifier(args ArgsNativeSupplyEvidenceVerifier) (*SupplyEvidenceVerifier, error) {
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
	verifier, err := NewSupplyEvidenceVerifier(ArgsSupplyEvidenceVerifier{Records: records, Reader: reader, Block: args.Block, EvidenceBytes: args.EvidenceBytes})
	if err != nil {
		return nil, err
	}
	verifier.cache = cache
	return verifier, nil
}
