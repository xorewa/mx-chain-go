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
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
)

// EXPERIMENTAL P06 representations (A L3190-3281), not allocated wire fields.
// No ordinary dispatcher, System-SC or processor imports this foundation.
const adminAppliedPrefix = core.ProtectedKeyPrefix + "DRWA@adminApplied@"

var errAdminCarrier = errors.New("invalid DRWA admin carrier construction")

type adminEffectEnvelope struct {
	effectID, legID, operation, origin, openCommitment []byte
	tokenID, tokenType, binding                        []byte
	cebEpoch                                           uint64
	actionID, planDigest                               []byte
	planStep                                           []byte // absent or exact uint64, not an inferred zero
	normalizedDigest, discriminator, payload           []byte
	targetShard                                        uint32
	targetKey, predecessor, result, gasVersion         []byte
	workLimit                                          uint64
}

func (e adminEffectEnvelope) copy() adminEffectEnvelope {
	for _, field := range []*[]byte{&e.effectID, &e.legID, &e.operation, &e.origin, &e.openCommitment,
		&e.tokenID, &e.tokenType, &e.binding, &e.actionID, &e.planDigest, &e.planStep,
		&e.normalizedDigest, &e.discriminator, &e.payload, &e.targetKey, &e.predecessor, &e.result, &e.gasVersion} {
		*field = bytes.Clone(*field)
	}
	return e
}

// adminCarrierHost is a TRUSTED protocol adapter, never supplied by untrusted
// ingress. VerifyCanonical must authenticate the exact protected origin result,
// immutable OpenEffect and canonical leg commitment, including all envelope
// fields. ValidateLocal supplies the EXACT current/prepared/terminal dependency,
// allowed native effect/target and sufficient PINNED work (all seven A predicates).
// No default implementation exists; bytes, sender and a discriminator alone
// cannot satisfy it. Actual native adapters/finality/transport/funding remain
// first-consumer prerequisites under L23, T10/T43 and AR-13.
//
// StateHash reads the actual target state. ApplyNative reuses the whole native
// inner effect without forging a public CallerAddr. Ack attaches this exact
// candidate ACK to the actual native output within the same T04 operation; it
// must neither publish nor commit independently. Same-locus operations need no
// carrier. Synthetic hosts in qualification establish no protocol provenance.
type adminCarrierHost interface {
	VerifyCanonical(envelope, proof []byte) error
	ValidateLocal(envelope adminEffectEnvelope) error
	StateHash(envelope adminEffectEnvelope) ([]byte, error)
	ApplyNative(envelope adminEffectEnvelope) (*vmcommon.VMOutput, error)
	Ack(envelope adminEffectEnvelope, ack []byte, output *vmcommon.VMOutput) (*vmcommon.VMOutput, error)
	IsInterfaceNil() bool
}

type adminCarrier struct {
	codec    *registrationRecords
	boundary *RollbackContainment
	host     adminCarrierHost
	domain   []byte
}

func newAdminCarrier(accounts state.AccountsAdapter, boundary *RollbackContainment,
	marshaller marshal.Marshalizer, hasher hashing.Hasher, domain []byte, maxBytes int,
	host adminCarrierHost) (*adminCarrier, error) {
	if boundary == nil || check.IfNil(host) || len(domain) == 0 || len(domain) > maxBytes {
		return nil, errAdminCarrier
	}
	owned := false
	for _, store := range boundary.stores {
		owned = owned || store == accounts
	}
	if !owned {
		return nil, errAdminCarrier
	}
	codec, err := newRegistrationRecords(accounts, marshaller, hasher, maxBytes)
	if err != nil {
		return nil, err
	}
	return &adminCarrier{codec: codec, boundary: boundary, host: host, domain: bytes.Clone(domain)}, nil
}

func (c *adminCarrier) digest(purpose string, fields ...[]byte) ([]byte, error) {
	preimage, err := c.codec.frame(append([][]byte{[]byte("DRWA/ADMIN/" + purpose + "/candidate1"), c.domain}, fields...)...)
	if err != nil {
		return nil, err
	}
	return c.codec.hasher.Compute(string(preimage)), nil
}

// Normalize native function/hex arguments using the pinned parser. Upper/lower
// hex represent the same baseline argument bytes; function names remain exact.
// Bounds precede the native parser allocation, and argument order is preserved.
func (c *adminCarrier) normalized(payload, discriminator []byte) ([]byte, error) {
	if len(payload) == 0 || len(payload) > c.codec.maxBytes {
		return nil, errAdminCarrier
	}
	function, arguments, err := parsers.NewCallArgsParser().ParseData(string(payload))
	if err != nil || !bytes.Equal([]byte(function), discriminator) {
		return nil, errAdminCarrier
	}
	return c.digest("NORMALIZED", append([][]byte{[]byte(function)}, arguments...)...)
}

func (c *adminCarrier) encode(e adminEffectEnvelope) ([]byte, error) {
	for _, digest := range [][]byte{e.effectID, e.legID, e.origin, e.openCommitment, e.normalizedDigest, e.predecessor, e.result} {
		if len(digest) != c.codec.hasher.Size() {
			return nil, errAdminCarrier
		}
	}
	if !vmcommon.ValidateToken(e.tokenID) || len(e.targetKey) == 0 || len(e.gasVersion) == 0 || e.workLimit == 0 ||
		e.targetShard == core.MetachainShardId || len(e.actionID) != 0 && len(e.actionID) != c.codec.hasher.Size() ||
		len(e.planDigest) != 0 && len(e.planDigest) != c.codec.hasher.Size() ||
		len(e.planDigest) == 0 && len(e.planStep) != 0 || len(e.planDigest) != 0 && len(e.planStep) != 8 {
		return nil, errAdminCarrier
	}
	switch string(e.tokenType) {
	case core.FungibleESDT, core.NonFungibleESDTv2, core.SemiFungibleESDT, core.MetaESDT,
		core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT:
	default:
		return nil, errAdminCarrier
	}
	switch string(e.binding) {
	case "CURRENT_CEB", "PREPARED_CEB", "TERMINAL":
	default:
		return nil, errAdminCarrier
	}
	switch string(e.operation) {
	case "DRWAApplyTokenAdmin", "DRWAMetadataMutation":
	case "DRWAApplyRequalificationAdmin":
		if string(e.binding) != "PREPARED_CEB" || len(e.actionID) == 0 || len(e.planDigest) == 0 {
			return nil, errAdminCarrier
		}
	default:
		return nil, errAdminCarrier
	}
	normalized, err := c.normalized(e.payload, e.discriminator)
	if err != nil || !bytes.Equal(normalized, e.normalizedDigest) {
		return nil, errAdminCarrier
	}
	return c.codec.frame([]byte("DRWA/ADMIN_ENVELOPE/candidate1"), c.domain,
		e.effectID, e.legID, e.operation, e.origin, e.openCommitment, e.tokenID, e.tokenType, e.binding,
		binary.BigEndian.AppendUint64(nil, e.cebEpoch), e.actionID, e.planDigest, e.planStep,
		e.normalizedDigest, e.discriminator, e.payload, binary.BigEndian.AppendUint32(nil, e.targetShard),
		e.targetKey, e.predecessor, e.result, e.gasVersion, binary.BigEndian.AppendUint64(nil, e.workLimit))
}

func (c *adminCarrier) decode(encoded []byte) (adminEffectEnvelope, error) {
	f, err := c.codec.unframe(encoded, 23)
	if err != nil || !bytes.Equal(f[0], []byte("DRWA/ADMIN_ENVELOPE/candidate1")) || !bytes.Equal(f[1], c.domain) ||
		len(f[10]) != 8 || len(f[17]) != 4 || len(f[22]) != 8 {
		return adminEffectEnvelope{}, errAdminCarrier
	}
	e := adminEffectEnvelope{effectID: f[2], legID: f[3], operation: f[4], origin: f[5], openCommitment: f[6],
		tokenID: f[7], tokenType: f[8], binding: f[9], cebEpoch: binary.BigEndian.Uint64(f[10]),
		actionID: f[11], planDigest: f[12], planStep: f[13], normalizedDigest: f[14], discriminator: f[15], payload: f[16],
		targetShard: binary.BigEndian.Uint32(f[17]), targetKey: f[18], predecessor: f[19], result: f[20],
		gasVersion: f[21], workLimit: binary.BigEndian.Uint64(f[22])}
	canonical, err := c.encode(e)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return adminEffectEnvelope{}, errAdminCarrier
	}
	return e, nil
}

func (c *adminCarrier) readApplied(key []byte) ([]byte, error) {
	account, err := c.codec.state.systemAccount()
	if err != nil {
		return nil, err
	}
	applied, _, err := account.RetrieveValue(key)
	if err != nil {
		return nil, err
	}
	if len(applied) > c.codec.maxBytes {
		return nil, errAdminCarrier
	}
	return bytes.Clone(applied), nil
}

func (c *adminCarrier) checkApplied(key, expected []byte) error {
	applied, err := c.readApplied(key)
	if err != nil {
		return err
	}
	if !bytes.Equal(applied, expected) {
		return errAdminCarrier
	}
	return nil
}

// apply is an isolated DESTINATION foundation. It neither emits an origin leg
// nor grants real native protocol context. Every external adapter receives a
// separate copy; mutating an adapter's buffers cannot change our
// retained binding. All authentication precedes duplicate handling.
//
// The actual producer MUST admit aggregate applied-identity count/rate/retention
// and completion funding before a consumer; maxBytes is only a per-record bound.
// No TTL, erase/compaction, retry timer or implicit redrive authority is supplied.
func (c *adminCarrier) apply(encoded, proof []byte) error {
	if len(proof) == 0 || len(proof) > c.codec.maxBytes {
		return errAdminCarrier
	}
	e, err := c.decode(encoded)
	if err != nil {
		return err
	}
	encoded, proof = bytes.Clone(encoded), bytes.Clone(proof)
	id, err := c.digest("APPLIED_ID", e.effectID, e.legID)
	if err != nil {
		return err
	}
	key := append([]byte(adminAppliedPrefix), id...)
	// All exact identity/terminal-policy/target/result fields are present in the
	// candidate ACK, rather than inferred from an equal local state hash.
	ack, err := c.codec.frame([]byte("DRWA/ADMIN_ACK/candidate1"), encoded)
	if err != nil {
		return err
	}
	fresh := e.copy
	acknowledge := func(output *vmcommon.VMOutput) (*vmcommon.VMOutput, error) {
		acked, err := c.host.Ack(fresh(), bytes.Clone(ack), output)
		if err != nil {
			return nil, err
		}
		if acked == nil || acked.ReturnCode != vmcommon.Ok {
			return nil, errAdminCarrier
		}
		if err = c.checkApplied(key, encoded); err != nil {
			return nil, err
		}
		current, err := c.host.StateHash(fresh())
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(current, e.result) {
			return nil, errAdminCarrier
		}
		if err = c.checkApplied(key, encoded); err != nil {
			return nil, err
		}
		return acked, nil
	}
	return c.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		applied, err := c.readApplied(key)
		if err != nil {
			return nil, err
		}
		if err = c.host.VerifyCanonical(bytes.Clone(encoded), bytes.Clone(proof)); err != nil {
			return nil, err
		}
		if err = c.checkApplied(key, applied); err != nil {
			return nil, err
		}
		if err = c.host.ValidateLocal(fresh()); err != nil {
			return nil, err
		}
		if err = c.checkApplied(key, applied); err != nil {
			return nil, err
		}
		current, err := c.host.StateHash(fresh())
		if err != nil {
			return nil, err
		}
		if err = c.checkApplied(key, applied); err != nil {
			return nil, err
		}
		if len(applied) != 0 {
			if !bytes.Equal(applied, encoded) || !bytes.Equal(current, e.result) {
				return nil, errAdminCarrier
			}
			return acknowledge(nil)
		}
		if !bytes.Equal(current, e.predecessor) {
			return nil, errAdminCarrier
		}
		output, err := c.host.ApplyNative(fresh())
		if err != nil {
			return nil, err
		}
		if output == nil || output.ReturnCode != vmcommon.Ok {
			return nil, errAdminCarrier
		}
		if err = c.checkApplied(key, nil); err != nil {
			return nil, err
		}
		current, err = c.host.StateHash(fresh())
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(current, e.result) {
			return nil, errAdminCarrier
		}
		if err = c.checkApplied(key, nil); err != nil {
			return nil, err
		}
		if err = c.host.ValidateLocal(fresh()); err != nil {
			return nil, err
		}
		if err = c.checkApplied(key, nil); err != nil {
			return nil, err
		}
		// The native inner effect may have saved/reloaded this same account.
		// Never save a pre-effect account alias over its updated native data trie.
		account, err := c.codec.state.systemAccount()
		if err != nil {
			return nil, err
		}
		if err = account.SaveKeyValue(key, bytes.Clone(encoded)); err != nil {
			return nil, err
		}
		if err = c.codec.state.accounts.SaveAccount(account); err != nil {
			return nil, err
		}
		return acknowledge(output)
	})
}
