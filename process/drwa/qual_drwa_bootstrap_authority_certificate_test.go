package drwa

import (
	"bytes"
	stded "crypto/ed25519"
	"encoding/hex"
	"testing"

	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// A126 uses the existing R3/B9 synthetic bodies, keys, bounds and time inputs.
// These literals were derived from native Batch field-1 bytes and independent
// BLAKE2b-256 before editing the verifier. No production encoder supplied them.
const qualA126MessageHex = "0a36445257412f424f4f5453545241505f494e54454e545f415554484f524954595f43455254494649434154452f63616e646964617465310a08746573742d6e65740a10424f4f5453545241505f494e54454e540a2001010101010101010101010101010101010101010101010101010101010101010a0770726f6772616d0a2011111111111111111111111111111111111111111111111111111111111111110a205984e139336878a8f248d26b79b9fe9b1cca09ca335011652c647cf393f9cdc60a20c757a67702124dfa784f683b4977a385ff23dcaa60ed3c5673d8ae28a5a6cc960a20a94ec7cbe8498d2d8f4e9e9c2250c627eed701a6989d4af334fa2d94cecbd6410ab6010a0d696e646570656e64656e74c3a90a350a08746573742d6e65740a2001010101010101010101010101010101010101010101010101010101010101010a0770726f6772616d0a2042424242424242424242424242424242424242424242424242424242424242420a0800000000000000010a20d49b7f1cf237c75abff4bc6270c666d9688d32d550ba07c9be1a6b0b6dd144e00a20ec92e52cb1cfd9059a27c97e493a72f775a73b59b7f40d63d8250ef4f0bdc3e90a08000000000000000a0a08000000000000005a"
const qualA126DigestHex = "2a94e43fd3b35e1fcdf53ab03d855006cd5ca22a8d28eddec600e9c299b53979"
const qualA126ReorderedCommitmentHex = "a4cbea420e5c4fe8b7625fbb8fe2c06bf0bb5f95d923de173796f67204dfb23f"

func qualA126Bytes(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	require.NoError(t, err)
	return raw
}

func qualA126Message(t *testing.T, ctx *registrationApprovalContext, nb, na uint64) []byte {
	t.Helper()
	intent := qualA38Split(ctx.intentBody)
	set := ctx.independent
	purpose := []byte("BOOTSTRAP_INTENT")
	scope := qualRecordFrame(ctx.network, ctx.scopeOwner, ctx.programme)
	row := qualRecordFrame(purpose, set.role, set.setID, set.version, set.bodyHash)
	projection := qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT_ROLE_MAP/candidate1"), ctx.network, ctx.scopeOwner, ctx.programme, row)
	dependency := qualRecordFrame(set.role, scope, set.setID, set.version, set.bodyHash, qualA38Hash(projection))
	commitment := qualA38Hash(qualRecordFrame(intent[10], intent[12]))
	return qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT_AUTHORITY_CERTIFICATE/candidate1"),
		ctx.network, purpose, ctx.scopeOwner, ctx.programme, ctx.issuer, ctx.intentID, ctx.intentHash,
		commitment, dependency, qualA38U64(nb), qualA38U64(na))
}

func qualA126Verify(c *registrationApprovalCodec, op *rollbackOperation, owner *RollbackContainment,
	source HeaderTimeSource, context *HeaderTimeContext, provider bootstrapProofProvider, b bootstrapProofBinding, raw []byte) error {
	// Rejection-only bridge lets the independently signed positive case run
	// before the adopted entry point exists, without a production test seam.
	v, exists := any(c).(interface {
		verifyBootstrapAuthorityCertificate(*rollbackOperation, *RollbackContainment, HeaderTimeSource, *HeaderTimeContext, bootstrapProofProvider, bootstrapProofBinding, []byte) error
	})
	if !exists {
		return errInvalidRegistrationRecord
	}
	return v.verifyBootstrapAuthorityCertificate(op, owner, source, context, provider, b, raw)
}

func TestQualA126BootstrapAuthorityCertificate(t *testing.T) {
	_, ctx, keys := qualR3Fixture(t, 100)
	m := qualA126Message(t, ctx, 10, 90)
	require.Equal(t, qualA126Bytes(t, qualA126MessageHex), m)
	require.Equal(t, qualA126Bytes(t, qualA126DigestHex), qualA38Hash(m))

	for _, name := range []string{"positive", "wrong_tag", "cross_purpose", "foreign_domain", "foreign_scope", "foreign_programme",
		"foreign_issuer", "wrong_intent_id", "wrong_intent_digest", "changed_admission", "reordered_sets", "body_hash_mismatch",
		"wrong_role", "wrong_set_id", "wrong_version", "wrong_body_hash", "wrong_projection", "wrong_roster", "missing_provider",
		"no_purpose", "no_role", "no_lineage", "stale", "stale_successor", "fresh_successor", "expired_lease", "expired_operation",
		"invalid_extra", "below_threshold", "out_of_order", "duplicate_index", "not_hashed", "noncanonical", "over_budget",
		"shared_pa_key", "shared_pa_id", "all_members", "below_configured_threshold",
		"exact_window", "future", "expired", "after_intent", "over_span", "reversed", "verification_write"} {
		t.Run(name, func(t *testing.T) {
			c, owner, source, time, p, b, _, end := qualBootstrapMechanicsFixture(t)
			_, ctx, _ := qualR3Fixture(t, 100)
			b.purpose = []byte("BOOTSTRAP_INTENT")
			b.intent = ctx.intentBody
			b.role, b.authority = ctx.independent.role, ctx.independent.body
			b.message = nil
			b.notBefore, b.notAfter = 0, 0
			p.id, p.digest = ctx.intentID, ctx.intentHash
			p.expected = b
			p.expected.message = bytes.Clone(m)
			p.expected.notBefore, p.expected.notAfter = 10, 90
			p.expected.signerIndices = []uint64{0, 2, 4}
			var provider bootstrapProofProvider = p
			independent := keys["REGISTER_TOKEN"]
			raw := qualA38Envelope(m, independent, 0, 2, 4)
			store := c.source.state.accounts.(*qualNativeStore)
			run := func() error {
				return owner.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
					return nil, qualA126Verify(c, op, owner, source, time, provider, b, raw)
				})
			}
			require.NoError(t, run(), "independent literal A126 positive control")
			fields := qualA38Split(m)
			signMessage := true
			accept := false
			switch name {
			case "positive":
				return
			case "wrong_tag", "foreign_domain", "foreign_scope", "foreign_programme", "foreign_issuer", "wrong_intent_id", "wrong_intent_digest", "changed_admission":
				index := map[string]int{"wrong_tag": 0, "foreign_domain": 1, "foreign_scope": 3, "foreign_programme": 4, "foreign_issuer": 5, "wrong_intent_id": 6, "wrong_intent_digest": 7, "changed_admission": 8}[name]
				fields[index][0] ^= 1
			case "cross_purpose":
				fields[2] = []byte("REGISTER_TOKEN")
			case "reordered_sets":
				fields[8] = qualA126Bytes(t, qualA126ReorderedCommitmentHex)
			case "body_hash_mismatch":
				body := qualA38Split(b.intent)
				setBodies := qualA38Split(body[11])
				setBodies[0], setBodies[1] = setBodies[1], setBodies[0]
				body[11] = qualRecordFrame(setBodies...)
				b.intent = qualRecordFrame(body...)
				// Re-sign the changed immutable intent so only the body/hash
				// correspondence is wrong, including the non-PA set.
				ctx.intentBody = b.intent
				ctx.intentHash = qualA38Hash(qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT_PAYLOAD/v1"), ctx.intentBody))
				ctx.intentID = qualA38Hash(qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT/v1"), ctx.network, ctx.issuer, ctx.programme, body[3], ctx.intentHash))
				p.id, p.digest, p.expected.intent = ctx.intentID, ctx.intentHash, b.intent
				p.expected.message = qualA126Message(t, ctx, 10, 90)
				raw = qualA38Envelope(p.expected.message, independent, 0, 2, 4)
				signMessage = false
			case "wrong_role", "wrong_set_id", "wrong_version", "wrong_body_hash", "wrong_projection":
				d := qualA38Split(fields[9])
				d[map[string]int{"wrong_role": 0, "wrong_set_id": 2, "wrong_version": 3, "wrong_body_hash": 4, "wrong_projection": 5}[name]][0] ^= 1
				fields[9] = qualRecordFrame(d...)
			case "no_purpose":
				b.purpose = nil
			case "no_role":
				b.role = nil
			case "no_lineage":
				b.lineage = nil
			case "missing_provider":
				provider = nil
			case "stale":
				p.current = false
			case "stale_successor", "fresh_successor":
				set := &ctx.independent
				body := qualA38Split(set.body)
				body[7], body[8] = set.version, set.bodyHash
				body[2] = ctx.pa.version // existing synthetic successor coordinate
				set.body = qualRecordFrame(body...)
				set.version = body[2]
				set.bodyHash = qualA38Hash(qualRecordFrame([]byte("DRWA/AUTHORITY_SET_VERSION_HASH/candidate1"), set.body))
				b.authority, p.expected.authority = set.body, bytes.Clone(set.body)
				p.expected.message = qualA126Message(t, ctx, 10, 90)
				if name == "fresh_successor" {
					raw = qualA38Envelope(p.expected.message, independent, 0, 2, 4)
					accept = true
				}
				signMessage = false
			case "expired_lease":
				end()
			case "expired_operation":
				var expired *rollbackOperation
				require.NoError(t, owner.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
					expired = op
					return nil, nil
				}))
				require.ErrorIs(t, qualA126Verify(c, expired, owner, source, time, provider, b, raw), ErrExecutionClosed)
				return
			case "wrong_roster":
				raw = qualA38Envelope(m, keys["PROGRAM_ADMINISTRATION"], 0, 2, 4)
				signMessage = false
			case "invalid_extra":
				raw = qualA38Envelope(m, independent, 0, 1, 2, 4)
				raw[len(raw)-1] ^= 1
				signMessage = false
			case "below_threshold", "out_of_order", "duplicate_index":
				indices := map[string][]uint64{"below_threshold": {0, 2}, "out_of_order": {2, 0, 4}, "duplicate_index": {0, 0, 4}}[name]
				raw = qualA38Envelope(m, independent, indices...)
				signMessage = false
			case "not_hashed":
				raw = qualRecordFrame(m, qualRecordFrame(qualA38U64(0), qualA38U64(2), qualA38U64(4)),
					qualRecordFrame(stded.Sign(independent[0], m), stded.Sign(independent[2], m), stded.Sign(independent[4], m)))
				signMessage = false
			case "noncanonical":
				raw = append(raw, 0x18, 0)
				signMessage = false
			case "over_budget":
				raw = bytes.Repeat([]byte{0x0a}, c.bounds.bytes+1)
				signMessage = false
			case "shared_pa_key", "shared_pa_id", "all_members", "below_configured_threshold":
				set := &ctx.independent
				body := qualA38Split(set.body)
				switch name {
				case "shared_pa_key":
					keysInBody := qualA38Split(body[5])
					keysInBody[4] = ctx.pa.members[4]
					body[5] = qualRecordFrame(keysInBody...)
				case "shared_pa_id":
					body[1] = ctx.pa.setID
					set.setID = body[1]
				default:
					body[4] = qualA38U64(uint64(len(set.members)))
				}
				set.body = qualRecordFrame(body...)
				set.bodyHash = qualA38Hash(qualRecordFrame([]byte("DRWA/AUTHORITY_SET_VERSION_HASH/candidate1"), set.body))
				b.authority, p.expected.authority = set.body, bytes.Clone(set.body)
				p.expected.message = qualA126Message(t, ctx, 10, 90)
				indices := []uint64{0, 2, 4}
				if name == "shared_pa_key" {
					// Keep all supplied signatures independently valid while
					// the unsigning member still violates role separation.
					indices = []uint64{0, 1, 2}
				} else if name == "all_members" {
					indices = []uint64{0, 1, 2, 3, 4}
					accept = true
				}
				p.expected.signerIndices = indices
				raw = qualA38Envelope(p.expected.message, independent, indices...)
				signMessage = false
			case "exact_window", "future", "expired", "after_intent", "over_span", "reversed":
				window := map[string][2]uint64{"exact_window": {50, 50}, "future": {51, 90}, "expired": {10, 49},
					"after_intent": {10, 101}, "over_span": {10, 90}, "reversed": {90, 10}}[name]
				fields[10], fields[11] = qualA38U64(window[0]), qualA38U64(window[1])
				p.expected.notBefore, p.expected.notAfter = window[0], window[1]
				p.expected.message = qualRecordFrame(fields...)
				if name == "over_span" {
					c.bounds.maxValidity = 79
				}
				accept = name == "exact_window"
			case "verification_write":
				p.hook = func() { qualRecordPut(t, store, []byte("illegal/bootstrap-provider-write"), []byte{1}) }
			}
			if signMessage {
				raw = qualA38Envelope(qualRecordFrame(fields...), independent, 0, 2, 4)
			}

			before, err := store.RootHash()
			require.NoError(t, err)
			journal, outputs := store.JournalLen(), len(owner.outputs)
			if accept {
				require.NoError(t, run())
			} else {
				// Swallow the decision-level error to exercise the original
				// operation's sticky failure and rollback of an earlier write.
				require.Error(t, owner.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
					require.NoError(t, op.withWrite(owner, store, func() error {
						qualRecordPut(t, store, []byte("original/pending-write"), []byte{1})
						return nil
					}))
					require.Error(t, qualA126Verify(c, op, owner, source, time, provider, b, raw))
					return nil, nil
				}))
			}
			after, err := store.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Equal(t, journal, store.JournalLen())
			require.Len(t, owner.outputs, outputs)
		})
	}
}
