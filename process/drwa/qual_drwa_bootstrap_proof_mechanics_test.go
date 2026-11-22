package drwa

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// All role/message/lineage/appointment meanings here are SYNTHETIC. This is
// deliberately NOT a candidate Step 1 allocation or an accepting native source.
type qualBootstrapProofProvider struct {
	expected        bootstrapProofBinding
	id, digest      []byte
	current         bool
	calls           int
	mutateArguments bool
	hook            func()
}

func (p *qualBootstrapProofProvider) IsInterfaceNil() bool { return p == nil }
func (p *qualBootstrapProofProvider) VerifyBootstrapBinding(b bootstrapProofBinding, id, digest []byte, at HeaderMilliseconds, epoch uint32) error {
	p.calls++
	if !p.current || !reflect.DeepEqual(p.expected, b) || !bytes.Equal(p.id, id) || !bytes.Equal(p.digest, digest) || at != 50 || epoch != 10 {
		return errInvalidRegistrationRecord
	}
	if p.mutateArguments {
		b.role[0] ^= 1
		b.authority[0] ^= 1
		b.intent[0] ^= 1
		b.message[0] ^= 1
		id[0] ^= 1
		digest[0] ^= 1
	}
	if p.hook != nil {
		p.hook()
	}
	return nil
}

func qualVerifyBootstrapMechanics(c *registrationApprovalCodec, operation *rollbackOperation, boundary *RollbackContainment, source HeaderTimeSource, context *HeaderTimeContext, provider bootstrapProofProvider, binding bootstrapProofBinding, raw []byte) error {
	verifier, exists := any(c).(interface {
		verifyBootstrapProof(*rollbackOperation, *RollbackContainment, HeaderTimeSource, *HeaderTimeContext, bootstrapProofProvider, bootstrapProofBinding, []byte) error
	})
	if !exists {
		return errInvalidRegistrationRecord
	}
	return verifier.verifyBootstrapProof(operation, boundary, source, context, provider, binding, raw)
}

func qualBootstrapMechanicsFixture(t *testing.T) (*registrationApprovalCodec, *RollbackContainment, *hooks.BlockChainHookImpl, *HeaderTimeContext, *qualBootstrapProofProvider, bootstrapProofBinding, []byte, func()) {
	t.Helper()
	store, records, _, _ := qualRecordStore(t)
	c, err := newRegistrationApprovalCodec(records, registrationApprovalBounds{4096, 2048, 64, 64, 8, 100})
	require.NoError(t, err)
	boundary, err := NewRollbackContainment(store)
	require.NoError(t, err)
	hook, _ := qualT42Hook(t, store, core.MetachainShardId, true)
	context, end := qualT42Install(t, hook, core.MetachainShardId, 50)
	t.Cleanup(end)
	_, ctx, keys := qualR3Fixture(t, 100)
	b := bootstrapProofBinding{purpose: []byte("SYNTHETIC_ONLY_BOOTSTRAP_PURPOSE"), role: bytes.Clone(ctx.admission.role), owner: bytes.Clone(ctx.scopeOwner), intent: bytes.Clone(ctx.intentBody), authority: bytes.Clone(ctx.admission.body), lineage: []byte("SYNTHETIC_ONLY_CURRENT_LINEAGE"), notBefore: 10, notAfter: 90}
	// Fixture field order only: independently framed and hashed BEFORE the
	// mechanics. No production method defines these fields as a Step 1 format.
	fields := qualA38Split(ctx.intentBody)
	b.message = qualRecordFrame([]byte("SYNTHETIC_ONLY_MESSAGE"), b.purpose, b.role, ctx.network, b.owner, ctx.programme, ctx.issuer, ctx.intentID, ctx.intentHash, fields[10], fields[12], qualA38U64(10), qualA38U64(90))
	expected := bootstrapProofBinding{purpose: bytes.Clone(b.purpose), role: bytes.Clone(b.role), owner: bytes.Clone(b.owner),
		intent: bytes.Clone(b.intent), authority: bytes.Clone(b.authority), lineage: bytes.Clone(b.lineage),
		message: bytes.Clone(b.message), notBefore: b.notBefore, notAfter: b.notAfter}
	provider := &qualBootstrapProofProvider{expected: expected, id: bytes.Clone(ctx.intentID), digest: bytes.Clone(ctx.intentHash), current: true}
	raw := qualA38Envelope(b.message, keys["REGISTER_TOKEN_ADMISSION"], 0, 2, 4)
	return c, boundary, hook, context, provider, b, raw, end
}

func TestQualBootstrapProofMechanicsSyntheticBinding(t *testing.T) {
	c, boundary, source, context, provider, binding, raw, _ := qualBootstrapMechanicsFixture(t)
	require.NoError(t, boundary.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
		return nil, qualVerifyBootstrapMechanics(c, op, boundary, source, context, provider, binding, raw)
	}), "explicit synthetic role/provider binding must verify without any production role default")
	require.Positive(t, provider.calls)
	require.Empty(t, boundary.outputs)
}

func TestQualBootstrapProofMechanicsBindings(t *testing.T) {
	// These thirteen positions are ONLY the synthetic fixture's message. The
	// production verifier compares an opaque trusted preimage, not this grammar.
	names := []string{"tag", "purpose", "role", "domain", "scope", "programme", "issuer", "intent_id", "intent_hash", "admission", "proposed_sets", "not_before", "not_after"}
	for i, name := range names {
		t.Run(name, func(t *testing.T) {
			c, boundary, source, context, provider, b, raw, _ := qualBootstrapMechanicsFixture(t)
			_, _, keys := qualR3Fixture(t, 100)
			fields := qualA38Split(b.message)
			fields[i] = bytes.Clone(fields[i])
			fields[i][0] ^= 1
			raw = qualA38Envelope(qualRecordFrame(fields...), keys["REGISTER_TOKEN_ADMISSION"], 0, 2, 4)
			qualBootstrapMechanicsDenial(t, c, boundary, source, context, provider, b, raw)
		})
	}
}

func qualBootstrapMechanicsDenial(t *testing.T, c *registrationApprovalCodec, boundary *RollbackContainment, source HeaderTimeSource, context *HeaderTimeContext, provider bootstrapProofProvider, b bootstrapProofBinding, raw []byte) {
	t.Helper()
	store := c.source.state.accounts
	before, err := store.RootHash()
	require.NoError(t, err)
	journal, outputs := store.JournalLen(), len(boundary.outputs)
	err = boundary.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
		return nil, qualVerifyBootstrapMechanics(c, op, boundary, source, context, provider, b, raw)
	})
	require.Error(t, err)
	after, e := store.RootHash()
	require.NoError(t, e)
	require.Equal(t, before, after)
	require.Equal(t, journal, store.JournalLen())
	require.Len(t, boundary.outputs, outputs)
}

func TestQualBootstrapProofMechanicsHostileEnvelope(t *testing.T) {
	for _, fault := range []string{"empty", "truncated", "unknown_tag", "nonshort_length", "extra_envelope", "message_noncanonical", "over_budget", "index_width", "duplicate", "out_of_order", "out_of_range", "threshold", "invalid_signature", "signature_width", "invalid_extra", "extra_signature", "other_roster"} {
		t.Run(fault, func(t *testing.T) {
			c, boundary, source, context, provider, b, raw, _ := qualBootstrapMechanicsFixture(t)
			_, _, keys := qualR3Fixture(t, 100)
			switch fault {
			case "empty":
				raw = nil
			case "truncated":
				raw = raw[:len(raw)-1]
			case "unknown_tag":
				raw = append(raw, 0x18, 0)
			case "nonshort_length":
				raw = append([]byte{0x0a, raw[1] | 0x80, raw[2] | 0x80, 0}, raw[3:]...)
			case "extra_envelope":
				raw = qualRecordFrame(append(qualA38Split(raw), nil)...)
			case "message_noncanonical":
				b.message = append([]byte{0x0a, 0x80, 0}, b.message...)
				provider.expected.message = bytes.Clone(b.message)
				raw = qualA38Envelope(b.message, keys["REGISTER_TOKEN_ADMISSION"], 0, 2, 4)
			case "over_budget":
				raw = bytes.Repeat([]byte{0x0a}, c.bounds.bytes+1)
			case "index_width":
				e := qualA38Split(raw)
				e[1] = qualRecordFrame([]byte{0}, qualA38U64(2), qualA38U64(4))
				raw = qualRecordFrame(e...)
			case "duplicate":
				raw = qualA38Envelope(b.message, keys["REGISTER_TOKEN_ADMISSION"], 0, 0, 4)
			case "out_of_order":
				raw = qualA38Envelope(b.message, keys["REGISTER_TOKEN_ADMISSION"], 2, 0, 4)
			case "out_of_range":
				e := qualA38Split(raw)
				e[1] = qualRecordFrame(qualA38U64(0), qualA38U64(2), qualA38U64(5))
				raw = qualRecordFrame(e...)
			case "threshold":
				raw = qualA38Envelope(b.message, keys["REGISTER_TOKEN_ADMISSION"], 0, 2)
			case "signature_width":
				e := qualA38Split(raw)
				signatures := qualA38Split(e[2])
				signatures[2] = signatures[2][:63]
				e[2] = qualRecordFrame(signatures...)
				raw = qualRecordFrame(e...)
			case "invalid_signature":
				raw[len(raw)-1] ^= 1
			case "invalid_extra":
				raw = qualA38Envelope(b.message, keys["REGISTER_TOKEN_ADMISSION"], 0, 1, 2, 4)
				raw[len(raw)-1] ^= 1
			case "extra_signature":
				e := qualA38Split(raw)
				e[2] = qualRecordFrame(append(qualA38Split(e[2]), bytes.Repeat([]byte{1}, 64))...)
				raw = qualRecordFrame(e...)
			case "other_roster":
				raw = qualA38Envelope(b.message, keys["REGISTER_TOKEN"], 0, 2, 4)
			}
			qualBootstrapMechanicsDenial(t, c, boundary, source, context, provider, b, raw)
		})
	}
}

func TestQualBootstrapProofMechanicsMissingCurrentInputs(t *testing.T) {
	for _, fault := range []string{"purpose", "role", "lineage", "provider", "typed_nil_provider", "authority", "intent", "message", "currentness", "expired", "future", "reversed", "overflow", "intent_expiry", "over_span", "nil_context", "ended_context", "wrong_role", "foreign_scope", "changed_intent_admission", "changed_intent_sets", "over_budget_expected", "oversize_role", "provider_write", "missing_profile_bound"} {
		t.Run(fault, func(t *testing.T) {
			c, boundary, source, context, p, b, raw, end := qualBootstrapMechanicsFixture(t)
			var provider bootstrapProofProvider = p
			switch fault {
			case "purpose":
				b.purpose = nil
			case "role":
				b.role = nil
			case "lineage":
				b.lineage = nil
			case "provider":
				provider = nil
			case "typed_nil_provider":
				var absent *qualBootstrapProofProvider
				provider = absent
			case "authority":
				b.authority = nil
			case "intent":
				b.intent = nil
			case "message":
				b.message = nil
			case "currentness":
				p.current = false
			case "expired":
				b.notAfter = 49
			case "future":
				b.notBefore = 51
			case "reversed":
				b.notBefore, b.notAfter = 90, 10
			case "overflow":
				b.notBefore, b.notAfter = ^uint64(0), 0
			case "intent_expiry":
				b.notAfter = 101
			case "over_span":
				c.bounds.maxValidity = 79
			case "nil_context":
				context = nil
			case "ended_context":
				end()
			case "wrong_role":
				b.role = []byte("SYNTHETIC_OTHER_ROLE")
			case "foreign_scope":
				b.owner = bytes.Repeat([]byte{7}, 32)
			case "changed_intent_admission":
				f := qualA38Split(b.intent)
				f[10] = []byte("different admission")
				b.intent = qualRecordFrame(f...)
			case "changed_intent_sets":
				f := qualA38Split(b.intent)
				sets := qualA38Split(f[12])
				sets[0][0] ^= 1
				f[12] = qualRecordFrame(sets...)
				b.intent = qualRecordFrame(f...)
			case "over_budget_expected":
				b.message = bytes.Repeat([]byte{0x0a}, c.bounds.bytes+1)
			case "oversize_role":
				b.role = bytes.Repeat([]byte{'r'}, c.bounds.roleBytes+1)
			case "provider_write":
				p.hook = func() {
					qualRecordPut(t, c.source.state.accounts.(*qualNativeStore), []byte("illegal/bootstrap-provider-write"), []byte{1})
				}
			case "missing_profile_bound":
				c.bounds.maxValidity = 0
			}
			qualBootstrapMechanicsDenial(t, c, boundary, source, context, provider, b, raw)
		})
	}
}

func TestQualBootstrapProofMechanicsOriginalOwnerAndAliases(t *testing.T) {
	c, boundary, source, context, p, b, raw, _ := qualBootstrapMechanicsFixture(t)
	p.mutateArguments = true
	expected := p.expected
	var expired *rollbackOperation
	require.NoError(t, boundary.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
		expired = op
		return nil, qualVerifyBootstrapMechanics(c, op, boundary, source, context, p, b, raw)
	}))
	require.Equal(t, expected, b)
	require.Error(t, qualVerifyBootstrapMechanics(c, expired, boundary, source, context, p, b, raw))
	p.mutateArguments = false
	before, err := c.source.state.accounts.RootHash()
	require.NoError(t, err)
	// A swallowed denial still stops the original operation and rolls back its
	// earlier write; the mechanics never open a second journal or publish output.
	err = boundary.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
		require.NoError(t, op.withWrite(boundary, c.source.state.accounts, func() error {
			qualRecordPut(t, c.source.state.accounts.(*qualNativeStore), []byte("original/pending-write"), []byte{1})
			return nil
		}))
		p.current = false
		require.Error(t, qualVerifyBootstrapMechanics(c, op, boundary, source, context, p, b, raw))
		return nil, nil
	})
	require.Error(t, err)
	after, e := c.source.state.accounts.RootHash()
	require.NoError(t, e)
	require.Equal(t, before, after)
	require.Empty(t, boundary.outputs)
}

func TestQualBootstrapProofMechanicsAllOwnedStoresReadOnly(t *testing.T) {
	c, _, source, context, p, b, raw, _ := qualBootstrapMechanicsFixture(t)
	primary := c.source.state.accounts.(*qualNativeStore)
	other := qualRegistrationStore(t, 0)
	boundary, err := NewRollbackContainment(primary, other)
	require.NoError(t, err)
	before, e := other.RootHash()
	require.NoError(t, e)
	journal := other.JournalLen()
	p.hook = func() { qualRecordPut(t, other, []byte("other/forbidden-verification-write"), []byte{1}) }
	qualBootstrapMechanicsDenial(t, c, boundary, source, context, p, b, raw)
	after, e := other.RootHash()
	require.NoError(t, e)
	require.Equal(t, before, after)
	require.Equal(t, journal, other.JournalLen())
}

func TestQualBootstrapProofMechanicsValidityBoundaries(t *testing.T) {
	for _, window := range [][2]uint64{{50, 90}, {10, 50}, {50, 50}, {0, 100}} {
		t.Run(fmt.Sprintf("%d_%d", window[0], window[1]), func(t *testing.T) {
			c, boundary, source, context, p, b, _, _ := qualBootstrapMechanicsFixture(t)
			_, _, keys := qualR3Fixture(t, 100)
			b.notBefore, b.notAfter = window[0], window[1]
			fields := qualA38Split(b.message)
			fields[11], fields[12] = qualA38U64(window[0]), qualA38U64(window[1])
			b.message = qualRecordFrame(fields...)
			p.expected.notBefore, p.expected.notAfter = window[0], window[1]
			p.expected.message = bytes.Clone(b.message)
			raw := qualA38Envelope(b.message, keys["REGISTER_TOKEN_ADMISSION"], 0, 2, 4)
			require.NoError(t, boundary.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
				return nil, qualVerifyBootstrapMechanics(c, op, boundary, source, context, p, b, raw)
			}))
		})
	}
}
