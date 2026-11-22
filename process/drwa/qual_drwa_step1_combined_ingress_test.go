package drwa

import (
	"bytes"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type qualStep1BundleProvider struct {
	*qualStep1R2Provider
	independent qualBootstrapProofProvider
}

func (p *qualStep1BundleProvider) IsInterfaceNil() bool { return p == nil }

func (p *qualStep1BundleProvider) VerifyBootstrapBinding(b bootstrapProofBinding, id, digest []byte, at HeaderMilliseconds, epoch uint32) error {
	if string(b.purpose) == "BOOTSTRAP_INTENT" {
		return p.independent.VerifyBootstrapBinding(b, id, digest, at, epoch)
	}
	return p.qualStep1R2Provider.VerifyBootstrapBinding(b, id, digest, at, epoch)
}

func qualStep1Bundle(c *registrationApprovalCodec, op *rollbackOperation, records *scopedAdmissionRecords,
	ctx *HeaderTimeContext, provider bootstrapProofProvider, in bootstrapAdmissionProofInput, role, lineage []byte, args [][]byte) error {
	v, ok := any(c).(interface {
		verifyBootstrapIntentArguments(*rollbackOperation, *scopedAdmissionRecords, *HeaderTimeContext, bootstrapProofProvider, bootstrapAdmissionProofInput, []byte, []byte, [][]byte) error
	})
	if !ok {
		return errInvalidRegistrationRecord
	}
	return v.verifyBootstrapIntentArguments(op, records, ctx, provider, in, role, lineage, args)
}

// These synthetic purpose heads use the existing native P record layout and
// independently framed VERSION preimage. They supply no lawful appointment.
func qualStep1PutPurposeHead(t *testing.T, f *qualScopedFixture, purpose string, predecessor, body []byte) ([]byte, []byte) {
	t.Helper()
	key := f.records.key("current", qualScopedHash("SCOPE", f.scope, []byte(purpose)))
	outer := qualScopedHash("VERSION", f.scope, predecessor, body)
	qualRecordPut(t, f.store, f.records.key("version", outer), qualRecordFrame(f.scope, predecessor, body))
	qualRecordPut(t, f.store, key, qualRecordFrame(f.scope, outer))
	return key, outer
}

func TestQualDRWAStep1CombinedProofBundle(t *testing.T) {
	for _, name := range []string{"exact", "different_windows", "empty_body", "missing_arg", "extra_arg", "empty_slot", "missing_slot", "extra_slot",
		"swap", "duplicate", "wrong_purpose", "unknown_field", "nonminimal_length", "unsigned_material", "large_inner",
		"aggregate_overhead", "wrong_roster", "different_intent", "no_lineage", "stale_independent", "authority_writes", "wrong_outer",
		"missing_independent_head", "only_shared_independent_head", "foreign_independent_head", "missing_independent_version", "rotated_independent_head"} {
		t.Run(name, func(t *testing.T) {
			f := qualScopedNew(t)
			reuse, ctx, keys := qualR3Fixture(t, 200)
			codec, err := newRegistrationApprovalCodec(f.records.codec, reuse.bounds)
			require.NoError(t, err)
			time, err := f.clock.Begin(&block.MetaBlockV3{Epoch: 10, TimestampMs: 50})
			require.NoError(t, err)

			outer := qualScopedHash("VERSION", f.scope, nil, ctx.admission.body)
			f.d.authority = outer
			decision := f.body()
			fields := qualA38Split(ctx.intentBody)
			fields[0], fields[1], fields[10] = f.records.domain, f.d.issuer, decision
			ctx.network, ctx.issuer = fields[0], fields[1]
			ctx.intentBody = qualRecordFrame(fields...)
			ctx.intentHash = qualA38Hash(qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT_PAYLOAD/v1"), ctx.intentBody))
			ctx.intentID = qualA38Hash(qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT/v1"), ctx.network, ctx.issuer, ctx.programme, fields[3], ctx.intentHash))
			headKey := f.records.key("current", qualScopedHash("SCOPE", f.scope, []byte("REGISTER_TOKEN_ADMISSION")))
			qualRecordPut(t, f.store, headKey, qualRecordFrame(f.scope, outer))
			qualRecordPut(t, f.store, f.records.key("version", outer), qualRecordFrame(f.scope, nil, ctx.admission.body))
			qualRecordPut(t, f.store, f.records.key("decision", f.id()), decision)
			independentHead, independentRef := qualStep1PutPurposeHead(t, f, "REGISTER_TOKEN", nil, ctx.independent.body)
			in := bootstrapAdmissionProofInput{owner: f.d.owner,
				admissionRole: ctx.admission.role, independentAuthority: ctx.independent.body}
			role, lineage := ctx.independent.role, []byte("synthetic admitted appointment lineage")
			a, pa := qualA126Bytes(t, qualStep1AdmissionM), qualA126Bytes(t, qualStep1PAM)
			nb, na := uint64(10), uint64(90)
			if name == "different_windows" {
				nb, na = 30, 71
			}
			ia := qualA126Message(t, ctx, nb, na)
			expect := func(purpose string, set registrationApprovalAuthority, line, message []byte, first, last uint64) qualBootstrapProofProvider {
				return qualBootstrapProofProvider{current: true, id: ctx.intentID, digest: ctx.intentHash, expected: bootstrapProofBinding{
					purpose: []byte(purpose), role: set.role, owner: f.d.owner, intent: ctx.intentBody, authority: set.body,
					lineage: line, message: message, notBefore: first, notAfter: last, signerIndices: []uint64{0, 2, 4},
				}}
			}
			p := &qualStep1BundleProvider{
				qualStep1R2Provider: &qualStep1R2Provider{
					admission: expect("BOOTSTRAP_INTENT_ADMISSION", ctx.admission, outer, a, 10, 90),
					pa:        expect("BOOTSTRAP_INTENT_PA_POSSESSION", ctx.pa, nil, pa, 10, 90),
				},
				independent: expect("BOOTSTRAP_INTENT", ctx.independent, lineage, ia, nb, na),
			}
			good := [][]byte{qualA38Envelope(a, keys["REGISTER_TOKEN_ADMISSION"], 0, 2, 4),
				qualA38Envelope(pa, keys["PROGRAM_ADMINISTRATION"], 0, 2, 4),
				qualA38Envelope(ia, keys["REGISTER_TOKEN"], 0, 2, 4)}
			bundle := qualRecordFrame(good...)
			args := [][]byte{ctx.intentBody, bundle}
			run := func() error {
				return f.boundary.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
					return nil, qualStep1Bundle(codec, op, f.records, time, p, in, role, lineage, args)
				})
			}
			require.NoError(t, run(), "independently framed and signed bundle under one owner")
			require.Equal(t, 1, p.admission.calls)
			require.Equal(t, 1, p.pa.calls)
			require.Equal(t, 1, p.independent.calls)
			if name == "exact" || name == "different_windows" {
				return
			}
			switch name {
			case "empty_body":
				args[0] = nil
			case "missing_arg":
				args = args[:1]
			case "extra_arg":
				args = append(args, []byte{1})
			case "empty_slot":
				args[1] = qualRecordFrame(good[0], nil, good[2])
			case "missing_slot":
				args[1] = qualRecordFrame(good[0], good[2])
			case "extra_slot":
				args[1] = qualRecordFrame(good[0], good[1], good[2], good[2])
			case "swap":
				args[1] = qualRecordFrame(good[1], good[0], good[2])
			case "duplicate":
				args[1] = qualRecordFrame(good[0], good[0], good[2])
			case "wrong_purpose":
				m := qualA38Split(ia)
				m[2] = []byte("BOOTSTRAP_INTENT_ADMISSION")
				args[1] = qualRecordFrame(good[0], good[1], qualA38Envelope(qualRecordFrame(m...), keys["REGISTER_TOKEN"], 0, 2, 4))
			case "unknown_field":
				args[1] = append(bytes.Clone(bundle), 0x10, 0)
			case "nonminimal_length":
				args[1] = append(append(bytes.Clone(bundle[:2]), bundle[2]|0x80, 0), bundle[3:]...)
			case "unsigned_material":
				args[1] = qualRecordFrame(good[0], good[1], append(bytes.Clone(good[2]), 0x10, 0))
			case "large_inner":
				args[1] = qualRecordFrame(good[0], good[1], make([]byte, codec.bounds.bytes+1))
			case "aggregate_overhead":
				f.records.codec.maxBytes = len(good[0]) + len(good[1]) + len(good[2])
				require.Greater(t, len(args[1]), f.records.codec.maxBytes)
			case "wrong_roster":
				args[1] = qualRecordFrame(good[0], good[1], qualA38Envelope(ia, keys["PROGRAM_ADMINISTRATION"], 0, 2, 4))
			case "different_intent":
				m := qualA38Split(ia)
				m[7][0] ^= 1
				args[1] = qualRecordFrame(good[0], good[1], qualA38Envelope(qualRecordFrame(m...), keys["REGISTER_TOKEN"], 0, 2, 4))
			case "no_lineage":
				lineage = nil
			case "stale_independent":
				p.independent.current = false
			case "authority_writes":
				p.independent.hook = func() { qualRecordPut(t, f.store, []byte("unrelated"), []byte("forbidden verification write")) }
			case "wrong_outer":
				intent := qualA38Split(bytes.Clone(args[0]))
				embedded := qualA38Split(intent[10])
				embedded[4] = ctx.admission.bodyHash // Inner hash cannot replace outer VERSION.
				intent[10] = qualRecordFrame(embedded...)
				args[0] = qualRecordFrame(intent...)
			case "missing_independent_head":
				qualRecordPut(t, f.store, independentHead, nil)
			case "only_shared_independent_head":
				qualRecordPut(t, f.store, independentHead, nil)
				shared := f.records.key("current", qualScopedHash("SCOPE", f.scope))
				qualRecordPut(t, f.store, shared, qualRecordFrame(f.scope, independentRef))
			case "foreign_independent_head":
				foreign := qualRecordFrame(f.records.domain, bytes.Repeat([]byte{0x9f}, len(f.d.owner)), f.d.program)
				qualRecordPut(t, f.store, independentHead, qualRecordFrame(foreign, independentRef))
			case "missing_independent_version":
				qualRecordPut(t, f.store, f.records.key("version", independentRef), nil)
			case "rotated_independent_head":
				next := qualA38Split(ctx.independent.body)
				next[2], next[7], next[8] = qualA38U64(1), ctx.independent.version, ctx.independent.bodyHash
				qualStep1PutPurposeHead(t, f, "REGISTER_TOKEN", independentRef, qualRecordFrame(next...))
			}
			before, err := f.store.RootHash()
			require.NoError(t, err)
			journal := f.store.JournalLen()
			require.Error(t, run())
			after, err := f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Equal(t, journal, f.store.JournalLen())
		})
	}
}

func TestQualDRWAStep1RetainsWithOriginalOperation(t *testing.T) {
	for _, late := range []bool{false, true} {
		f, _, _ := admissionDependencyOperation(t, false)
		proof := []byte("explicit-step1-mandate")
		ctx, err := f.admit.source.EvaluatedHeaderTimeContext()
		require.NoError(t, err)
		key := string(append([]byte(registrationIntentPrefix), f.owner.id...))
		before, err := f.store.RootHash()
		require.NoError(t, err)
		journal, outputs := f.store.JournalLen(), len(f.boundary.outputs)
		failure := ErrInvalidOperation
		run := func(op *rollbackOperation) error {
			if a, ok := any(f.admit).(interface {
				retainBootstrapIntentOwned(*rollbackOperation, *HeaderTimeContext, []byte, []byte) error
			}); ok {
				return a.retainBootstrapIntentOwned(op, ctx, f.verify.body, proof)
			}
			return f.admit.RetainBootstrapIntent(f.verify.body, proof)
		}
		err = f.boundary.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
			if e := run(op); e != nil {
				return nil, e
			}
			require.Equal(t, qualRecordFrame(f.verify.body, []byte("OPEN"), nil), qualRegistryValue(t, f.store, key))
			once := f.store.JournalLen()
			require.NoError(t, run(op))
			require.Equal(t, once, f.store.JournalLen())
			if late {
				return nil, failure
			}
			return nil, nil
		})
		if late {
			require.ErrorIs(t, err, failure)
			after, err := f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Equal(t, journal, f.store.JournalLen())
			require.Empty(t, qualRegistryValue(t, f.store, key))
		} else {
			require.NoError(t, err, "Step 1 retention must borrow the existing rollback operation")
		}
		require.Len(t, f.boundary.outputs, outputs)
	}
}
