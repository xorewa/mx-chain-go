package drwa

import (
	"bytes"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Independently frozen from the adopted R2 frames, the existing A38/B9
// fixtures and Python BLAKE2b-256. These are fixture bytes only.
const qualStep1AdmissionM = "0a36445257412f424f4f5453545241505f494e54454e545f41444d495353494f4e5f43455254494649434154452f63616e646964617465310a0e666978747572652d646f6d61696e0a1a424f4f5453545241505f494e54454e545f41444d495353494f4e0a2001010101010101010101010101010101010101010101010101010101010101010a0770726f6772616d0a2002020202020202020202020202020202020202020202020202020202020202020a2066e07fde0162d66628211c34f008458a34d82f998733c19ee1029b1ba2506b750a205b2655096425aecd8267a4b35fb673d12241bba75227e0b800355aacc7c5771f0a200ba3d412fca22c79827b4656b702b06e3becc14c8ecfdf7d7f431494d6ead4970abf010a1061646d697373696f6e006f70617175650a3b0a0e666978747572652d646f6d61696e0a2001010101010101010101010101010101010101010101010101010101010101010a0770726f6772616d0a2041414141414141414141414141414141414141414141414141414141414141410a0800000000000000000a20b5754ab9a4f27599a70b544c66da6dc8dfe06b7c68ee97c4121ec8c94abb3f470a20c26820415811f0b31450f92919a1685c266ba410ad23ddbfbd64b2907fad6b460a08000000000000000a0a08000000000000005a"
const qualStep1AdmissionH = "f936940d2ea365f8f3eec9601ddc3ae2a54c51e26c12bc0102bbddb0db0b0cb4"
const qualStep1PAM = "0a2e445257412f424f4f5453545241505f494e54454e545f50415f504f5353455353494f4e2f63616e646964617465310a0e666978747572652d646f6d61696e0a1e424f4f5453545241505f494e54454e545f50415f504f5353455353494f4e0a2001010101010101010101010101010101010101010101010101010101010101010a0770726f6772616d0a2002020202020202020202020202020202020202020202020202020202020202020a2066e07fde0162d66628211c34f008458a34d82f998733c19ee1029b1ba2506b750a205b2655096425aecd8267a4b35fb673d12241bba75227e0b800355aacc7c5771f0a200ba3d412fca22c79827b4656b702b06e3becc14c8ecfdf7d7f431494d6ead4970acf010a2050726f6772616d2041646d696e697374726174696f6e20417574686f726974790a3b0a0e666978747572652d646f6d61696e0a2001010101010101010101010101010101010101010101010101010101010101010a0770726f6772616d0a2043434343434343434343434343434343434343434343434343434343434343430a0800000000000000020a20bb7781ae5698dfa9a1cc4603d4a19c875355536e6853d7373bbafbe69143e0eb0a205b2655096425aecd8267a4b35fb673d12241bba75227e0b800355aacc7c5771f0a08000000000000000a0a08000000000000005a"
const qualStep1PAH = "4b020c5db6b018354d9a7dbd64dc6c557387722a62239bc315039885e67d0110"
const qualStep1ReorderedC = "06709a4647cb147460c73b854de3a3e26709f3a82ee7b197fb614bdbf17a0a8e"

type qualStep1R2Provider struct {
	admission, pa qualBootstrapProofProvider
}

func (p *qualStep1R2Provider) IsInterfaceNil() bool { return p == nil }
func (p *qualStep1R2Provider) VerifyBootstrapBinding(b bootstrapProofBinding, id, digest []byte, at HeaderMilliseconds, epoch uint32) error {
	switch string(b.purpose) {
	case "BOOTSTRAP_INTENT_ADMISSION":
		return p.admission.VerifyBootstrapBinding(b, id, digest, at, epoch)
	case "BOOTSTRAP_INTENT_PA_POSSESSION":
		return p.pa.VerifyBootstrapBinding(b, id, digest, at, epoch)
	default:
		return errInvalidRegistrationRecord
	}
}

func qualStep1R2Verify(c *registrationApprovalCodec, op *rollbackOperation, records *scopedAdmissionRecords,
	context *HeaderTimeContext, provider bootstrapProofProvider, in bootstrapAdmissionProofInput, admission, pa []byte) error {
	v, exists := any(c).(interface {
		verifyBootstrapAdmissionPA(*rollbackOperation, *scopedAdmissionRecords, *HeaderTimeContext, bootstrapProofProvider, bootstrapAdmissionProofInput, []byte, []byte) error
	})
	if !exists {
		return errInvalidRegistrationRecord
	}
	return v.verifyBootstrapAdmissionPA(op, records, context, provider, in, admission, pa)
}

func TestQualDRWAStep1R2PrivateProofs(t *testing.T) {
	for _, name := range []string{"exact", "no_bridge", "changed_admission", "no_provider", "swapped_envelopes", "admission_signed_by_pa", "pa_signed_by_independent",
		"other_tag", "wrong_projection", "reordered_sets", "wrong_pa_set", "bad_extra", "threshold", "duplicate", "out_of_order",
		"noncanonical", "over_budget", "head_missing_with_shared_pointer", "wrong_outer_reference", "wrong_head_body", "shared_independent_roster", "rotated", "withdrawn",
		"expired_decision", "expired_envelope", "expired_header", "expired_operation", "foreign_operation", "provider_writes"} {
		t.Run(name, func(t *testing.T) {
			f := qualScopedNew(t)
			reuse, ctx, keys := qualR3Fixture(t, 200)
			c, err := newRegistrationApprovalCodec(f.records.codec, reuse.bounds)
			require.NoError(t, err)
			f.context, err = f.clock.Begin(&block.MetaBlockV3{Epoch: 10, TimestampMs: 50})
			require.NoError(t, err)

			outer := qualScopedHash("VERSION", f.scope, nil, ctx.admission.body)
			require.Equal(t, qualA126Bytes(t, "f849cdbde511347acbb3a4e3024af66acec86a99eae1c20129a7ba88e57e39d4"), outer)
			f.d.authority = outer
			decision := f.body()
			fields := qualA38Split(ctx.intentBody)
			fields[0], fields[1], fields[10] = f.records.domain, f.d.issuer, decision
			intent := qualRecordFrame(fields...)
			digest := qualA38Hash(qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT_PAYLOAD/v1"), intent))
			id := qualA38Hash(qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT/v1"), fields[0], fields[1], fields[2], fields[3], digest))
			require.Equal(t, qualA126Bytes(t, "5b2655096425aecd8267a4b35fb673d12241bba75227e0b800355aacc7c5771f"), digest)
			require.Equal(t, qualA126Bytes(t, "66e07fde0162d66628211c34f008458a34d82f998733c19ee1029b1ba2506b75"), id)
			headKey := f.records.key("current", qualScopedHash("SCOPE", f.scope, []byte("REGISTER_TOKEN_ADMISSION")))
			qualRecordPut(t, f.store, headKey, qualRecordFrame(f.scope, outer))
			qualRecordPut(t, f.store, f.records.key("version", outer), qualRecordFrame(f.scope, nil, ctx.admission.body))
			qualRecordPut(t, f.store, f.records.key("decision", f.id()), decision)

			in := bootstrapAdmissionProofInput{owner: f.d.owner, intent: intent,
				admissionRole: ctx.admission.role, independentAuthority: ctx.independent.body}
			a, pa := qualA126Bytes(t, qualStep1AdmissionM), qualA126Bytes(t, qualStep1PAM)
			require.Equal(t, qualA126Bytes(t, qualStep1AdmissionH), qualA38Hash(a))
			require.Equal(t, qualA126Bytes(t, qualStep1PAH), qualA38Hash(pa))
			expected := func(purpose string, authority registrationApprovalAuthority, line, m []byte) qualBootstrapProofProvider {
				return qualBootstrapProofProvider{current: true, id: id, digest: digest, expected: bootstrapProofBinding{
					purpose: []byte(purpose), role: authority.role, owner: f.d.owner, intent: intent,
					authority: authority.body, lineage: line, message: m, notBefore: 10, notAfter: 90, signerIndices: []uint64{0, 2, 4},
				}}
			}
			p := &qualStep1R2Provider{
				admission: expected("BOOTSTRAP_INTENT_ADMISSION", ctx.admission, outer, a),
				pa:        expected("BOOTSTRAP_INTENT_PA_POSSESSION", ctx.pa, nil, pa),
			}
			var provider bootstrapProofProvider = p
			aKeys, paKeys := keys["REGISTER_TOKEN_ADMISSION"], keys["PROGRAM_ADMINISTRATION"]
			goodA, goodPA := qualA38Envelope(a, aKeys, 0, 2, 4), qualA38Envelope(pa, paKeys, 0, 2, 4)
			admissionProof, paProof := goodA, goodPA
			run := func(owner *RollbackContainment) error {
				return owner.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
					return nil, qualStep1R2Verify(c, op, f.records, f.context, provider, in, admissionProof, paProof)
				})
			}
			require.NoError(t, run(f.boundary), "independent R2 positive control")
			require.Equal(t, 1, p.admission.calls)
			require.Equal(t, 1, p.pa.calls)

			switch name {
			case "exact":
				return
			case "no_bridge":
				in.owner = nil
			case "changed_admission":
				fields := qualA38Split(bytes.Clone(in.intent))
				fields[10][len(fields[10])-1] ^= 1
				in.intent = qualRecordFrame(fields...)
			case "no_provider":
				provider = nil
			case "swapped_envelopes":
				admissionProof, paProof = paProof, admissionProof
			case "admission_signed_by_pa":
				admissionProof = qualA38Envelope(a, paKeys, 0, 2, 4)
			case "pa_signed_by_independent":
				paProof = qualA38Envelope(pa, keys["REGISTER_TOKEN"], 0, 2, 4)
			case "other_tag", "wrong_projection", "reordered_sets", "wrong_pa_set":
				frame := qualA38Split(a)
				roster := aKeys
				if name == "wrong_pa_set" {
					frame, roster = qualA38Split(pa), paKeys
					dep := qualA38Split(frame[9])
					dep[2][0] ^= 1
					frame[9] = qualRecordFrame(dep...)
				} else if name == "wrong_projection" {
					dep := qualA38Split(frame[9])
					dep[5][0] ^= 1
					frame[9] = qualRecordFrame(dep...)
				} else if name == "reordered_sets" {
					frame[8] = qualA126Bytes(t, qualStep1ReorderedC)
				} else {
					frame[0][0] ^= 1
				}
				mutated := qualA38Envelope(qualRecordFrame(frame...), roster, 0, 2, 4)
				if name == "wrong_pa_set" {
					paProof = mutated
				} else {
					admissionProof = mutated
				}
			case "bad_extra":
				env := qualA38Split(qualA38Envelope(pa, paKeys, 0, 1, 2, 4))
				sigs := qualA38Split(env[2])
				sigs[3][0] ^= 1
				env[2] = qualRecordFrame(sigs...)
				paProof = qualRecordFrame(env...)
			case "threshold":
				paProof = qualA38Envelope(pa, paKeys, 0, 2)
			case "duplicate":
				paProof = qualA38Envelope(pa, paKeys, 0, 0, 4)
			case "out_of_order":
				paProof = qualA38Envelope(pa, paKeys, 2, 0, 4)
			case "noncanonical":
				paProof = append(bytes.Clone(paProof), 0x10, 0)
			case "over_budget":
				admissionProof = make([]byte, c.bounds.bytes+1)
			case "head_missing_with_shared_pointer":
				qualRecordPut(t, f.store, headKey, nil)
				qualRecordPut(t, f.store, f.records.key("current", qualScopedHash("SCOPE", f.scope)), qualRecordFrame(f.scope, outer))
			case "wrong_outer_reference":
				fields := qualA38Split(in.intent)
				decisionFields := qualA38Split(fields[10])
				decisionFields[4] = ctx.admission.bodyHash
				fields[10] = qualRecordFrame(decisionFields...)
				in.intent = qualRecordFrame(fields...)
			case "wrong_head_body":
				qualRecordPut(t, f.store, f.records.key("version", outer), qualRecordFrame(f.scope, nil, ctx.independent.body))
			case "shared_independent_roster":
				in.independentAuthority = ctx.admission.body
			case "rotated":
				fresh := qualA38Split(ctx.admission.body)
				fresh[2], fresh[7], fresh[8] = qualA38U64(1), ctx.admission.version, ctx.admission.bodyHash
				updated := qualRecordFrame(fresh...)
				newRef := qualScopedHash("VERSION", f.scope, outer, updated)
				qualRecordPut(t, f.store, f.records.key("version", newRef), qualRecordFrame(f.scope, outer, updated))
				qualRecordPut(t, f.store, headKey, qualRecordFrame(f.scope, newRef))
			case "withdrawn":
				qualRecordPut(t, f.store, f.records.key("withdrawn", f.id()), decision)
			case "expired_decision":
				fields := qualA38Split(in.intent)
				decisionFields := qualA38Split(fields[10])
				decisionFields[5] = qualA38U64(49)
				fields[10] = qualRecordFrame(decisionFields...)
				in.intent = qualRecordFrame(fields...)
				qualRecordPut(t, f.store, f.records.key("decision", f.id()), fields[10])
			case "expired_envelope":
				f.context, err = f.clock.Begin(&block.MetaBlockV3{Epoch: 10, TimestampMs: 91})
				require.NoError(t, err)
			case "expired_header":
				f.clock.End(f.context)
			case "expired_operation":
				var expired *rollbackOperation
				require.NoError(t, f.boundary.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
					expired = op
					return nil, nil
				}))
				require.ErrorIs(t, qualStep1R2Verify(c, expired, f.records, f.context, provider, in, goodA, goodPA), ErrExecutionClosed)
				return
			case "foreign_operation":
				foreign := qualScopedNew(t)
				require.Error(t, run(foreign.boundary))
				return
			case "provider_writes":
				p.admission.hook = func() { qualRecordPut(t, f.store, []byte("synthetic/unrelated"), []byte("write")) }
			}
			root, err := f.store.RootHash()
			require.NoError(t, err)
			journal, outputs := f.store.JournalLen(), len(f.boundary.outputs)
			require.Error(t, run(f.boundary))
			after, err := f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
			require.Equal(t, journal, f.store.JournalLen())
			require.Equal(t, outputs, len(f.boundary.outputs))
		})
	}
}
