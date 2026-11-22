package drwa

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type qualStep1JoinFixture struct {
	state    *qualScopedFixture
	admit    *RegistrationAdmission
	codec    *registrationApprovalCodec
	provider *qualStep1BundleProvider
	input    bootstrapAdmissionProofInput
	role     []byte
	lineage  []byte
	args     [][]byte
	id       []byte
	digest   []byte
}

// The embedded decision and authority context here are experimental fixtures.
// They establish no production issuance or appointment.
func qualStep1OwnedJoin(t *testing.T) *qualStep1JoinFixture {
	t.Helper()
	return qualStep1OwnedJoinWithField10(t, nil)
}

func qualStep1OwnedJoinWithField10(t *testing.T, change func([]byte) []byte) *qualStep1JoinFixture {
	t.Helper()
	f := qualScopedNew(t)
	template, ctx, keys := qualR3Fixture(t, 200)
	codec, err := newRegistrationApprovalCodec(f.records.codec, template.bounds)
	require.NoError(t, err)
	f.context, err = f.clock.Begin(&block.MetaBlockV3{Epoch: 10, TimestampMs: 50})
	require.NoError(t, err)

	outer := qualScopedHash("VERSION", f.scope, nil, ctx.admission.body)
	f.d.authority = outer
	decision := f.body()
	fields := qualA38Split(ctx.intentBody)
	fields[0], fields[1], fields[10] = f.records.domain, f.d.issuer, decision
	if change != nil {
		fields[10] = change(decision)
	}
	ctx.network, ctx.issuer = fields[0], fields[1]
	ctx.intentBody = qualRecordFrame(fields...)
	ctx.intentHash = qualA38Hash(qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT_PAYLOAD/v1"), ctx.intentBody))
	ctx.intentID = qualA38Hash(qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT/v1"), ctx.network, ctx.issuer, ctx.programme, fields[3], ctx.intentHash))
	head := qualScopedHash("SCOPE", f.scope, []byte("REGISTER_TOKEN_ADMISSION"))
	qualRecordPut(t, f.store, f.records.key("current", head), qualRecordFrame(f.scope, outer))
	qualRecordPut(t, f.store, f.records.key("version", outer), qualRecordFrame(f.scope, nil, ctx.admission.body))
	qualRecordPut(t, f.store, f.records.key("decision", f.id()), decision)
	qualStep1PutPurposeHead(t, f, "REGISTER_TOKEN", nil, ctx.independent.body)
	_, _, err = f.boundary.Commit()
	require.NoError(t, err)
	f.boundary, err = NewRollbackContainment(f.store)
	require.NoError(t, err)
	f.records.boundary = f.boundary

	lineage := []byte("synthetic admitted appointment lineage")
	a, pa, ia := qualA126Bytes(t, qualStep1AdmissionM), qualA126Bytes(t, qualStep1PAM), qualA126Message(t, ctx, 10, 90)
	if change != nil {
		commitment := qualA38Hash(qualRecordFrame(fields[10], fields[12]))
		aFields, paFields := qualA38Split(a), qualA38Split(pa)
		aFields[6], aFields[7], aFields[8] = ctx.intentID, ctx.intentHash, commitment
		paFields[6], paFields[7], paFields[8] = ctx.intentID, ctx.intentHash, commitment
		paDependency := qualA38Split(paFields[9])
		paDependency[5] = ctx.intentHash
		paFields[9] = qualRecordFrame(paDependency...)
		a, pa = qualRecordFrame(aFields...), qualRecordFrame(paFields...)
	}
	expect := func(purpose string, set registrationApprovalAuthority, line, message []byte) qualBootstrapProofProvider {
		return qualBootstrapProofProvider{current: true, id: ctx.intentID, digest: ctx.intentHash, expected: bootstrapProofBinding{
			purpose: []byte(purpose), role: set.role, owner: f.d.owner, intent: ctx.intentBody, authority: set.body,
			lineage: line, message: message, notBefore: 10, notAfter: 90, signerIndices: []uint64{0, 2, 4},
		}}
	}
	provider := &qualStep1BundleProvider{
		qualStep1R2Provider: &qualStep1R2Provider{
			admission: expect("BOOTSTRAP_INTENT_ADMISSION", ctx.admission, outer, a),
			pa:        expect("BOOTSTRAP_INTENT_PA_POSSESSION", ctx.pa, nil, pa),
		},
		independent: expect("BOOTSTRAP_INTENT", ctx.independent, lineage, ia),
	}
	bundle := qualRecordFrame(qualA38Envelope(a, keys["REGISTER_TOKEN_ADMISSION"], 0, 2, 4),
		qualA38Envelope(pa, keys["PROGRAM_ADMINISTRATION"], 0, 2, 4),
		qualA38Envelope(ia, keys["REGISTER_TOKEN"], 0, 2, 4))
	owner := &RegistrationIntentOwner{records: f.records.codec, boundary: f.boundary, id: ctx.intentID, digest: ctx.intentHash}
	limits := f.records.limits
	admit := &RegistrationAdmission{owner: owner, source: f.records.timeSource, domain: bytes.Clone(f.records.domain), enableEpoch: 10,
		limits: RegistrationResourceLimits{limits.records, limits.retainedBytes, limits.newRecordsPerEpoch}}
	return &qualStep1JoinFixture{state: f, admit: admit, codec: codec, provider: provider,
		input: bootstrapAdmissionProofInput{owner: f.d.owner, admissionRole: ctx.admission.role, independentAuthority: ctx.independent.body},
		role:  ctx.independent.role, lineage: lineage, args: [][]byte{ctx.intentBody, bundle}, id: ctx.intentID, digest: ctx.intentHash}
}

// Independently framed literal D6: positive native fixture decision, and a
// distinct opaque commitment with leading zeros and high/zero bytes.
const qualStep1D6Original = "0a3b0a0e666978747572652d646f6d61696e0a2001010101010101010101010101010101010101010101010101010101010101010a0770726f6772616d0a2002020202020202020202020202020202020202020202020202020202020202020a0a6465636973696f6e2d310a1d6f66662d636861696e2d65766964656e63652d636f6d6d69746d656e740a20f849cdbde511347acbb3a4e3024af66acec86a99eae1c20129a7ba88e57e39d40a0800000000000000c8"
const qualStep1D6Opaque = "0a3b0a0e666978747572652d646f6d61696e0a2001010101010101010101010101010101010101010101010101010101010101010a0770726f6772616d0a2002020202020202020202020202020202020202020202020202020202020202020a0a6465636973696f6e2d310a05000080ff000a20f849cdbde511347acbb3a4e3024af66acec86a99eae1c20129a7ba88e57e39d40a0800000000000000c8"

func TestQualDRWAStep1D6SignedDecisionMustMatchProtectedRow(t *testing.T) {
	for _, name := range []string{"opaque-commitment", "foreign-scope", "wrong-issuer", "wrong-outer-version", "malformed", "extra-field", "empty-version"} {
		t.Run(name, func(t *testing.T) {
			f := qualStep1OwnedJoinWithField10(t, func(original []byte) []byte {
				require.Equal(t, qualA126Bytes(t, qualStep1D6Original), original)
				fields := qualA38Split(bytes.Clone(original))
				switch name {
				case "opaque-commitment":
					return qualA126Bytes(t, qualStep1D6Opaque)
				case "foreign-scope":
					scope := qualA38Split(fields[0])
					scope[1][0] ^= 1
					fields[0] = qualRecordFrame(scope...)
				case "wrong-issuer":
					fields[1][0] ^= 1
				case "wrong-outer-version":
					fields[4][0] ^= 1
				case "malformed":
					fields[5] = fields[5][1:]
				case "extra-field":
					fields = append(fields, []byte("unallocated flag"))
				case "empty-version":
					fields[2] = nil
				}
				return qualRecordFrame(fields...)
			})
			s := f.state
			before := qualSnapshotScopedAdmission(t, s)
			calls := 0
			f.admit.verifier = qualStep1NativeVerifier(func(string, []byte, []byte, []byte, []byte, []byte, HeaderMilliseconds, uint32) error {
				calls++
				return nil
			})
			proofs := bootstrapIntentProofInputs{codec: f.codec, records: s.records, provider: f.provider, admission: f.input,
				independentRole: f.role, independentLineage: f.lineage}
			err := s.boundary.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
				return nil, f.admit.retainBootstrapIntentWithProofsOwned(op, s.context, proofs, f.args)
			})
			require.Error(t, err, "valid signatures over a different or invalid decision must not borrow an earlier stored decision")
			require.Zero(t, calls)
			require.Zero(t, f.provider.admission.calls)
			require.Equal(t, before, qualSnapshotScopedAdmission(t, s))
			require.Empty(t, qualRegistryValue(t, s.store, registrationIntentPrefix+string(f.id)))
		})
	}
}

func TestQualDRWAStep1D6OpaqueCommitmentReplayAndWithdrawal(t *testing.T) {
	opaque := qualA126Bytes(t, qualStep1D6Opaque)
	f := qualStep1OwnedJoinWithField10(t, func([]byte) []byte { return opaque })
	s := f.state
	// The independently constructed row stands in for earlier authenticated
	// issuance only in this fixture. The verification path cannot write it.
	qualRecordPut(t, s.store, s.records.key("decision", s.id()), opaque)
	parsed, err := s.records.codec.decodeBody(f.args[0])
	require.NoError(t, err)
	d, scope, err := f.codec.decodeBootstrapAdmissionDecision(s.records, parsed, f.input.owner)
	require.NoError(t, err)
	require.Equal(t, s.scope, scope)
	require.Equal(t, s.d.issuer, d.issuer)
	require.Equal(t, s.d.version, d.version)
	require.Equal(t, s.d.authority, d.authority)
	require.Equal(t, s.d.validUntil, d.validUntil)
	clear(parsed.issuerProgramAdmissionDecision)
	require.Equal(t, []byte{0, 0, 0x80, 0xff, 0}, d.commitment)
	calls := 0
	f.admit.verifier = qualStep1NativeVerifier(func(string, []byte, []byte, []byte, []byte, []byte, HeaderMilliseconds, uint32) error {
		calls++
		return nil
	})
	proofs := bootstrapIntentProofInputs{codec: f.codec, records: s.records, provider: f.provider, admission: f.input,
		independentRole: f.role, independentLineage: f.lineage}
	run := func() error {
		return s.boundary.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
			return nil, f.admit.retainBootstrapIntentWithProofsOwned(op, s.context, proofs, f.args)
		})
	}
	require.NoError(t, run())
	require.Equal(t, qualRecordFrame(f.args[0], []byte("OPEN"), nil), qualRegistryValue(t, s.store, registrationIntentPrefix+string(f.id)))
	before := qualSnapshotScopedAdmission(t, s)
	require.NoError(t, run())
	require.Equal(t, before, qualSnapshotScopedAdmission(t, s), "exact OPEN replay has no additional write")
	require.Equal(t, 2, calls)
	qualRecordPut(t, s.store, s.records.key("withdrawn", s.id()), opaque)
	withdrawn := qualSnapshotScopedAdmission(t, s)
	require.ErrorIs(t, run(), errScopedAdmission, "an OPEN replay is also an admission use")
	require.Equal(t, 2, calls)
	require.Equal(t, 2, f.provider.admission.calls)
	require.Equal(t, withdrawn, qualSnapshotScopedAdmission(t, s))
	require.Empty(t, s.boundary.outputs)
}

type qualStep1NativeVerifier func(string, []byte, []byte, []byte, []byte, []byte, HeaderMilliseconds, uint32) error

func (v qualStep1NativeVerifier) IsInterfaceNil() bool { return v == nil }

func (v qualStep1NativeVerifier) VerifyRegistration(purpose string, id, digest, body, creation, proof []byte,
	at HeaderMilliseconds, epoch uint32) error {
	return v(purpose, id, digest, body, creation, proof, at, epoch)
}

func TestQualDRWAStep1RejectsNestedWriteLease(t *testing.T) {
	f := qualStep1OwnedJoin(t)
	err := f.state.boundary.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
		f.admit.verifier = qualStep1NativeVerifier(func(_ string, _, _, body, _, proof []byte, _ HeaderMilliseconds, _ uint32) error {
			return f.codec.verifyBootstrapIntentArguments(op, f.state.records, f.state.context, f.provider, f.input, f.role, f.lineage, [][]byte{body, proof})
		})
		return nil, f.admit.retainBootstrapIntentOwned(op, f.state.context, f.args[0], f.args[1])
	})
	require.ErrorIs(t, err, ErrExecutionBusy)
	require.Empty(t, qualRegistryValue(t, f.state.store, string(append([]byte(registrationIntentPrefix), f.id...))))
	require.Empty(t, f.state.boundary.outputs)
}

type qualStep1ProviderFailure struct {
	bootstrapProofProvider
	failure error
}

func (p qualStep1ProviderFailure) VerifyBootstrapBinding(binding bootstrapProofBinding, id, digest []byte, at HeaderMilliseconds, epoch uint32) error {
	if err := p.bootstrapProofProvider.VerifyBootstrapBinding(binding, id, digest, at, epoch); err != nil {
		return err
	}
	return p.failure
}

func TestQualDRWAStep1OriginalOperationProofRetentionJoin(t *testing.T) {
	for _, name := range []string{"exact", "freeze", "nil-operation", "closed", "foreign", "wrong-boundary", "wrong-records", "wrong-header", "missing-provider",
		"missing-independent-head", "missing-stored-admission", "withdrawn-stored-admission",
		"second-store", "same-value", "aba", "partial-proof", "proof-provider-error", "native-verifier-error", "native-root-error", "final-save-error", "late-error"} {
		t.Run(name, func(t *testing.T) {
			f := qualStep1OwnedJoin(t)
			s := f.state
			other := qualRegistrationStore(t, 0)
			reader := &rootReadFault{AccountsAdapter: other}
			var err error
			s.boundary, err = NewRollbackContainment(s.store, reader)
			require.NoError(t, err)
			s.records.boundary, f.admit.owner.boundary = s.boundary, s.boundary
			priorKey, priorValue := []byte("fixture/prior-step1"), []byte("prior state")
			require.NoError(t, s.boundary.executeOwned(func(*rollbackOperation) ([]*vmcommon.VMOutput, error) {
				qualRecordPut(t, s.store, priorKey, priorValue)
				qualRecordPut(t, other, priorKey, priorValue)
				return nil, nil
			}))
			switch name {
			case "missing-independent-head":
				key := s.records.key("current", qualScopedHash("SCOPE", s.scope, []byte("REGISTER_TOKEN")))
				qualRecordPut(t, s.store, key, nil)
			case "missing-stored-admission":
				qualRecordPut(t, s.store, s.records.key("decision", s.id()), nil)
			case "withdrawn-stored-admission":
				qualRecordPut(t, s.store, s.records.key("withdrawn", s.id()), s.body())
			}
			before := qualSnapshotScopedAdmission(t, s)
			otherRoot, err := other.RootHash()
			require.NoError(t, err)
			otherJournal := other.JournalLen()
			key := string(append([]byte(registrationIntentPrefix), f.id...))
			wantOpen := qualRecordFrame(f.args[0], []byte("OPEN"), nil)
			proofs := bootstrapIntentProofInputs{codec: f.codec, records: s.records, provider: f.provider, admission: f.input,
				independentRole: f.role, independentLineage: f.lineage}
			proofs.admission.owner = bytes.Clone(f.input.owner)
			args := [][]byte{bytes.Clone(f.args[0]), bytes.Clone(f.args[1])}
			context := s.context
			calls := 0
			nativeFailure := errors.New("synthetic native Step 1 failure")
			f.admit.verifier = qualStep1NativeVerifier(func(purpose string, id, digest, body, creation, proof []byte, at HeaderMilliseconds, epoch uint32) error {
				calls++
				require.Equal(t, "BOOTSTRAP_INTENT", purpose)
				require.Equal(t, f.id, id)
				require.Equal(t, f.digest, digest)
				require.Equal(t, f.args[0], body)
				require.Equal(t, f.args[1], proof)
				require.Empty(t, creation)
				require.Equal(t, HeaderMilliseconds(50), at)
				require.Equal(t, uint32(10), epoch)
				require.Empty(t, s.boundary.outputs)
				body[0], proof[0], id[0], digest[0] = 0, 0, 0, 0
				if name == "final-save-error" {
					s.store.saveErr = nativeFailure
				}
				if name == "native-verifier-error" {
					return nativeFailure
				}
				return nil
			})

			wantErr := errInvalidRegistrationRecord
			switch name {
			case "freeze":
				f.provider.admission.mutateArguments = true
				f.provider.admission.hook = func() {
					args[0][0], args[1][0] = 0, 0
					proofs.admission.owner[0] = 0
				}
			case "wrong-boundary":
				proofs.records = &scopedAdmissionRecords{codec: s.records.codec, boundary: qualScopedNew(t).boundary}
				wantErr = errInvalidMetaContext
			case "wrong-records":
				copyRecords := *s.records
				copyCodec := *s.records.codec
				copyRecords.codec = &copyCodec
				proofs.records = &copyRecords
				wantErr = errInvalidMetaContext
			case "wrong-header":
				context = qualScopedNew(t).context
				wantErr = ErrInactiveHeaderTime
			case "missing-provider":
				proofs.provider = nil
			case "missing-independent-head", "missing-stored-admission", "withdrawn-stored-admission":
				wantErr = errScopedAdmission
			case "second-store":
				f.provider.admission.hook = func() { qualRecordPut(t, other, priorKey, []byte("verifier write")) }
			case "same-value", "aba":
				f.provider.admission.hook = func() {
					journal := s.store.JournalLen()
					if name == "aba" {
						qualRecordPut(t, s.store, priorKey, []byte("temporary verifier write"))
					}
					qualRecordPut(t, s.store, priorKey, priorValue)
					root, e := s.store.RootHash()
					require.NoError(t, e)
					require.Equal(t, before.root, root)
					require.Greater(t, s.store.JournalLen(), journal)
				}
			case "partial-proof":
				args[1][len(args[1])-1] ^= 1
				wantErr = nil // exact signature failure comes from the existing verifier
			case "proof-provider-error":
				proofs.provider = qualStep1ProviderFailure{f.provider, nativeFailure}
				wantErr = nativeFailure
			case "native-root-error":
				f.provider.admission.hook = func() { reader.at, reader.failure = reader.calls+1, nativeFailure }
				wantErr = nativeFailure
			case "native-verifier-error", "final-save-error", "late-error":
				wantErr = nativeFailure
			}

			run := func(op *rollbackOperation) error {
				return f.admit.retainBootstrapIntentWithProofsOwned(op, context, proofs, args)
			}
			switch name {
			case "nil-operation":
				require.ErrorIs(t, run(nil), errInvalidMetaContext)
			case "closed":
				var closed *rollbackOperation
				require.NoError(t, s.boundary.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
					closed = op
					return nil, nil
				}))
				require.ErrorIs(t, run(closed), ErrExecutionClosed)
			case "foreign":
				foreign := qualScopedNew(t)
				require.ErrorIs(t, foreign.boundary.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
					return nil, run(op)
				}), errInvalidMetaContext)
			default:
				lateOutput := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, ReturnMessage: "original operation output"}
				err = s.boundary.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
					if e := run(op); e != nil {
						// Dropping an inner failure must not make the original owner commit.
						return []*vmcommon.VMOutput{lateOutput}, nil
					}
					require.Equal(t, wantOpen, qualRegistryValue(t, s.store, key))
					require.Empty(t, s.boundary.outputs)
					roots, outputs, e := s.boundary.Commit()
					require.ErrorIs(t, e, ErrExecutionBusy)
					require.Empty(t, roots)
					require.Empty(t, outputs)
					if name == "late-error" {
						return []*vmcommon.VMOutput{lateOutput}, nativeFailure
					}
					return []*vmcommon.VMOutput{lateOutput}, nil
				})
				if name == "exact" || name == "freeze" {
					require.NoError(t, err)
					require.Equal(t, 1, calls)
					require.Equal(t, 1, f.provider.admission.calls)
					require.Equal(t, 1, f.provider.pa.calls)
					require.Equal(t, 1, f.provider.independent.calls)
					_, outputs, e := s.boundary.Commit()
					require.NoError(t, e)
					require.Equal(t, []*vmcommon.VMOutput{lateOutput}, outputs)
					return
				}
				if wantErr == nil {
					require.Error(t, err)
				} else {
					require.ErrorIs(t, err, wantErr)
				}
			}

			require.Empty(t, qualRegistryValue(t, s.store, key))
			require.Equal(t, before, qualSnapshotScopedAdmission(t, s))
			afterOther, err := other.RootHash()
			require.NoError(t, err)
			require.Equal(t, otherRoot, afterOther)
			require.Equal(t, otherJournal, other.JournalLen())
			require.Equal(t, priorValue, qualRegistryValue(t, s.store, string(priorKey)))
			require.Equal(t, priorValue, qualRegistryValue(t, other, string(priorKey)))
			require.Empty(t, s.boundary.outputs)
			switch name {
			case "native-verifier-error", "final-save-error", "late-error":
				require.Equal(t, 1, calls)
				require.Equal(t, 1, f.provider.independent.calls)
			case "partial-proof":
				require.Zero(t, calls)
				require.Equal(t, 1, f.provider.admission.calls)
				require.Equal(t, 1, f.provider.pa.calls)
				require.Zero(t, f.provider.independent.calls)
			case "second-store", "same-value", "aba", "proof-provider-error", "native-root-error":
				require.Zero(t, calls)
				require.Equal(t, 1, f.provider.admission.calls)
				require.Zero(t, f.provider.pa.calls)
			default:
				require.Zero(t, calls)
				require.Zero(t, f.provider.admission.calls)
			}
		})
	}
}
