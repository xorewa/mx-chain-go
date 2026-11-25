package drwa

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/config"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestQualDRWALaneBBootstrapCommitmentFraming(t *testing.T) {
	records := qualB9Codec(t, nil).codec
	codec, err := newRegistrationApprovalCodec(records, registrationApprovalBounds{
		bytes: 4096, fieldBytes: 64, roleBytes: 64, familyBytes: 64, maxMembers: 5, maxValidity: 1,
	})
	require.NoError(t, err)
	a, pa := qualB9Bytes(t, "A_hash"), qualB9Bytes(t, "PA_hash")
	intent := bootstrapIntentBody{issuerProgramAdmissionDecision: []byte("opaque")}
	for _, tc := range []struct {
		name   string
		hashes [][]byte
		want   string
	}{
		{"A-then-PA", [][]byte{a, pa}, "6f0ade74de38a4bafd4dd1c01031261b475663f591185fef6a769ceb55bc562b"},
		{"PA-then-A", [][]byte{pa, a}, "a138dc846df63a7b022c63b89dbc7744354a6920c2e75006956df306ae6868ad"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			intent.proposedProgramAuthoritySetHashes = tc.hashes
			got, err := codec.bootstrapIntentCommitment(intent)
			require.NoError(t, err)
			require.Equal(t, tc.want, hex.EncodeToString(got))
		})
	}
	intent.proposedProgramAuthoritySetHashes = nil
	got, err := codec.bootstrapIntentCommitment(intent)
	require.ErrorIs(t, err, errInvalidRegistrationRecord)
	require.Nil(t, got)
	got, err = codec.bootstrapFrameHash(make([]byte, records.maxBytes))
	require.ErrorIs(t, err, errInvalidRegistrationRecord)
	require.Nil(t, got)
}

func TestQualDRWALaneBBootstrapReadOnlyPreconditions(t *testing.T) {
	f := qualScopedNew(t)
	codec, err := newRegistrationApprovalCodec(f.records.codec, registrationApprovalBounds{
		bytes: 4096, fieldBytes: 64, roleBytes: 64, familyBytes: 64, maxMembers: 5, maxValidity: 1,
	})
	require.NoError(t, err)

	called := false
	err = codec.withBootstrapProofOperation(nil, f.records, f.context, func(HeaderMilliseconds, uint32) error {
		called = true
		return nil
	})
	require.ErrorIs(t, err, errInvalidRegistrationRecord)
	require.False(t, called)
	err = codec.verifyBootstrapAdmissionPAAt(f.records, f.context, nil, bootstrapAdmissionProofInput{}, nil, nil, nil, 100, 10)
	require.ErrorIs(t, err, errInvalidRegistrationRecord)

	intent := bootstrapIntentBody{
		networkDomain: []byte("fixture-domain"), issuerProgramAdmissionDecision: f.body(),
		programID: f.d.program, issuer: f.d.issuer,
	}
	got, scope, err := codec.decodeBootstrapAdmissionDecision(f.records, intent, f.d.owner)
	require.NoError(t, err)
	require.Equal(t, f.d, got)
	require.Equal(t, f.scope, scope)

	t.Run("missing-issuer", func(t *testing.T) {
		noIssuer := intent
		noIssuer.issuer = nil
		got, scope, err := codec.decodeBootstrapAdmissionDecision(f.records, noIssuer, f.d.owner)
		require.ErrorIs(t, err, errScopedAdmission)
		require.Equal(t, scopedAdmissionDecision{}, got)
		require.Nil(t, scope)
	})
	t.Run("missing-owner", func(t *testing.T) {
		got, scope, err := codec.decodeBootstrapAdmissionDecision(f.records, intent, nil)
		require.ErrorIs(t, err, errScopedAdmission)
		require.Equal(t, scopedAdmissionDecision{}, got)
		require.Nil(t, scope)
	})
	t.Run("missing-decision", func(t *testing.T) {
		noDecision := intent
		noDecision.issuerProgramAdmissionDecision = nil
		got, scope, err := codec.decodeBootstrapAdmissionDecision(f.records, noDecision, f.d.owner)
		require.ErrorIs(t, err, errInvalidRegistrationRecord)
		require.Equal(t, scopedAdmissionDecision{}, got)
		require.Nil(t, scope)
	})
	t.Run("unrelated-issuer", func(t *testing.T) {
		unrelated := intent
		unrelated.issuer = bytes.Clone(intent.issuer)
		unrelated.issuer[0] ^= 1
		got, scope, err := codec.decodeBootstrapAdmissionDecision(f.records, unrelated, f.d.owner)
		require.ErrorIs(t, err, errScopedAdmission)
		require.Equal(t, scopedAdmissionDecision{}, got)
		require.Nil(t, scope)
	})

	intent.networkDomain = []byte("other-qualification-domain")
	got, scope, err = codec.decodeBootstrapAdmissionDecision(f.records, intent, f.d.owner)
	require.ErrorIs(t, err, errScopedAdmission)
	require.Equal(t, scopedAdmissionDecision{}, got)
	require.Nil(t, scope)
}

func TestQualDRWALaneBNativeWitnessRequiresInputs(t *testing.T) {
	args := qualReaderArgs(false)
	reader, err := NewResultAccountReader(args)
	require.NoError(t, err)
	template := AccountItemWitness{Header: []byte("ordinary header"), ExecutedHeader: []byte("ordinary execution")}
	committed := []byte{1}
	address, key := []byte("ordinary account"), []byte("ordinary key")
	got, err := reader.BuildNativeWitness(nil, committed, 0, address, key, template, 64)
	require.ErrorIs(t, err, ErrInvalidAccountWitness)
	require.Equal(t, AccountItemWitness{}, got)

	db := qualGenesisAccountsFromArgs(t, args)
	got, err = reader.BuildNativeWitness(db, committed, 0, address, key, template, 64)
	require.ErrorIs(t, err, ErrInvalidAccountWitness)
	require.Equal(t, template, got)
	require.Zero(t, db.JournalLen())
}

func TestQualDRWALaneBInitialProgrammePreparationRefusals(t *testing.T) {
	input, limits := qualStageAData(t)
	mismatched := append([]InitialProgrammeEvidence(nil), input...)
	mismatched[0].owner = bytes.Repeat([]byte{9}, 32)
	for _, tc := range []struct {
		name    string
		input   []InitialProgrammeEvidence
		minimum *config.DRWAMinimumGenesis
		want    error
	}{
		{"no-programme", nil, nil, ErrInitialProgrammeLimits},
		{"empty-minimum", input, &config.DRWAMinimumGenesis{}, errInvalidGenesisState},
		{"cached-owner-mismatch", mismatched, nil, errInvalidRegistrationRecord},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := qualReaderArgs(false)
			db := qualGenesisAccountsFromArgs(t, args)
			before, err := db.RootHash()
			require.NoError(t, err)
			stage, err := PrepareInitialProgrammeGenesis(db, tc.input, limits, tc.minimum, args.Marshaller, args.Hasher, 17)
			require.ErrorIs(t, err, tc.want)
			require.Nil(t, stage)
			after, err := db.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Zero(t, db.JournalLen())
		})
	}

	t.Run("adapter-failure-before-staging", func(t *testing.T) {
		rootErr := errors.New("fixture root unavailable")
		rootReads := 0
		db := &stateMock.AccountsStub{
			RootHashCalled: func() ([]byte, error) {
				rootReads++
				return nil, rootErr
			},
			LoadAccountCalled: func([]byte) (vmcommon.AccountHandler, error) {
				t.Fatal("account load before root validation")
				return nil, rootErr
			},
			SaveAccountCalled: func(vmcommon.AccountHandler) error {
				t.Fatal("account save before root validation")
				return rootErr
			},
		}
		args := qualReaderArgs(false)
		stage, err := PrepareInitialProgrammeGenesis(db, input, limits, nil, nil, args.Hasher, 17)
		require.ErrorIs(t, err, errInvalidRegistrationRecord)
		require.Nil(t, stage)
		require.Zero(t, rootReads)

		stage, err = PrepareInitialProgrammeGenesis(db, input, limits, nil, args.Marshaller, args.Hasher, 17)
		require.ErrorIs(t, err, rootErr)
		require.Nil(t, stage)
		require.Equal(t, 1, rootReads)
	})

	for _, tc := range []struct {
		name    string
		minimum *config.DRWAMinimumGenesis
	}{
		{"basic-writer-root-unavailable", nil},
		{"minimum-writer-root-unavailable", &config.DRWAMinimumGenesis{
			ProfileDigest:      sha256.Sum256([]byte("fixture profile")),
			ReleaseDigest:      sha256.Sum256([]byte("fixture release")),
			MaxEverTokens:      64,
			RegistryProofBytes: 1048576,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rootErr := errors.New("fixture writer root unavailable")
			rootReads := 0
			db := &stateMock.AccountsStub{
				RootHashCalled: func() ([]byte, error) {
					rootReads++
					if rootReads == 1 {
						return nil, nil
					}
					return nil, rootErr
				},
				LoadAccountCalled: func([]byte) (vmcommon.AccountHandler, error) {
					t.Fatal("account load after writer root error")
					return nil, rootErr
				},
				SaveAccountCalled: func(vmcommon.AccountHandler) error {
					t.Fatal("account save after writer root error")
					return rootErr
				},
			}
			args := qualReaderArgs(false)
			stage, err := PrepareInitialProgrammeGenesis(db, input, limits, tc.minimum, args.Marshaller, args.Hasher, 17)
			require.NoError(t, err)
			require.NotNil(t, stage)
			require.Equal(t, 1, rootReads)
			require.ErrorIs(t, stage(), rootErr)
			require.Equal(t, 2, rootReads)
		})
	}
}

func TestQualDRWALaneBStoredObservationPrerequisites(t *testing.T) {
	for _, omitDecoder := range []bool{false, true} {
		name := "lookup-keys-over-budget"
		if omitDecoder {
			name = "missing-decoder"
		}
		t.Run(name, func(t *testing.T) {
			f, previous, original, miniRaw, resultRaw, limit := qualNativeMetaSCRFixture(t, nil)
			origin := f.hash(f.w.Account.ExecutedHeader)
			miniHash, resultHash := f.hash(miniRaw), f.hash(resultRaw)
			limit += len(miniHash) + len(resultHash)
			if omitDecoder {
				f.reader.accounts.args.Marshaller = nil
			} else {
				// The fixture's starting limit includes the payloads. Set a
				// limit one byte short of the context and lookup keys alone.
				limit -= len(miniRaw) + len(resultRaw) + 1
			}
			reads := 0
			storer := &qualSCRPayloadStorer{get: func([]byte, uint32) ([]byte, error) {
				reads++
				return nil, errors.New("unexpected storage read")
			}}
			source := &qualSCRPayloadStorage{mini: storer, results: storer}
			before := f.oracle.calls
			got, err := f.reader.readStoredNativeMetaSCRObservation(source, 7, miniHash, resultHash,
				f.bHash, f.consumer, origin, previous, original, f.w, limit)
			require.ErrorIs(t, err, ErrInvalidAccountWitness)
			require.Nil(t, got)
			require.Zero(t, reads)
			require.Equal(t, before, f.oracle.calls)
		})
	}
}

func TestQualDRWALaneBIntentAuthorityListShape(t *testing.T) {
	codec := qualB9Codec(t, nil)
	owner, programme := bytes.Repeat([]byte{1}, 32), []byte("program")
	intent := bootstrapIntentBody{
		proposedProgramAuthoritySetBodies: [][]byte{qualB9Bytes(t, "A_body"), qualB9Bytes(t, "PA_body")},
		proposedProgramAuthoritySetHashes: [][]byte{qualB9Bytes(t, "A_hash"), qualB9Bytes(t, "PA_hash")},
	}
	got, err := codec.selectIntentPA(intent, owner, programme)
	require.NoError(t, err)
	require.Equal(t, qualB9Bytes(t, "PA_hash"), got.hash)

	for _, tc := range []struct {
		name string
		body bool
	}{
		{"missing-body", true},
		{"missing-hash", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := intent
			if tc.body {
				candidate.proposedProgramAuthoritySetBodies = [][]byte{intent.proposedProgramAuthoritySetBodies[0], nil}
			} else {
				candidate.proposedProgramAuthoritySetHashes = [][]byte{intent.proposedProgramAuthoritySetHashes[0], nil}
			}
			selected, err := codec.selectIntentPA(candidate, owner, programme)
			require.ErrorIs(t, err, errInvalidRegistrationRecord)
			require.Nil(t, selected)
		})
	}

	intent.proposedProgramAuthoritySetHashes = intent.proposedProgramAuthoritySetHashes[:1]
	got, err = codec.selectIntentPA(intent, owner, programme)
	require.ErrorIs(t, err, errInvalidRegistrationRecord)
	require.Nil(t, got)
	got, err = codec.selectIntentPA(bootstrapIntentBody{}, owner, programme)
	require.ErrorIs(t, err, errInvalidRegistrationRecord)
	require.Nil(t, got)
}

func TestQualDRWALaneBAuthorityPurposeBounds(t *testing.T) {
	codec := qualB9Codec(t, nil).codec
	records := &scopedAdmissionRecords{codec: codec, domain: []byte("fixture")}
	key, err := records.authorityPurposeKey(make([]byte, codec.maxBytes+1), "REGISTER_TOKEN")
	require.ErrorIs(t, err, errInvalidRegistrationRecord)
	require.Nil(t, key)

	writes, err := records.initialPurposeWrites(&initialAppointment{
		owner: bytes.Repeat([]byte{1}, 31), programme: []byte("program"),
	})
	require.ErrorIs(t, err, errScopedAdmission)
	require.Nil(t, writes)
}

func TestQualDRWALaneBIdentitySnapshots(t *testing.T) {
	fields, bounds := qualA72IdentityInput(t)
	raw := qualRecordFrame(fields...)
	pin := sha256.Sum256(raw)
	identity, err := qualA72DecodeIdentity(raw, pin[:], fields[1], 17, bounds)
	require.NoError(t, err)
	for _, field := range []struct {
		get  func() []byte
		want []byte
	}{
		{identity.Raw, raw},
		{identity.Header, fields[3]},
		{identity.GenesisHash, fields[4]},
		{identity.Domain, fields[5]},
	} {
		got := field.get()
		require.Equal(t, field.want, got)
		got[0] ^= 1
		require.Equal(t, field.want, field.get())
	}
	require.Equal(t, uint32(17), identity.GenesisEpoch())

	var absent *DeploymentIdentity
	require.Nil(t, absent.Raw())
	require.Nil(t, absent.Header())
	require.Nil(t, absent.GenesisHash())
	require.Nil(t, absent.Domain())
	require.Zero(t, absent.GenesisEpoch())
}

func TestQualDRWALaneBProgrammeEvidence(t *testing.T) {
	raw := qualStageARaw(t)
	limits := qualStageALimits()
	limits.FileBytes = len(raw)
	marshaller := &marshal.GogoProtoMarshalizer{}
	hasher := blake2b.NewBlake2b()
	evidence, err := DecodeInitialProgrammeEvidence(raw, "synthetic", "integrity-only", limits, marshaller, hasher)
	require.NoError(t, err)
	require.Equal(t, raw, evidence.Raw())
	require.Equal(t, bytes.Repeat([]byte{1}, 32), evidence.Owner())
	require.Equal(t, []byte("program"), evidence.Programme())
	path, pin := evidence.Source()
	require.Equal(t, "synthetic", path)
	require.Equal(t, "integrity-only", pin)

	input := []InitialProgrammeEvidence{evidence}
	copied := CloneInitialProgrammeEvidence(input)
	for _, value := range [][]byte{copied[0].Raw(), copied[0].Owner(), copied[0].Programme()} {
		value[0] ^= 1
	}
	input[0].raw[0] ^= 1
	input[0].owner[0] ^= 1
	input[0].programme[0] ^= 1
	require.Equal(t, raw, copied[0].Raw())
	require.Equal(t, bytes.Repeat([]byte{1}, 32), copied[0].Owner())
	require.Equal(t, []byte("program"), copied[0].Programme())
	require.Nil(t, CloneInitialProgrammeEvidence(nil))

	limits.FileBytes--
	refused, err := DecodeInitialProgrammeEvidence(raw, path, pin, limits, marshaller, hasher)
	require.ErrorIs(t, err, ErrInitialProgrammeLimits)
	require.Equal(t, InitialProgrammeEvidence{}, refused)
	refused, err = DecodeInitialProgrammeEvidence(raw, path, pin, nil, marshaller, hasher)
	require.ErrorIs(t, err, ErrInitialProgrammeLimits)
	require.Equal(t, InitialProgrammeEvidence{}, refused)
	refused, err = DecodeInitialProgrammeEvidence(raw, path, pin, limits, nil, hasher)
	require.ErrorIs(t, err, errInvalidRegistrationRecord)
	require.Equal(t, InitialProgrammeEvidence{}, refused)
}

func TestQualDRWALaneBMinimumGenesisDeclarations(t *testing.T) {
	input := config.DRWAMinimumGenesis{
		ProfileDigest:      sha256.Sum256([]byte("fixture profile")),
		ReleaseDigest:      sha256.Sum256([]byte("fixture release")),
		MaxEverTokens:      64,
		RegistryProofBytes: 1048576,
	}
	require.NoError(t, ValidateInitialProgrammeMinimum(input))
	minimum := initialProgrammeMinimum(input)
	require.Equal(t, input.ProfileDigest, minimum.profileDigest)
	require.Equal(t, input.ReleaseDigest, minimum.releaseDigest)
	require.Equal(t, input.MaxEverTokens, minimum.maxEverTokens)
	require.Equal(t, input.RegistryProofBytes, minimum.registryProofBytes)

	invalid := input
	invalid.ProfileDigest = [32]byte{}
	require.ErrorIs(t, ValidateInitialProgrammeMinimum(invalid), errInvalidGenesisState)
	invalid = input
	invalid.ReleaseDigest = [32]byte{}
	require.ErrorIs(t, ValidateInitialProgrammeMinimum(invalid), errInvalidGenesisState)
	invalid = input
	invalid.MaxEverTokens = 0
	require.ErrorIs(t, ValidateInitialProgrammeMinimum(invalid), errInvalidGenesisState)
	invalid = input
	invalid.RegistryProofBytes = 0
	require.ErrorIs(t, ValidateInitialProgrammeMinimum(invalid), errInvalidGenesisState)
	invalid.RegistryProofBytes = uint64(math.MaxInt) + 1
	require.ErrorIs(t, ValidateInitialProgrammeMinimum(invalid), errInvalidGenesisState)
}

func TestQualDRWALaneBActivationParentShapes(t *testing.T) {
	records := &registrationRecords{
		marshaller: &marshal.GogoProtoMarshalizer{},
		hasher:     blake2b.NewBlake2b(),
		maxBytes:   4096,
	}
	token := []byte("TOKEN-abcdef")
	intent := sha256.Sum256([]byte("fixture activation intent"))
	commitment := sha256.Sum256([]byte("fixture activation parent"))
	for _, fixture := range []struct {
		name   string
		fields [][]byte
	}{
		{"bootstrap", [][]byte{token, intent[:], []byte("BootstrapDeny")}},
		{"active", [][]byte{token, intent[:], []byte("Active"), commitment[:]}},
		{"wind-down", [][]byte{token, intent[:], []byte("WindDownDeny"), commitment[:]}},
		{"retired", [][]byte{token, intent[:], []byte("RetiredDeny"), commitment[:]}},
		{"cancelled", [][]byte{
			token, intent[:], []byte("RetiredDeny"), []byte("fixture original"),
			[]byte("fixture readback"), []byte("fixture issuer"), []byte("fixture cancellation"),
		}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			raw := qualRecordFrame(fixture.fields...)
			got, err := records.decodeActivationParent(raw, token)
			require.NoError(t, err)
			require.Equal(t, fixture.fields, got)
		})
	}

	for _, fixture := range []struct {
		name string
		raw  []byte
	}{
		{"missing", nil},
		{"unrelated-token", qualRecordFrame([]byte("OTHER-abcdef"), intent[:], []byte("BootstrapDeny"))},
		{"unexpected-state", qualRecordFrame(token, intent[:], []byte("Unknown"))},
		{"incomplete-cancellation", qualRecordFrame(token, intent[:], []byte("RetiredDeny"),
			[]byte("fixture original"), []byte("fixture readback"), []byte("fixture issuer"), nil)},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			got, err := records.decodeActivationParent(fixture.raw, token)
			require.ErrorIs(t, err, errActivationRecord)
			require.Nil(t, got)
		})
	}
}

func TestQualDRWALaneBActivationReadinessPreconditions(t *testing.T) {
	fixture := qualActivationNew(t)
	t.Cleanup(fixture.f.end)
	store := fixture.f.store
	binding := []byte("synthetic verified readiness identity")
	commitment := bytes.Repeat([]byte{7}, 32)
	phase := qualConvergenceNew(t, 3)
	phase.host.store, phase.host.binding = store, binding
	host := &activationReadinessHost{
		convergenceHost: phase.host,
		activation:      fixture.a,
		binding:         binding,
		token:           []byte("TOKEN-abcdef"),
		intentID:        fixture.f.owner.id,
	}
	for _, input := range []struct {
		name                string
		binding, commitment []byte
	}{
		{"different binding", []byte("another synthetic readiness identity"), commitment},
		{"wrong commitment width", binding, commitment[:31]},
	} {
		t.Run(input.name, func(t *testing.T) {
			before, err := store.RootHash()
			require.NoError(t, err)
			journal := store.JournalLen()

			out, err := host.Complete(input.binding, input.commitment)
			require.ErrorIs(t, err, errActivationRecord)
			require.Nil(t, out)
			require.ErrorIs(t, host.VerifyParent(input.binding, input.commitment), errActivationRecord)
			require.Zero(t, phase.host.completeCalls)
			require.Zero(t, phase.host.parentCalls)
			require.Empty(t, host.written)

			after, err := store.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Equal(t, journal, store.JournalLen())
		})
	}

	t.Run("bootstrap deny cannot prove readiness", func(t *testing.T) {
		key := append([]byte(registrationActivationPrefix), host.token...)
		require.Equal(t, qualRecordFrame(host.token, host.intentID, []byte("BootstrapDeny")), qualActivationValue(t, store, key))
		before, err := store.RootHash()
		require.NoError(t, err)
		journal := store.JournalLen()

		require.ErrorIs(t, host.VerifyParent(binding, commitment), errActivationRecord)
		require.Zero(t, phase.host.parentCalls)
		require.Empty(t, host.written)

		after, err := store.RootHash()
		require.NoError(t, err)
		require.Equal(t, before, after)
		require.Equal(t, journal, store.JournalLen())
	})
}

func TestQualDRWALaneBAuthorityPurposeScope(t *testing.T) {
	fixture := qualScopedNew(t)
	t.Cleanup(func() { fixture.clock.End(fixture.context) })
	for _, input := range []struct {
		name, purpose    string
		owner, programme []byte
		shardContext     bool
	}{
		{"missing owner", "REGISTER_TOKEN", nil, fixture.d.program, false},
		{"missing programme", "REGISTER_TOKEN", fixture.d.owner, nil, false},
		{"unknown purpose", "UNKNOWN", fixture.d.owner, fixture.d.program, false},
		{"absent registration head", "REGISTER_TOKEN", fixture.d.owner, fixture.d.program, false},
		{"absent admission head", "REGISTER_TOKEN_ADMISSION", fixture.d.owner, fixture.d.program, false},
		{"current shard context", "REGISTER_TOKEN", fixture.d.owner, fixture.d.program, true},
	} {
		t.Run(input.name, func(t *testing.T) {
			active := fixture
			if input.shardContext {
				active = qualScopedNew(t)
				t.Cleanup(func() { active.clock.End(active.context) })
				context, err := active.clock.Begin(&block.HeaderV3{Epoch: 10, ShardID: 1, TimestampMs: 100})
				require.NoError(t, err)
				active.context = context

				current, err := active.records.timeSource.EvaluatedHeaderTimeContext()
				require.NoError(t, err)
				require.Same(t, context, current)
			}
			codec := qualB9Codec(t, active.records.codec)
			authority, err := codec.decode(qualB9Bytes(t, "C_body"))
			require.NoError(t, err)

			before, err := active.store.RootHash()
			require.NoError(t, err)
			journal := active.store.JournalLen()

			body, reference, err := active.records.readAuthorityPurposeHead(
				active.context, input.owner, input.programme, input.purpose, authority.role, codec,
			)
			require.ErrorIs(t, err, errScopedAdmission)
			require.Nil(t, body)
			require.Nil(t, reference)

			after, err := active.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Equal(t, journal, active.store.JournalLen())
		})
	}
}
