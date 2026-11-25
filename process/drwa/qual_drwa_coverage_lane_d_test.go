package drwa

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/marshallerMock"
	statemock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestQualLaneDRegistrationApprovalPublicVectors(t *testing.T) {
	records := &registrationRecords{
		marshaller: &marshal.GogoProtoMarshalizer{},
		hasher:     blake2b.NewBlake2b(),
		maxBytes:   4096,
	}
	codec, err := newRegistrationApprovalCodec(records, registrationApprovalBounds{
		bytes: 4096, fieldBytes: 2048, roleBytes: 64, familyBytes: 64, maxMembers: 8, maxValidity: 100,
	})
	require.NoError(t, err)

	t.Run("creation", func(t *testing.T) {
		raw := qualA38Bytes(t, "creation")
		intent, err := records.decodeBody(qualA38Bytes(t, "intent_body"))
		require.NoError(t, err)
		creation, err := codec.decodeCreation(raw, intent, bytes.Repeat([]byte{0x33}, 32), qualA38Bytes(t, "profile"))
		require.NoError(t, err)
		require.Equal(t, &registrationCreationBody{
			family:      []byte(core.FungibleESDT),
			profileHash: qualA38Split(raw)[2],
			name:        []byte("TokenName"),
			ticker:      []byte("TOKEN"),
			digest:      qualA38Bytes(t, "creation_hash"),
			decimals:    6,
		}, creation)
	})

	t.Run("missing-creation-input", func(t *testing.T) {
		intent, err := records.decodeBody(qualA38Bytes(t, "intent_body"))
		require.NoError(t, err)
		creation, err := codec.decodeCreation(nil, intent, bytes.Repeat([]byte{0x33}, 32), qualA38Bytes(t, "profile"))
		require.Error(t, err)
		require.Nil(t, creation)
	})

	t.Run("missing-profile", func(t *testing.T) {
		intent, err := records.decodeBody(qualA38Bytes(t, "intent_body"))
		require.NoError(t, err)
		creation, err := codec.decodeCreation(qualA38Bytes(t, "creation"), intent, bytes.Repeat([]byte{0x33}, 32), nil)
		require.ErrorIs(t, err, errInvalidRegistrationRecord)
		require.Nil(t, creation)
	})

	for _, tc := range []struct {
		name        string
		manager     []byte
		profile     []byte
		wantDigests int
	}{
		{
			name: "creation-body-is-not-a-profile", manager: bytes.Repeat([]byte{0x33}, 32),
			profile: qualA38Bytes(t, "creation"), wantDigests: 0,
		},
		{
			name: "scope-owner-is-not-profile-manager", manager: qualA38Split(qualA38Bytes(t, "scope"))[1],
			profile: qualA38Bytes(t, "profile"), wantDigests: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := qualA38Bytes(t, "creation")
			intent, err := records.decodeBody(qualA38Bytes(t, "intent_body"))
			require.NoError(t, err)
			var digests []string
			localRecords := *records
			localRecords.hasher = &testscommon.HasherStub{
				SizeCalled: records.hasher.Size,
				ComputeCalled: func(value string) []byte {
					digests = append(digests, value)
					require.Equal(t, string(raw), value)
					return records.hasher.Compute(value)
				},
			}
			localCodec, err := newRegistrationApprovalCodec(&localRecords, codec.bounds)
			require.NoError(t, err)
			creation, err := localCodec.decodeCreation(raw, intent, tc.manager, tc.profile)
			require.ErrorIs(t, err, errInvalidRegistrationRecord)
			require.Nil(t, creation)
			require.Len(t, digests, tc.wantDigests)
		})
	}

	t.Run("no-creation-digest", func(t *testing.T) {
		raw := qualA38Bytes(t, "creation")
		intent, err := records.decodeBody(qualA38Bytes(t, "intent_body"))
		require.NoError(t, err)
		calls := 0
		localRecords := *records
		localRecords.hasher = &testscommon.HasherStub{
			SizeCalled: records.hasher.Size,
			ComputeCalled: func(value string) []byte {
				calls++
				require.Equal(t, string(raw), value)
				return nil
			},
		}
		localCodec, err := newRegistrationApprovalCodec(&localRecords, codec.bounds)
		require.NoError(t, err)
		creation, err := localCodec.decodeCreation(raw, intent, bytes.Repeat([]byte{0x33}, 32), qualA38Bytes(t, "profile"))
		require.ErrorIs(t, err, errInvalidRegistrationRecord)
		require.Nil(t, creation)
		require.Equal(t, 1, calls)
	})

	t.Run("role-map", func(t *testing.T) {
		scope := qualA38Split(qualA38Bytes(t, "scope"))
		admission := qualA38Split(qualA38Bytes(t, "admission_dependency"))
		independent := qualA38Split(qualA38Bytes(t, "independent_dependency"))
		ctx := &registrationApprovalContext{
			network: scope[0], scopeOwner: scope[1], programme: scope[2],
			admission: registrationApprovalAuthority{
				role: admission[0], setID: admission[2], version: admission[3], bodyHash: admission[4],
			},
			independent: registrationApprovalAuthority{
				role: independent[0], setID: independent[2], version: independent[3], bodyHash: independent[4],
			},
		}
		expectedWire := qualA38Bytes(t, "map_bytes")
		wire, digest, err := codec.roleMap(ctx)
		require.NoError(t, err)
		require.Equal(t, expectedWire, wire)
		require.Equal(t, qualA38Bytes(t, "map_hash"), digest)

		t.Run("frame-over-bound", func(t *testing.T) {
			bounds := codec.bounds
			bounds.bytes = len(expectedWire) - 1
			bounds.fieldBytes = bounds.bytes
			fields := qualA38Split(expectedWire)
			require.LessOrEqual(t, len(fields[4]), bounds.bytes)
			require.LessOrEqual(t, len(fields[5]), bounds.bytes)
			localRecords := *records
			localRecords.hasher = &testscommon.HasherStub{
				SizeCalled: records.hasher.Size,
				ComputeCalled: func(string) []byte {
					t.Fatal("oversized frame reached digest")
					return nil
				},
			}
			bounded, err := newRegistrationApprovalCodec(&localRecords, bounds)
			require.NoError(t, err)
			wire, digest, err := bounded.roleMap(ctx)
			require.ErrorIs(t, err, errInvalidRegistrationRecord)
			require.Nil(t, wire)
			require.Nil(t, digest)
		})

		for _, tc := range []struct {
			name string
			row  int
		}{
			{name: "admission-row-encoding-error", row: 1},
			{name: "independent-row-encoding-error", row: 2},
		} {
			t.Run(tc.name, func(t *testing.T) {
				failure := errors.New("fixture role row encoding failed")
				calls := 0
				localRecords := *records
				localRecords.marshaller = &marshallerMock.MarshalizerStub{MarshalCalled: func(value interface{}) ([]byte, error) {
					calls++
					if calls == tc.row {
						return nil, failure
					}
					return records.marshaller.Marshal(value)
				}}
				localRecords.hasher = &testscommon.HasherStub{
					SizeCalled: records.hasher.Size,
					ComputeCalled: func(string) []byte {
						t.Fatal("failed row reached digest")
						return nil
					},
				}
				bounded, err := newRegistrationApprovalCodec(&localRecords, codec.bounds)
				require.NoError(t, err)
				wire, digest, err := bounded.roleMap(ctx)
				require.ErrorIs(t, err, failure)
				require.Nil(t, wire)
				require.Nil(t, digest)
				require.Equal(t, tc.row, calls)
			})
		}
	})

	t.Run("empty-input", func(t *testing.T) {
		wire, digest, err := codec.roleMap(nil)
		require.ErrorIs(t, err, errInvalidRegistrationRecord)
		require.Nil(t, wire)
		require.Nil(t, digest)
		digest, err = codec.hash(nil)
		require.ErrorIs(t, err, errInvalidRegistrationRecord)
		require.Nil(t, digest)
	})
}

func TestQualLaneDResultWitnessStorageReadOnly(t *testing.T) {
	key, node := []byte("supplied-node"), []byte("public node bytes")
	storage := &resultWitnessStorage{nodes: map[string][]byte{string(key): bytes.Clone(node)}}
	got, err := storage.GetFromCurrentEpoch(key)
	require.NoError(t, err)
	require.Equal(t, node, got)
	got[0] ^= 1
	got, err = storage.GetFromCurrentEpoch(key)
	require.NoError(t, err)
	require.Equal(t, node, got)

	absent := []byte("missing-node")
	require.ErrorIs(t, storage.Put(absent, node), ErrInvalidAccountWitness)
	require.ErrorIs(t, storage.Put(key, []byte("replacement")), ErrInvalidAccountWitness)
	got, err = storage.GetFromCurrentEpoch(absent)
	require.ErrorIs(t, err, ErrInvalidAccountWitness)
	require.Nil(t, got)
	got, err = storage.GetFromCurrentEpoch(key)
	require.NoError(t, err)
	require.Equal(t, node, got)
}

func TestQualLaneDRootLeafNonceSupplyDecoder(t *testing.T) {
	codec := qualRootLeafCodec(t)
	for _, tc := range []struct {
		name         string
		family       core.ESDTType
		raw          []byte
		issued, live int64
	}{
		{"unique-live", core.NonFungibleV2, []byte{1}, 1, 1},
		{"unique-burned", core.DynamicNFT, []byte{0}, 1, 0},
		{"semi-fungible-live", core.SemiFungible, qualRecordFrame([]byte{7}, []byte{3}), 7, 3},
		{"semi-fungible-full-burn", core.SemiFungible, qualRecordFrame([]byte{7}, nil), 7, 0},
		{"fungible-no-nonce", core.Fungible, []byte{1}, 0, 0},
		{"record-bound", core.SemiFungible, bytes.Repeat([]byte{1}, 513), 0, 0},
		{"invalid-unique", core.NonFungibleV2, []byte{2}, 0, 0},
		{"missing-unique", core.DynamicNFT, nil, 0, 0},
		{"incomplete-frame", core.SemiFungible, []byte{0x0a}, 0, 0},
		{"issued-leading-zero", core.SemiFungible, qualRecordFrame([]byte{0, 7}, []byte{3}), 0, 0},
		{"live-leading-zero", core.SemiFungible, qualRecordFrame([]byte{7}, []byte{0, 3}), 0, 0},
		{"live-exceeds-issued", core.SemiFungible, qualRecordFrame([]byte{3}, []byte{7}), 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := codec.decodeNonceValue(tc.family, tc.raw)
			if tc.issued == 0 {
				require.Error(t, err)
				require.Equal(t, nonceSupply{}, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, big.NewInt(tc.issued), got.issued)
			require.Equal(t, big.NewInt(tc.live), got.live)
		})
	}
}

func TestQualLaneDNativeRollbackRetainsBothFailures(t *testing.T) {
	owner := &statemock.AccountsStub{RootHashCalled: func() ([]byte, error) {
		return []byte("fixture checkpoint"), nil
	}}
	_, err := newNativeRollbackContainment()
	require.ErrorIs(t, err, state.ErrNilAccountsAdapter)
	boundary, err := newNativeRollbackContainment(owner)
	require.NoError(t, err)
	require.ErrorIs(t, boundary.nativeCommittedFor(owner), errNativePersistenceReceipt)
	require.ErrorIs(t, boundary.nativeResetFor(owner), errNativePersistenceReceipt)

	original := errors.New("fixture commit failure")
	restoration := errors.New("fixture restoration failure")
	require.ErrorIs(t, boundary.nativeCommitFailed(original), original)
	err = boundary.nativeCommitFailed(restoration)
	require.ErrorIs(t, err, original)
	require.ErrorIs(t, err, restoration)
	roots, outputs, err := boundary.nativeCommitReceipt()
	require.Nil(t, roots)
	require.Nil(t, outputs)
	require.ErrorIs(t, err, original)
	require.ErrorIs(t, err, restoration)
}

func TestQualLaneDNativeRollbackMissingFailureCause(t *testing.T) {
	owner := &statemock.AccountsStub{RootHashCalled: func() ([]byte, error) {
		return []byte("fixture checkpoint"), nil
	}}
	boundary, err := newNativeRollbackContainment(owner)
	require.NoError(t, err)
	require.ErrorIs(t, boundary.nativeCommitFailed(nil), errNativePersistenceReceipt)
	roots, outputs, err := boundary.nativeCommitReceipt()
	require.ErrorIs(t, err, errNativePersistenceReceipt)
	require.Nil(t, roots)
	require.Nil(t, outputs)
}

func TestQualLaneDRegistrationRefusesMissingLease(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lease *registrationNativeLease
	}{
		{name: "absent"},
		{name: "inactive", lease: &registrationNativeLease{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.ErrorIs(t, tc.lease.VerifyTransaction(nil, nil, nil, nil), vm.ErrDRWAExecution)
			require.ErrorIs(t, tc.lease.BindCall(nil), vm.ErrDRWAExecution)
			require.ErrorIs(t, tc.lease.VerifyCall(nil), vm.ErrDRWAExecution)
		})
	}
}

func TestQualLaneDRouteOperationRejectsMissingInput(t *testing.T) {
	op := &routeNativeOperation{name: "fixture", guard: &routeNativeGuard{}}
	gate := &routeNativeOperationGate{operation: op}
	require.ErrorIs(t, gate.CheckTransfer("different fixture", nil, nil, nil), errRouteNativeGuard)
	out, parsed, err := op.run(nil, nil, nil, nil)
	require.ErrorIs(t, err, process.ErrNilVmInput)
	require.Nil(t, out)
	require.Nil(t, parsed)
	out, parsed, err = op.run(nil, nil, nil, nil)
	require.ErrorIs(t, err, ErrExecutionClosed)
	require.Nil(t, out)
	require.Nil(t, parsed)
}

func TestQualLaneDPositionTransferRetainsAccountReadFailure(t *testing.T) {
	holder := bytes.Repeat([]byte{1}, len(core.SystemAccountAddress))
	readErr := errors.New("fixture account read failure")
	guard, accounts, err := newRouteNativeGuard(&statemock.AccountsStub{
		GetExistingAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			require.Equal(t, holder, address)
			return nil, readErr
		},
	})
	require.NoError(t, err)
	operation := &routeNativeOperation{guard: guard, accounts: accounts}
	position := &nativePositionTransfer{}
	require.ErrorIs(t, position.prepare(operation, nil, nil), errSetupLocalState)
	require.Empty(t, position.balances)
	balance, err := position.balance(operation, holder, 1)
	require.Nil(t, balance)
	require.ErrorIs(t, err, readErr)
	position.balances = []transferPositionBalance{{holder: holder, nonce: 1}}
	require.ErrorIs(t, position.finish(operation), readErr)
	require.ErrorIs(t, guard.finish(), readErr)
}

func TestQualLaneDPositionTransferRejectsNonUserAccount(t *testing.T) {
	holder := bytes.Repeat([]byte{1}, len(core.SystemAccountAddress))
	guard, accounts, err := newRouteNativeGuard(&statemock.AccountsStub{
		GetExistingAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
			require.Equal(t, holder, address)
			return &statemock.BaseAccountMock{AddressBytesField: address}, nil
		},
	})
	require.NoError(t, err)
	operation := &routeNativeOperation{guard: guard, accounts: accounts}
	position := &nativePositionTransfer{balances: []transferPositionBalance{{holder: holder, nonce: 1}}}
	balance, err := position.balance(operation, holder, 1)
	require.Nil(t, balance)
	require.ErrorIs(t, err, errSetupLocalState)
	require.ErrorIs(t, position.finish(operation), errSetupLocalState)
}

func TestQualLaneDCommitFailureRequiresAvailableNativeOwner(t *testing.T) {
	supplied := errors.New("inert commit cause")
	for _, tc := range []struct {
		name                   string
		owned, closed, running bool
		want                   error
	}{
		{name: "unowned", want: errNativePersistenceReceipt},
		{name: "closed", owned: true, closed: true, want: ErrExecutionClosed},
		{name: "busy", owned: true, running: true, want: ErrExecutionBusy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			boundary := &RollbackContainment{nativeOwned: tc.owned, closed: tc.closed, running: tc.running}
			err := boundary.nativeCommitFailed(supplied)
			require.ErrorIs(t, err, tc.want)
			require.NotErrorIs(t, err, supplied)
			require.Nil(t, boundary.failure)
		})
	}
}
