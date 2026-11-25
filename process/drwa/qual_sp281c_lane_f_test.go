package drwa

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	vmMock "github.com/multiversx/mx-chain-vm-common-go/mock"
	"github.com/stretchr/testify/require"
)

func TestQualSP281CLaneFSetupRejectsInvalidBoundsAndLeavesNoEffects(t *testing.T) {
	f, initializer, host := qualSetupNew(t, uint32(core.Fungible), false, true)
	reader, err := newSetupLocalStateReader(f.r, &qualLocalSetupHost{t: t, f: f}, 0)
	require.ErrorIs(t, err, errSetupLocalState)
	require.Nil(t, reader)
	wrong, err := newSetupInitialization(f.r, host, 0)
	require.ErrorIs(t, err, errSetupInitialization)
	require.Nil(t, wrong)
	_, err = (*setupLocalStateReader)(nil).withInitializedState(nil, nil, 0, nil, nil)
	require.ErrorIs(t, err, errSetupLocalState)
	require.Zero(t, host.reserves)
	require.Empty(t, host.rootCalls)

	records := initializer.records
	key, err := records.outerKey(supplyStatePrefix, []byte("not-a-token"))
	require.ErrorIs(t, err, errSupplyPositionRecord)
	require.Nil(t, key)
	key, err = records.outerKey(string(bytes.Repeat([]byte{'p'}, records.codec.maxBytes)), []byte("TOKEN-abcdef"))
	require.ErrorIs(t, err, errSupplyPositionRecord)
	require.Nil(t, key)
	raw, err := records.encodeSupplyRecord(&initializedSupplyState{token: []byte("TOKEN-abcdef"), family: core.Fungible})
	require.ErrorIs(t, err, errSupplyPositionRecord)
	require.Nil(t, raw)
}

func TestQualSP281CLaneFNativeBalanceObservationRefusesInconsistentInputs(t *testing.T) {
	// An inert native account from the existing setup fixture. The reader
	// below supplies only an observation and has no persistence callback.
	f, _, _ := qualSetupNew(t, uint32(core.Fungible), false, true)
	stateAccount, err := f.r.current.codec.state.systemAccount()
	require.NoError(t, err)
	account, ok := stateAccount.(vmcommon.UserAccountHandler)
	require.True(t, ok)
	token := []byte("TOKEN-abcdef")
	key := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), token...)
	readErr := errors.New("inert native read failure")
	firstErr := errors.New("inert first recorded native failure")
	for _, tc := range []struct {
		name              string
		record            *esdt.ESDigitalToken
		missing           bool
		read, first, want error
	}{
		{name: "present", record: &esdt.ESDigitalToken{Type: uint32(core.Fungible), Value: big.NewInt(7)}},
		{name: "read-error", read: readErr, want: readErr},
		{name: "first-error", read: readErr, first: firstErr, want: firstErr},
		{name: "nil-observation", want: errSetupLocalState},
		{name: "missing-nonzero", missing: true, record: &esdt.ESDigitalToken{Value: big.NewInt(1)}, want: errSetupLocalState},
		{name: "wrong-family", record: &esdt.ESDigitalToken{Type: uint32(core.SemiFungible), Value: big.NewInt(1)}, want: errSetupLocalState},
		{name: "oversized", record: &esdt.ESDigitalToken{Value: big.NewInt(256)}, want: errSetupLocalState},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storage := &vmMock.ESDTNFTStorageHandlerStub{GetESDTNFTTokenOnDestinationCalled: func(got vmcommon.UserAccountHandler, gotKey []byte, nonce uint64) (*esdt.ESDigitalToken, bool, error) {
				require.Same(t, account, got)
				require.Equal(t, key, gotKey)
				require.Zero(t, nonce)
				return tc.record, tc.missing, tc.read
			}}
			balance, err := nativePositionBalance(storage, &routeNativeGuard{first: tc.first}, account, token, core.Fungible, 0, 1)
			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
				require.Nil(t, balance)
				return
			}
			require.NoError(t, err)
			balance.SetInt64(9)
			require.Equal(t, big.NewInt(7), tc.record.Value)
		})
	}
	balance, err := nativePositionBalance(nil, &routeNativeGuard{}, account, token, core.Fungible, 0, 1)
	require.ErrorIs(t, err, errSetupLocalState)
	require.Nil(t, balance)
}

func TestQualSP281CLaneFPositionWriterRefusesUnboundPredecessor(t *testing.T) {
	w := qualOwnedSupplyNew(t, core.Fungible)
	w.begin(t)
	records := w.reader.records
	_, positionKey := qualSetupKeys()
	raw := w.read(t, positionKey)
	position, err := records.decodePositionRecord(raw)
	require.NoError(t, err)
	key, err := records.positionKey(w.token, core.Fungible, 0, w.origin)
	require.NoError(t, err)
	local := localSetupState{positions: position, positionRaw: raw}
	invalidPredecessor := local
	invalidPredecessor.positionRaw = []byte("synthetic foreign predecessor")
	noChange := []positionLeafChange{{key: key}}
	require.ErrorIs(t, records.writePositionMap(nil, local, noChange, 1, &w.leafVersion), errSetupLocalState)
	require.Error(t, records.writePositionMap(w.db, invalidPredecessor, noChange, 1, &w.leafVersion))
	require.ErrorIs(t, records.writePositionMap(w.db, local, []positionLeafChange{{key: []byte("foreign")}}, 1, &w.leafVersion), errSetupLocalState)
	require.Equal(t, raw, w.read(t, positionKey))
}

func TestQualSP281CLaneFInitialAppointmentMustDecodeBeforeProducingWrite(t *testing.T) {
	f := qualScopedNew(t)
	records := f.records
	body := &authorityBodyCodec{source: records.codec}
	approval := &registrationApprovalCodec{source: records.codec}
	before := f.store.JournalLen()
	write, err := records.prepareInitialPurposePair(f.context, f.d.owner, []byte("malformed"),
		[][]byte{f.d.program, {1}, {2}}, [][]byte{{3}, {4}}, body, approval, []byte("admission"), []byte("independent"))
	require.ErrorIs(t, err, errInvalidRegistrationRecord)
	require.Nil(t, write)
	require.Equal(t, before, f.store.JournalLen())
}

func TestQualSP281CLaneFOwnedSupplyRequiresJournalOwner(t *testing.T) {
	reader := qualOwnedSupplyNew(t, core.Fungible).reader
	for _, operation := range []*supplyNativeOperation{nil, {}} {
		out, err := operation.executeOwned(nil, reader, nil, nil, nil, nil, supplyWriteBinding{})
		require.ErrorIs(t, err, errSupplyAccounting)
		require.Nil(t, out)
	}
}

func TestQualSP281CLaneFSupplyWriteRefusesUnmatchedEffectsAndSuccessors(t *testing.T) {
	for _, family := range []core.ESDTType{core.Fungible, core.SemiFungible} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			w := qualOwnedSupplyNew(t, family)
			w.begin(t)
			supplyKey, positionKey := qualSetupKeys()
			beforeSupply, beforePosition := w.read(t, supplyKey), w.read(t, positionKey)
			account, err := w.db.GetExistingAccount(w.origin)
			require.NoError(t, err)
			origin := account.(vmcommon.UserAccountHandler)
			readerErr := errors.New("inert origin balance read failure")
			balance := int64(0)
			var observeErr error
			var nonce uint64
			var previous uint64
			name := core.BuiltInFunctionESDTLocalBurn
			if family != core.Fungible {
				name, nonce, previous = core.BuiltInFunctionESDTNFTCreate, 3, 1
			}
			o := &supplyNativeOperation{name: name, guard: &routeNativeGuard{},
				storage: &vmMock.ESDTNFTStorageHandlerStub{
					GetESDTNFTTokenOnDestinationCalled: func(got vmcommon.UserAccountHandler, _ []byte, gotNonce uint64) (*esdt.ESDigitalToken, bool, error) {
						require.Same(t, origin, got)
						require.Equal(t, nonce, gotNonce)
						return &esdt.ESDigitalToken{Type: uint32(family), Value: big.NewInt(balance)}, false, observeErr
					},
				}}
			positions, err := w.reader.records.decodePositionRecord(beforePosition)
			require.NoError(t, err)
			write := &supplyNativeWrite{reader: w.reader, db: w.db, local: localSetupState{
				supply: w.recordsSupply(t), positions: positions, supplyRaw: beforeSupply, positionRaw: beforePosition,
			}}
			if family == core.Fungible {
				// An aggregate containing one unit does not prove this origin has it.
				write.local.supply.accounting = &supplyAccounting{cumulativeIssued: big.NewInt(1), liveSupply: big.NewInt(1)}
			}
			effect := vmcommon.DRWASupplyEffect{TokenIdentifier: w.token, RoleAddress: w.origin, TokenType: uint32(family),
				Nonce: nonce, PreviousNonce: previous, Quantity: big.NewInt(1)}
			mismatched := effect
			mismatched.RoleAddress = []byte("another origin")
			require.ErrorIs(t, write.prepare(o, origin, mismatched), errSupplyAccounting)
			require.ErrorIs(t, write.prepare(o, origin, effect), errSupplyAccounting)
			write.binding.leafVersion = &w.leafVersion
			observeErr = readerErr
			require.ErrorIs(t, write.prepare(o, origin, effect), readerErr)
			observeErr = nil
			if family != core.Fungible {
				next := *write.local.supply
				require.Error(t, write.stageNonceSupply(name, next), "nonce zero is not a nonce-family leaf")
			}
			require.ErrorIs(t, write.prepare(o, origin, effect), errSupplyAccounting,
				"zero cannot fund a burn and nonce three cannot follow nonce one")

			write.effect = effect
			write.supplyKey = supplyKey
			write.expectedOriginBalance = big.NewInt(1)
			out := &vmcommon.VMOutput{ReturnData: [][]byte{{byte(nonce)}}}
			observeErr = readerErr
			require.ErrorIs(t, write.finish(o, origin, out), readerErr)
			observeErr = nil
			require.ErrorIs(t, write.finish(o, origin, out), errSupplyAccounting)
			balance = 1
			if family != core.Fungible {
				require.ErrorIs(t, write.finish(o, origin, &vmcommon.VMOutput{ReturnData: [][]byte{{1}}}), errSupplyAccounting)
			}
			write.successor = []byte("unpublished successor")
			require.ErrorIs(t, write.finish(o, origin, out), errSupplyAccounting)
			write.successor = beforeSupply
			write.local.positions = nil
			require.NoError(t, write.finish(o, origin, out))
			require.Equal(t, beforeSupply, w.read(t, supplyKey))
			require.Equal(t, beforePosition, w.read(t, positionKey))
		})
	}
}

func TestQualSP281CLaneFSetupMemberUnavailableIsNotAbsent(t *testing.T) {
	_, position := qualSetupKeys()
	readFailure := errors.New("inert protected member lookup failure")
	account := &stateMock.UserAccountStub{Address: core.SystemAccountAddress, RetrieveValueCalled: func(key []byte) ([]byte, uint32, error) {
		require.Equal(t, position, key)
		return nil, 0, readFailure
	}}
	accounts := &stateMock.AccountsStub{}
	reader := &setupLocalStateReader{current: &currentLifecycleReader{current: &currentLocalDependencies{
		codec: &registrationRecords{state: &protectedState{accounts: accounts}},
	}}}
	accounts.GetExistingAccountCalled = func(addr []byte) (vmcommon.AccountHandler, error) {
		require.Equal(t, core.SystemAccountAddress, addr)
		return nil, readFailure
	}
	raw, err := reader.readMember(position, false)
	require.ErrorIs(t, err, readFailure)
	require.Nil(t, raw)
	accounts.GetExistingAccountCalled = func([]byte) (vmcommon.AccountHandler, error) { return account, nil }
	raw, err = reader.readMember(position, false)
	require.ErrorIs(t, err, readFailure)
	require.Nil(t, raw)
	account.RetrieveValueCalled = func([]byte) ([]byte, uint32, error) { return nil, 0, nil }
	raw, err = reader.readMember(position, false)
	require.NoError(t, err)
	require.Nil(t, raw)
}

func TestQualSP281CLaneFSetupBoundsDoNotPermitPartialInitialization(t *testing.T) {
	supply, position := qualSetupKeys()
	for _, max := range []int{len(supply) - 1, len(position) - 1} {
		t.Run(fmt.Sprint(max), func(t *testing.T) {
			f, init, host := qualSetupNew(t, uint32(core.Fungible), true, true)
			// The lifecycle codec remains valid. Only the dependent state
			// writer/reader is presented with an insufficient byte limit.
			limited := *init.records.codec
			limited.maxBytes = max
			rootCodec := *init.records
			rootCodec.codec = &limited
			init.records = &rootCodec
			require.ErrorIs(t, qualSetupExecute(f, init), errSupplyPositionRecord)
			require.Zero(t, host.reserves)
			require.Empty(t, host.rootCalls)
			require.Empty(t, qualActivationValue(t, f.x.f.store, supply))
			require.Empty(t, qualActivationValue(t, f.x.f.store, position))

			reader := &setupLocalStateReader{current: f.r, records: &rootCodec}
			err := qualLocalSetupRead(f, reader,
				func(lifecycleReadView, localSetupState) (*vmcommon.VMOutput, error) {
					t.Fatal("invalid scope must not invoke the initialized-state consumer")
					return nil, nil
				})
			require.ErrorIs(t, err, errSupplyPositionRecord)
		})
	}
}

func TestQualSP281CLaneFInitialPairRequiresLiveEvaluatedTime(t *testing.T) {
	f, original, args, proofs, bodies, approval := qualInitialPair(t)
	before := f.store.JournalLen()
	mandates := f.mandates.calls
	write, err := f.records.prepareInitialPurposePair(nil, f.d.owner, original,
		args, proofs, bodies, approval, []byte("admission\x00opaque"), []byte("independent\xc3\xa9"))
	require.NoError(t, err)
	require.NotNil(t, write)
	out, err := write()
	require.ErrorIs(t, err, errScopedAdmission)
	require.Nil(t, out)
	require.Equal(t, before, f.store.JournalLen())
	require.Equal(t, mandates, f.mandates.calls)
}

func TestQualSP281CLaneFFungibleSupplyRequiresReadableExactPredecessor(t *testing.T) {
	w := qualOwnedSupplyNew(t, core.Fungible)
	w.begin(t)
	supplyKey, positionKey := qualSetupKeys()
	supplyRaw, positionRaw := w.read(t, supplyKey), w.read(t, positionKey)
	supply := w.recordsSupply(t)
	positions, err := w.reader.records.decodePositionRecord(positionRaw)
	require.NoError(t, err)
	origin, err := w.db.GetExistingAccount(w.origin)
	require.NoError(t, err)
	op, err := newSupplyNativeOperation(w.args, core.BuiltInFunctionESDTLocalMint)
	require.NoError(t, err)
	effect := vmcommon.DRWASupplyEffect{TokenIdentifier: w.token, RoleAddress: w.origin,
		TokenType: uint32(core.Fungible), Quantity: big.NewInt(1)}
	refusal := errors.New("inert protected account read failure")
	for _, tc := range []struct {
		name string
		want error
	}{
		{"stale predecessor", errSupplyAccounting},
		{"account unavailable", refusal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local := localSetupState{supply: supply, positions: positions, supplyRaw: supplyRaw, positionRaw: positionRaw}
			reader := w.reader
			if tc.want == refusal {
				readerCopy := *w.reader
				records := *w.reader.records
				codec := *records.codec
				codec.state = &protectedState{accounts: &stateMock.AccountsStub{
					GetExistingAccountCalled: func(addr []byte) (vmcommon.AccountHandler, error) {
						require.Equal(t, core.SystemAccountAddress, addr)
						return nil, refusal
					},
				}}
				records.codec = &codec
				readerCopy.records = &records
				reader = &readerCopy
			} else {
				local.supplyRaw = append(bytes.Clone(supplyRaw), 0)
			}
			write := &supplyNativeWrite{reader: reader, db: w.db, local: local,
				binding: supplyWriteBinding{leafVersion: &w.leafVersion}}
			journal := w.db.JournalLen()
			err := w.owner.executeOwned(func(owner *rollbackOperation) ([]*vmcommon.VMOutput, error) {
				return nil, owner.withWrite(w.owner, w.db, func() error {
					return write.prepare(op, origin.(vmcommon.UserAccountHandler), effect)
				})
			})
			require.ErrorIs(t, err, tc.want)
			require.Empty(t, write.successor)
			require.Equal(t, journal, w.db.JournalLen())
			require.Equal(t, supplyRaw, w.read(t, supplyKey))
			require.Equal(t, positionRaw, w.read(t, positionKey))
		})
	}
}

func TestQualSP281CLaneFNonceSupplyRejectsWrongVersionOrMalformedPreviousLeaf(t *testing.T) {
	w := qualOwnedSupplyNew(t, core.SemiFungible)
	w.begin(t)
	mint := w.input(core.BuiltInFunctionESDTNFTCreate, w.origin, w.origin, w.token,
		[]byte{5}, []byte("name"), nil, nil, nil, []byte("uri"))
	require.NoError(t, w.supply(t, mint, 0, nil))

	records := w.reader.records
	supplyKey, positionKey := qualSetupKeys()
	prior := w.recordsSupply(t)
	key, err := records.nonceKey(w.token, core.SemiFungible, 1)
	require.NoError(t, err)
	attempt := func(version core.TrieNodeVersion, want error) {
		t.Helper()
		beforeSupply, beforePosition := w.read(t, supplyKey), w.read(t, positionKey)
		journal := w.db.JournalLen()
		write := &supplyNativeWrite{reader: w.reader, db: w.db, supplyKey: supplyKey,
			local: localSetupState{supplyRaw: beforeSupply}, binding: supplyWriteBinding{leafVersion: &version},
			effect: vmcommon.DRWASupplyEffect{Nonce: 1, Quantity: big.NewInt(1)}}
		err := w.owner.executeOwned(func(owner *rollbackOperation) ([]*vmcommon.VMOutput, error) {
			return nil, owner.withWrite(w.owner, w.db, func() error {
				return write.stageNonceSupply(core.BuiltInFunctionESDTNFTAddQuantity, *prior)
			})
		})
		require.ErrorIs(t, err, want)
		require.Empty(t, write.successor)
		require.Equal(t, journal, w.db.JournalLen())
		require.Equal(t, beforeSupply, w.read(t, supplyKey))
		require.Equal(t, beforePosition, w.read(t, positionKey))
	}
	require.Equal(t, core.NotSpecified, w.leafVersion)
	attempt(core.AutoBalanceEnabled, errSupplyAccounting)

	malformed := []byte{0}
	require.NoError(t, w.owner.executeOwned(func(owner *rollbackOperation) ([]*vmcommon.VMOutput, error) {
		predecessor := w.read(t, supplyKey)
		return nil, owner.withWrite(w.owner, w.db, func() error {
			_, err := w.db.StageDerivedProtectedChildTrie(core.SystemAccountAddress, supplyKey, predecessor, [][]byte{key},
				func(previous []core.TrieData) ([]core.TrieData, error) {
					require.Len(t, previous, 1)
					require.Equal(t, w.leafVersion, previous[0].Version)
					require.NotEmpty(t, previous[0].Value)
					return []core.TrieData{{Key: key, Value: malformed, Version: w.leafVersion}}, nil
				}, func(root []byte) ([]byte, error) {
					next := *prior
					next.nonceRoot = root
					return records.encodeSupplyRecord(&next)
				})
			return err
		})
	}))
	attempt(w.leafVersion, errInvalidRegistrationRecord)
}
