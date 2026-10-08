package systemSmartContracts

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type qualCommittedFixture struct {
	owner                                   *drwa.RegistrationIntentOwner
	boundary                                *drwa.RollbackContainment
	profile, bodyDigest, intent, id, digest []byte
}

// Healthy structural owner instrumentation: it delegates every argument to
// the real production owner/AccountsDB, and changes no result or expectation.
// Native fresh-context rejection must precede entry into that owner, just as
// registerDRWATokenLocked rejects before registration.RegisterToken.
type qualCommittedOwnerProbe struct {
	owner drwaCommittedRegistrationOwner
	calls int
}

func (o *qualCommittedOwnerProbe) IsInterfaceNil() bool { return o == nil }

func (o *qualCommittedOwnerProbe) RegisterTokenForCommittedCreation(issuer, manager, family,
	profile, name, ticker []byte, decimals uint32, bodyDigest []byte,
	create func(state.AccountsAdapter, []byte, []byte, []byte, []byte, []byte, uint32, [][]byte) ([]byte, *vmcommon.VMOutput, error)) error {
	o.calls++
	return o.owner.RegisterTokenForCommittedCreation(issuer, manager, family, profile, name, ticker, decimals, bodyDigest, create)
}

// Hand-assembled L41 native field-1 vectors, independent of the production
// frame/decoder. The native fixture uses NumDecimals=0 and manager=02*32;
// neither is an admitted network/profile value. No SUT generates commitments.
func qualCommittedIntent(t *testing.T, s *qualDRWARegistrationStore, request drwaTokenCreation) qualCommittedFixture {
	t.Helper()
	transfer := byte(1)
	if string(request.family) == core.FungibleESDT {
		transfer = 0
	}
	profile := qualNativeIntentFrame([]byte("DRWA/CREATION_PROFILE/v2"), []byte("n"), request.manager,
		request.family, []byte{0}, []byte{1}, []byte{0}, []byte{0}, []byte{0}, []byte{0}, []byte{0}, []byte{0}, []byte{0}, []byte{transfer})
	h := blake2b.NewBlake2b()
	ph := h.Compute(string(profile))
	name := h.Compute(string(qualNativeIntentFrame([]byte("DRWA/CREATION_NAME/v1"), request.name)))
	ticker := h.Compute(string(qualNativeIntentFrame([]byte("DRWA/CREATION_TICKER/v1"), request.ticker)))
	properties := h.Compute(string(qualNativeIntentFrame([]byte("DRWA/CREATION_PROPERTIES/v1"), ph, []byte{0, 0, 0, 0})))
	bodyDigest := h.Compute(string(qualNativeIntentFrame([]byte("DRWA/TOKEN_CREATION_BODY/v1"), request.family,
		ph, request.name, request.ticker, []byte{0, 0, 0, 0})))
	body := qualNativeIntentFrame([]byte("n"), request.issuer, []byte("p"), []byte("1"), request.family,
		ph, name, ticker, properties, []byte("schema"), []byte("admission"),
		qualNativeIntentFrame([]byte("authority-body")), qualNativeIntentFrame(bytes.Repeat([]byte{3}, 32)),
		[]byte("burn-and-retire"), []byte("network-profile"), []byte{0, 0, 0, 0, 0, 0, 0, 1})
	digest := h.Compute(string(qualNativeIntentFrame([]byte("DRWA/BOOTSTRAP_INTENT_PAYLOAD/v1"), body)))
	id := h.Compute(string(qualNativeIntentFrame([]byte("DRWA/BOOTSTRAP_INTENT/v1"), []byte("n"), request.issuer, []byte("p"), []byte("1"), digest)))
	a, err := s.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue(append([]byte(core.ProtectedKeyPrefix+"DRWA@registration@intent@"), id...), qualNativeIntentFrame(body, []byte("OPEN"), nil)))
	require.NoError(t, s.SaveAccount(a))
	_, err = s.Commit()
	require.NoError(t, err)
	s.saves = 0
	r, boundary, err := drwa.NewRegistryRegistration(s, &testscommon.ShardsCoordinatorMock{SelfIDCalled: func() uint32 { return core.MetachainShardId }}, 2)
	require.NoError(t, err)
	owner, err := r.BindIntent(id, digest, request.manager, &marshal.GogoProtoMarshalizer{}, h, 4096)
	require.NoError(t, err)
	return qualCommittedFixture{owner, boundary, profile, bodyDigest, body, id, digest}
}

func TestQualDRWANativeRegistrationCommittedFamilies(t *testing.T) {
	for _, family := range []string{core.FungibleESDT, core.NonFungibleESDTv2, core.SemiFungibleESDT, core.MetaESDT, core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT} {
		t.Run(family, func(t *testing.T) {
			e, ctx, s, _, _, request := qualNativeRegistration(t)
			request.family = []byte(family)
			request.properties = nil
			f := qualCommittedIntent(t, s, request)
			seeds := 0
			ctx.blockChainHook.(*mock.BlockChainHookStub).CurrentRandomSeedCalled = func() []byte {
				seeds++
				locked := e.mutExecution.TryLock()
				if locked {
					e.mutExecution.Unlock()
				}
				require.False(t, locked, "exclusive lock held through native creation")
				return []byte("registration-seed")
			}
			require.NoError(t, e.registerDRWACommittedToken(f.owner, request, f.profile, f.bodyDigest))
			require.Equal(t, 1, seeds)
			token := bytes.Clone(ctx.output[0])
			roots, outputs, err := f.boundary.Commit()
			require.NoError(t, err)
			require.Len(t, outputs, 1)
			require.Equal(t, token, outputs[0].ReturnData[0])
			require.NoError(t, s.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
			native := &ESDTDataV2{}
			require.NoError(t, e.marshalizer.Unmarshal(native, qualNativeRegistrationValue(t, s, core.ESDTSCAddress, token)))
			require.Equal(t, request.name, native.TokenName)
			require.Equal(t, request.ticker, native.TickerName)
			require.Equal(t, request.family, native.TokenType)
			require.Equal(t, request.manager, native.OwnerAddress)
			require.Equal(t, uint32(0), native.NumDecimals)
			require.True(t, native.CanAddSpecialRoles)
			require.Equal(t, family != core.FungibleESDT, native.CanTransferNFTCreateRole)
			for _, v := range []bool{native.Upgradable, native.CanFreeze, native.CanWipe, native.CanPause, native.CanChangeOwner, native.CanCreateMultiShard, native.Mintable, native.Burnable} {
				require.False(t, v)
			}
			require.Zero(t, native.MintedValue.Sign())
			require.Zero(t, native.BurntValue.Sign())
			require.Empty(t, native.SpecialRoles)
			for key, want := range map[string][]byte{
				core.ProtectedKeyPrefix + "DRWA@registration@intent@" + string(f.id):      qualNativeIntentFrame(f.intent, []byte("CONSUMED"), token),
				core.ProtectedKeyPrefix + "DRWA@registration@token@" + string(token):      qualNativeIntentFrame(token, f.id, f.digest, f.intent, request.manager),
				core.ProtectedKeyPrefix + "DRWA@registration@activation@" + string(token): qualNativeIntentFrame(token, f.id, []byte("BootstrapDeny")),
				core.ProtectedKeyPrefix + "DRWA@registry@member@" + string(token):         {1}, core.ProtectedKeyPrefix + "DRWA@registry@count": {0, 0, 0, 0, 0, 0, 0, 1},
			} {
				require.Equal(t, want, qualNativeRegistrationValue(t, s, core.SystemAccountAddress, []byte(key)))
			}
		})
	}
}

func TestQualDRWANativeRegistrationCommittedDenial(t *testing.T) {
	for _, fault := range []string{"name", "ticker", "decimals", "body", "profile", "issuer", "manager", "family", "raw-properties", "nil-owner", "typed-nil", "context", "storage", "accounts", "output", "logs"} {
		t.Run(fault, func(t *testing.T) {
			e, ctx, s, _, _, request := qualNativeRegistration(t)
			request.properties = nil
			f := qualCommittedIntent(t, s, request)
			probe := &qualCommittedOwnerProbe{owner: f.owner}
			var owner drwaCommittedRegistrationOwner = probe
			switch fault {
			case "name":
				request.name = []byte("OtherName")
			case "ticker":
				request.ticker = []byte("OTHER")
			case "decimals":
				request.decimals = 1
			case "body":
				f.bodyDigest[0] ^= 1
			case "profile":
				f.profile[0] ^= 1
			case "issuer":
				request.issuer[0] ^= 1
			case "manager":
				request.manager[0] ^= 1
			case "family":
				request.family = []byte(core.NonFungibleESDTv2)
			case "raw-properties":
				request.properties = [][]byte{[]byte(canFreeze), []byte("true")}
			case "nil-owner":
				owner = nil
			case "typed-nil":
				var missing *drwa.RegistrationIntentOwner
				owner = missing
			case "context":
				e.eei = nil
			case "storage":
				ctx.SetStorage([]byte("prior"), []byte{1})
			case "accounts":
				ctx.outputAccounts["prior"] = &vmcommon.OutputAccount{Address: []byte("prior")}
			case "output":
				ctx.Finish([]byte("prior"))
			case "logs":
				ctx.logs = append(ctx.logs, &vmcommon.LogEntry{Identifier: []byte("prior")})
			}
			beforeStorage, beforeAccounts, beforeOutput, beforeLogs := ctx.storageUpdate, ctx.outputAccounts, ctx.output, ctx.logs
			seed := 0
			ctx.blockChainHook.(*mock.BlockChainHookStub).CurrentRandomSeedCalled = func() []byte { seed++; return []byte("registration-seed") }
			root, err := s.RootHash()
			require.NoError(t, err)
			require.Error(t, e.registerDRWACommittedToken(owner, request, f.profile, f.bodyDigest))
			after, err := s.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
			require.Zero(t, s.JournalLen())
			require.Zero(t, s.saves)
			require.Zero(t, seed)
			switch fault {
			case "raw-properties", "nil-owner", "typed-nil", "context", "storage", "accounts", "output", "logs":
				require.Zero(t, probe.calls, "fresh native context required BEFORE entering the real T04 owner")
			default:
				require.Equal(t, 1, probe.calls)
			}
			require.Equal(t, beforeStorage, ctx.storageUpdate)
			require.Equal(t, beforeAccounts, ctx.outputAccounts)
			require.Equal(t, beforeOutput, ctx.output)
			require.Equal(t, beforeLogs, ctx.logs)
		})
	}
}

func TestQualDRWANativeRegistrationCommittedRollbackAndCancellation(t *testing.T) {
	for _, fault := range []string{"token", "records", "registry", "rollback", "cancelled"} {
		t.Run(fault, func(t *testing.T) {
			e, ctx, s, _, _, request := qualNativeRegistration(t)
			request.properties = nil
			f := qualCommittedIntent(t, s, request)
			root, err := s.RootHash()
			require.NoError(t, err)
			original, rollback := errors.New("committed creation save fault"), errors.New("committed creation undo fault")
			if fault != "cancelled" {
				s.saveFault = original
				s.failAt = 1
				if fault == "records" {
					s.failAt = 2
				}
				if fault == "registry" {
					s.failAt = 3
				}
				if fault == "rollback" {
					s.rollbackFault = rollback
				}
			}
			if fault == "cancelled" {
				ctx.blockChainHook.(*mock.BlockChainHookStub).CurrentRandomSeedCalled = func() []byte {
					a, err := s.GetExistingAccount(core.SystemAccountAddress)
					require.NoError(t, err)
					require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue(append([]byte(core.ProtectedKeyPrefix+"DRWA@registration@intent@"), f.id...), qualNativeIntentFrame(f.intent, []byte("CANCELLED"), nil)))
					require.NoError(t, s.SaveAccount(a))
					return []byte("registration-seed")
				}
			}
			err = e.registerDRWACommittedToken(f.owner, request, f.profile, f.bodyDigest)
			require.Error(t, err)
			if fault != "cancelled" {
				require.ErrorIs(t, err, original)
			} else {
				require.Equal(t, 2, s.saves)
			}
			if fault == "rollback" {
				require.ErrorIs(t, err, rollback)
				_, out, err := f.boundary.Commit()
				require.Error(t, err)
				require.Empty(t, out)
				require.NoError(t, f.boundary.Recover())
			}
			after, err := s.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
			require.Zero(t, s.JournalLen())
			require.Equal(t, qualNativeIntentFrame(f.intent, []byte("OPEN"), nil), qualNativeRegistrationValue(t, s, core.SystemAccountAddress, append([]byte(core.ProtectedKeyPrefix+"DRWA@registration@intent@"), f.id...)))
			require.Empty(t, ctx.output)
			require.Empty(t, ctx.outputAccounts)
			require.Empty(t, ctx.logs)
			require.Empty(t, ctx.storageUpdate)
			require.Same(t, ctx, e.eei)
		})
	}
}

func TestQualDRWANativeRegistrationCommittedPrivateTuple(t *testing.T) {
	e, ctx, s, _, _, request := qualNativeRegistration(t)
	request.properties = nil
	f := qualCommittedIntent(t, s, request)
	expectedName, expectedTicker, expectedManager := bytes.Clone(request.name), bytes.Clone(request.ticker), bytes.Clone(request.manager)
	ctx.blockChainHook.(*mock.BlockChainHookStub).CurrentRandomSeedCalled = func() []byte {
		for _, v := range [][]byte{request.issuer, request.manager, request.family, request.name, request.ticker, f.profile, f.bodyDigest} {
			v[0] ^= 1
		}
		return []byte("registration-seed")
	}
	require.NoError(t, e.registerDRWACommittedToken(f.owner, request, f.profile, f.bodyDigest))
	token := ctx.output[0]
	native := &ESDTDataV2{}
	require.NoError(t, e.marshalizer.Unmarshal(native, qualNativeRegistrationValue(t, s, core.ESDTSCAddress, token)))
	require.Equal(t, expectedName, native.TokenName)
	require.Equal(t, expectedTicker, native.TickerName)
	require.Equal(t, expectedManager, native.OwnerAddress)
	require.Equal(t, []byte(core.FungibleESDT), native.TokenType)
	_, out, err := f.boundary.Commit()
	require.NoError(t, err)
	require.Len(t, out, 1)
}
