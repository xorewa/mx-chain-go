package systemSmartContracts

import (
	"bytes"
	"encoding/binary"
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
	"github.com/stretchr/testify/require"
)

// Independent field-1 protobuf vectors, not production codec output. Opaque
// authority/profile commitments and numeric limits are construction fixtures;
// neither admission nor expiry validation is claimed by this native binding.
func qualNativeIntentFrame(fields ...[]byte) []byte {
	var out []byte
	for _, field := range fields {
		var length [10]byte
		n := binary.PutUvarint(length[:], uint64(len(field)))
		out = append(out, 0x0a)
		out = append(out, length[:n]...)
		out = append(out, field...)
	}
	return out
}

// RG-01: CurrentRandomSeed is called by the real native identifier creator,
// after the identity read and before consumption. Alter only lifecycle status
// in the same real journal: body/digest equality must not mask cancellation.
func TestQualDRWANativeRegistrationIntentCancelledDuringCreation(t *testing.T) {
	e, ctx, s, _, _, request := qualNativeRegistration(t)
	owner, _, body, id, _ := qualNativeIntent(t, s, request)
	root, err := s.RootHash()
	require.NoError(t, err)
	called := 0
	ctx.blockChainHook.(*mock.BlockChainHookStub).CurrentRandomSeedCalled = func() []byte {
		called++
		account, readErr := s.GetExistingAccount(core.SystemAccountAddress)
		require.NoError(t, readErr)
		require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(
			append([]byte(core.ProtectedKeyPrefix+"DRWA@registration@intent@"), id...),
			qualNativeIntentFrame(body, []byte("CANCELLED"), nil)))
		require.NoError(t, s.SaveAccount(account))
		return []byte("registration-seed")
	}
	require.Error(t, e.registerDRWAIntentToken(owner, request))
	require.Equal(t, 1, called)
	require.Equal(t, 2, s.saves, "cancellation and native token save occur before the OPEN recheck")
	after, err := s.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
	require.Zero(t, s.JournalLen())
	require.Equal(t, qualNativeIntentFrame(body, []byte("OPEN"), nil),
		qualNativeRegistrationValue(t, s, core.SystemAccountAddress,
			append([]byte(core.ProtectedKeyPrefix+"DRWA@registration@intent@"), id...)))
	require.Equal(t, make([]byte, 8), qualNativeRegistrationValue(t, s, core.SystemAccountAddress,
		[]byte(core.ProtectedKeyPrefix+"DRWA@registry@count")))
	require.Empty(t, ctx.output)
	require.Empty(t, ctx.outputAccounts)
	require.Empty(t, ctx.logs)
	require.Empty(t, ctx.storageUpdate)
	require.Same(t, ctx, e.eei)
}

func qualNativeIntent(t *testing.T, s *qualDRWARegistrationStore, request drwaTokenCreation) (*drwa.RegistrationIntentOwner, *drwa.RollbackContainment, []byte, []byte, []byte) {
	t.Helper()
	body := qualNativeIntentFrame([]byte("n"), request.issuer, []byte("p"), []byte("1"), request.family,
		[]byte("profile"), []byte("name"), []byte("ticker"), []byte("properties"), []byte("schema"), []byte("admission"),
		qualNativeIntentFrame([]byte("authority-body")), qualNativeIntentFrame(bytes.Repeat([]byte{3}, 32)),
		[]byte("burn-and-retire"), []byte("network-profile"), []byte{0, 0, 0, 0, 0, 0, 0, 1})
	hash := blake2b.NewBlake2b()
	digest := hash.Compute(string(qualNativeIntentFrame([]byte("DRWA/BOOTSTRAP_INTENT_PAYLOAD/v1"), body)))
	id := hash.Compute(string(qualNativeIntentFrame([]byte("DRWA/BOOTSTRAP_INTENT/v1"), []byte("n"), request.issuer, []byte("p"), []byte("1"), digest)))
	account, err := s.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(append([]byte(core.ProtectedKeyPrefix+"DRWA@registration@intent@"), id...), qualNativeIntentFrame(body, []byte("OPEN"), nil)))
	require.NoError(t, s.SaveAccount(account))
	_, err = s.Commit()
	require.NoError(t, err)
	s.saves = 0
	registration, boundary, err := drwa.NewRegistryRegistration(s, &testscommon.ShardsCoordinatorMock{SelfIDCalled: func() uint32 { return core.MetachainShardId }}, 2)
	require.NoError(t, err)
	owner, err := registration.BindIntent(id, digest, request.manager, &marshal.GogoProtoMarshalizer{}, hash, 4096)
	require.NoError(t, err)
	return owner, boundary, body, id, digest
}

func TestQualDRWANativeRegistrationIntentFamilies(t *testing.T) {
	for _, family := range []string{core.FungibleESDT, core.NonFungibleESDTv2, core.SemiFungibleESDT, core.MetaESDT, core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT} {
		t.Run(family, func(t *testing.T) {
			e, ctx, s, _, _, request := qualNativeRegistration(t)
			request.family = []byte(family)
			if family != core.FungibleESDT {
				request.properties = append(request.properties, []byte(canTransferNFTCreateRole), []byte("true"))
			}
			owner, boundary, body, id, digest := qualNativeIntent(t, s, request)
			require.NoError(t, e.registerDRWAIntentToken(owner, request))
			require.Len(t, ctx.output, 1)
			token := bytes.Clone(ctx.output[0])
			roots, outputs, err := boundary.Commit()
			require.NoError(t, err)
			require.Len(t, outputs, 1)
			require.Equal(t, token, outputs[0].ReturnData[0])
			require.NoError(t, s.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
			native := &ESDTDataV2{}
			require.NoError(t, e.marshalizer.Unmarshal(native, qualNativeRegistrationValue(t, s, core.ESDTSCAddress, token)))
			require.Equal(t, request.manager, native.OwnerAddress)
			require.Equal(t, request.family, native.TokenType)
			require.Zero(t, native.MintedValue.Sign())
			require.Zero(t, native.BurntValue.Sign())
			require.Empty(t, native.SpecialRoles)
			require.Equal(t, family != core.FungibleESDT, native.CanTransferNFTCreateRole)
			for _, flag := range []bool{native.Upgradable, native.CanFreeze, native.CanWipe, native.CanPause, native.CanChangeOwner, native.CanCreateMultiShard, native.Mintable, native.Burnable} {
				require.False(t, flag)
			}
			require.True(t, native.CanAddSpecialRoles)
			for key, expected := range map[string][]byte{
				core.ProtectedKeyPrefix + "DRWA@registration@intent@" + string(id):        qualNativeIntentFrame(body, []byte("CONSUMED"), token),
				core.ProtectedKeyPrefix + "DRWA@registration@token@" + string(token):      qualNativeIntentFrame(token, id, digest, body, request.manager),
				core.ProtectedKeyPrefix + "DRWA@registration@activation@" + string(token): qualNativeIntentFrame(token, id, []byte("BootstrapDeny")),
				core.ProtectedKeyPrefix + "DRWA@registry@member@" + string(token):         {1},
				core.ProtectedKeyPrefix + "DRWA@registry@count":                           {0, 0, 0, 0, 0, 0, 0, 1},
			} {
				require.Equal(t, expected, qualNativeRegistrationValue(t, s, core.SystemAccountAddress, []byte(key)))
			}
			ctx.CleanCache()
			require.Error(t, e.registerDRWAIntentToken(owner, request), "closed candidate cannot create a second token")
			require.Empty(t, ctx.output)
			require.Empty(t, ctx.storageUpdate)
			require.Same(t, ctx, e.eei)
		})
	}
}

func TestQualDRWANativeRegistrationIntentIdentity(t *testing.T) {
	for _, field := range []string{"issuer", "manager", "family", "nil-owner", "typed-nil-owner"} {
		t.Run(field, func(t *testing.T) {
			e, ctx, s, _, _, request := qualNativeRegistration(t)
			owner, _, body, id, _ := qualNativeIntent(t, s, request)
			root, err := s.RootHash()
			require.NoError(t, err)
			var bound drwaIntentRegistrationOwner = owner
			switch field {
			case "issuer":
				request.issuer = bytes.Repeat([]byte{4}, 32)
			case "manager":
				request.manager = bytes.Repeat([]byte{4}, 32)
			case "family":
				request.family = []byte(core.NonFungibleESDTv2)
				request.properties = append(request.properties, []byte(canTransferNFTCreateRole), []byte("true"))
			case "nil-owner":
				bound = nil
			case "typed-nil-owner":
				var missing *drwa.RegistrationIntentOwner
				bound = missing
			}
			require.Error(t, e.registerDRWAIntentToken(bound, request))
			after, err := s.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
			require.Zero(t, s.saves)
			require.Zero(t, s.JournalLen())
			require.Equal(t, qualNativeIntentFrame(body, []byte("OPEN"), nil), qualNativeRegistrationValue(t, s, core.SystemAccountAddress, append([]byte(core.ProtectedKeyPrefix+"DRWA@registration@intent@"), id...)))
			require.Empty(t, ctx.output)
			require.Empty(t, ctx.outputAccounts)
			require.Empty(t, ctx.logs)
			require.Empty(t, ctx.storageUpdate)
			require.Same(t, ctx, e.eei)
		})
	}
}

func TestQualDRWANativeRegistrationIntentRollback(t *testing.T) {
	for _, fault := range []string{"token", "records", "registry", "rollback"} {
		t.Run(fault, func(t *testing.T) {
			e, ctx, s, _, _, request := qualNativeRegistration(t)
			owner, boundary, body, id, _ := qualNativeIntent(t, s, request)
			root, err := s.RootHash()
			require.NoError(t, err)
			original, rollback := errors.New("native bundle save fault"), errors.New("native bundle revert fault")
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
			err = e.registerDRWAIntentToken(owner, request)
			require.ErrorIs(t, err, original)
			if fault == "rollback" {
				require.ErrorIs(t, err, rollback)
				_, outputs, commitErr := boundary.Commit()
				require.Error(t, commitErr)
				require.Empty(t, outputs)
				require.NoError(t, boundary.Recover())
			}
			after, err := s.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
			require.Zero(t, s.JournalLen())
			require.Equal(t, qualNativeIntentFrame(body, []byte("OPEN"), nil), qualNativeRegistrationValue(t, s, core.SystemAccountAddress, append([]byte(core.ProtectedKeyPrefix+"DRWA@registration@intent@"), id...)))
			require.Equal(t, make([]byte, 8), qualNativeRegistrationValue(t, s, core.SystemAccountAddress, []byte(core.ProtectedKeyPrefix+"DRWA@registry@count")))
			require.Empty(t, ctx.output)
			require.Empty(t, ctx.outputAccounts)
			require.Empty(t, ctx.logs)
			require.Empty(t, ctx.storageUpdate)
			require.Same(t, ctx, e.eei)
		})
	}
}
