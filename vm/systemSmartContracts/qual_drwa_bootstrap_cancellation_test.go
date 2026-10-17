package systemSmartContracts

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// R7: native creator, reader, AccountsDB and T04 are real; lawful authority,
// canonical distributed no-effect proof and this package's clock are synthetic.
// The process/drwa companion uses the native hook and real purpose signatures.
type qualT46NativeVerifier struct {
	subject []byte
	hook    func(string)
	calls   int
}

func (v *qualT46NativeVerifier) IsInterfaceNil() bool { return v == nil }
func (v *qualT46NativeVerifier) VerifyBootstrapCancellation(p string, subject, proof []byte, at drwa.HeaderMilliseconds, epoch uint32) error {
	v.calls++
	if at != 100 || epoch != 10 || !bytes.Equal(subject, v.subject) || !bytes.Equal(proof, []byte(p)) {
		return errors.New("synthetic T46 semantic host denied")
	}
	if v.hook != nil {
		v.hook(p)
	}
	return nil
}

type qualT46NativeFixture struct {
	e             *esdt
	ctx           *vmContext
	s             *qualDRWARegistrationStore
	f             qualCommittedFixture
	c             *drwa.RegistrationCancellation
	v             *qualT46NativeVerifier
	token, native []byte
}

func qualT46Native(t *testing.T, family string) *qualT46NativeFixture {
	t.Helper()
	e, ctx, s, _, _, request := qualNativeRegistration(t)
	request.family, request.properties = []byte(family), nil
	f := qualCommittedIntent(t, s, request)
	admit, _ := qualEndpointAdmission(t, e, &f, s)
	code, err := e.registerDRWATokenEndpoint(admit, qualEndpointInput(e, f, request), request, f.profile)
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, code)
	token := bytes.Clone(ctx.output[0])
	_, _, err = f.boundary.Commit()
	require.NoError(t, err)
	ctx.CleanStorageUpdates()
	ctx.outputAccounts = make(map[string]*vmcommon.OutputAccount)
	ctx.output = nil
	ctx.logs = nil
	r, b, err := drwa.NewRegistryRegistration(s, &testscommon.ShardsCoordinatorMock{SelfIDCalled: func() uint32 { return core.MetachainShardId }}, 2)
	require.NoError(t, err)
	f.owner, err = r.BindIntent(f.id, f.digest, request.manager, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
	require.NoError(t, err)
	f.boundary = b
	flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
	flags.IsFlagEnabledInEpochCalled = func(flag core.EnableEpochFlag, epoch uint32) bool { return flag != common.SupernovaFlag || epoch >= 10 }
	clock, err := drwa.NewEvaluatedHeaderTime(flags, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b())
	require.NoError(t, err)
	context, err := clock.Begin(&block.MetaBlockV3{Epoch: 10, TimestampMs: 100})
	require.NoError(t, err)
	t.Cleanup(func() { clock.End(context) })
	native := bytes.Clone(qualNativeRegistrationValue(t, s, core.ESDTSCAddress, token))
	subject := qualNativeIntentFrame([]byte("DRWA/BOOTSTRAP_CANCEL/candidate1"), []byte("n"), token, f.id, f.digest, f.intent, request.manager, native, []byte("NATIVE_BOOTSTRAP_STATE"), binary.BigEndian.AppendUint64(nil, 100), binary.BigEndian.AppendUint32(nil, 10))
	v := &qualT46NativeVerifier{subject: subject}
	c, err := f.owner.WithBootstrapCancellation(&qualEndpointTime{clock, s}, []byte("n"), 10, drwa.RegistrationResourceLimits{Records: 1000, RetainedBytes: 1048576, NewRecordsPerEpoch: 100}, v)
	require.NoError(t, err)
	return &qualT46NativeFixture{e, ctx, s, f, c, v, token, native}
}
func (x *qualT46NativeFixture) cancel() error {
	return x.e.cancelDRWABootstrapToken(x.c, x.token, x.f.id, []byte("PROGRAM_ADMINISTRATION"), []byte("BOOTSTRAP_CANCEL"), []byte("NATIVE_BOOTSTRAP_STATE"))
}
func TestQualDRWAT46NativeCancellationFamilies(t *testing.T) {
	for _, family := range []string{core.FungibleESDT, core.NonFungibleESDTv2, core.SemiFungibleESDT, core.MetaESDT, core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT} {
		t.Run(family, func(t *testing.T) {
			x := qualT46Native(t, family)
			retained := make(map[string][]byte)
			for _, key := range []string{core.ProtectedKeyPrefix + "DRWA@registration@intent@" + string(x.f.id), core.ProtectedKeyPrefix + "DRWA@registration@token@" + string(x.token), core.ProtectedKeyPrefix + "DRWA@registry@member@" + string(x.token), core.ProtectedKeyPrefix + "DRWA@registry@count"} {
				retained[key] = bytes.Clone(qualNativeRegistrationValue(t, x.s, core.SystemAccountAddress, []byte(key)))
			}
			x.v.hook = func(string) {
				locked := x.e.mutExecution.TryLock()
				if locked {
					x.e.mutExecution.Unlock()
				}
				require.False(t, locked, "exclusive native lock held")
			}
			require.NoError(t, x.cancel())
			require.Same(t, x.ctx, x.e.eei)
			key := []byte(core.ProtectedKeyPrefix + "DRWA@registration@activation@" + string(x.token))
			want := qualNativeIntentFrame(x.token, x.f.id, []byte("RetiredDeny"), x.native, []byte("NATIVE_BOOTSTRAP_STATE"), []byte("PROGRAM_ADMINISTRATION"), []byte("BOOTSTRAP_CANCEL"))
			require.Equal(t, want, qualNativeRegistrationValue(t, x.s, core.SystemAccountAddress, key))
			require.Equal(t, x.native, qualNativeRegistrationValue(t, x.s, core.ESDTSCAddress, x.token))
			for k, v := range retained {
				require.Equal(t, v, qualNativeRegistrationValue(t, x.s, core.SystemAccountAddress, []byte(k)))
			}
			require.Empty(t, x.ctx.storageUpdate)
			require.Empty(t, x.ctx.outputAccounts)
			require.Empty(t, x.ctx.output)
			require.Empty(t, x.ctx.logs)
			roots, out, err := x.f.boundary.Commit()
			require.NoError(t, err)
			require.Len(t, out, 1)
			require.Nil(t, out[0], "state-only action retains no VM output")
			require.NoError(t, x.s.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
			require.Equal(t, want, qualNativeRegistrationValue(t, x.s, core.SystemAccountAddress, key))
			require.Error(t, x.cancel())
		})
	}
}
func TestQualDRWAT46NativeCancellationDenials(t *testing.T) {
	for _, fault := range []string{"missing", "malformed", "minted", "burnt", "net-zero-history", "negative", "roles", "paused", "nft-stopped", "wiped", "manager", "family", "foreign-store", "save", "rollback", "verifier-storage", "verifier-accounts", "verifier-output", "verifier-logs", "verifier-native"} {
		t.Run(fault, func(t *testing.T) {
			x := qualT46Native(t, core.DynamicNFTESDT)
			original, undo := errors.New("T46 native save fault"), errors.New("T46 native rollback fault")
			if fault == "foreign-store" {
				x.ctx.userAccountsDB = x.s.AccountsAdapter
			}
			if fault == "save" || fault == "rollback" {
				x.s.failAt = x.s.saves + 1
				x.s.saveFault = original
				if fault == "rollback" {
					x.s.rollbackFault = undo
				}
			}
			if bytes.HasPrefix([]byte(fault), []byte("verifier-")) {
				x.v.hook = func(p string) {
					if p != "NATIVE_BOOTSTRAP_STATE" {
						return
					}
					switch fault {
					case "verifier-storage":
						x.ctx.SetStorage([]byte("unrelated"), []byte{1})
					case "verifier-accounts":
						x.ctx.outputAccounts["unrelated"] = &vmcommon.OutputAccount{Address: []byte("unrelated")}
					case "verifier-output":
						x.ctx.Finish([]byte("unrelated"))
					case "verifier-logs":
						x.ctx.logs = append(x.ctx.logs, &vmcommon.LogEntry{Identifier: []byte("unrelated")})
					case "verifier-native":
						a, e := x.s.GetExistingAccount(core.ESDTSCAddress)
						require.NoError(t, e)
						require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue(x.token, []byte("mutated")))
						require.NoError(t, x.s.SaveAccount(a))
					}
				}
			} else if fault != "foreign-store" && fault != "save" && fault != "rollback" {
				token := &ESDTDataV2{}
				require.NoError(t, x.e.marshalizer.Unmarshal(token, x.native))
				switch fault {
				case "minted":
					token.MintedValue = big.NewInt(1)
				case "burnt":
					token.BurntValue = big.NewInt(1)
				case "net-zero-history":
					token.MintedValue = big.NewInt(1)
					token.BurntValue = big.NewInt(1)
				case "negative":
					token.MintedValue = big.NewInt(-1)
				case "roles":
					token.SpecialRoles = []*ESDTRoles{{Address: bytes.Repeat([]byte{2}, 32), Roles: [][]byte{[]byte(core.ESDTRoleNFTCreate)}}}
				case "paused":
					token.IsPaused = true
				case "nft-stopped":
					token.NFTCreateStopped = true
				case "wiped":
					token.NumWiped = 1
				case "manager":
					token.OwnerAddress[0] ^= 1
				case "family":
					token.TokenType = []byte(core.FungibleESDT)
				}
				encoded, e := x.e.marshalizer.Marshal(token)
				require.NoError(t, e)
				if fault == "missing" {
					encoded = nil
				}
				if fault == "malformed" {
					encoded = []byte{255}
				}
				a, e := x.s.GetExistingAccount(core.ESDTSCAddress)
				require.NoError(t, e)
				require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue(x.token, encoded))
				require.NoError(t, x.s.SaveAccount(a))
			}
			before, e := x.s.RootHash()
			require.NoError(t, e)
			journal := x.s.JournalLen()
			err := x.cancel()
			require.Error(t, err)
			if fault != "save" && fault != "rollback" && !bytes.HasPrefix([]byte(fault), []byte("verifier-")) {
				require.Zero(t, x.v.calls, "invalid native evidence denied before semantic verifiers")
			}
			require.Same(t, x.ctx, x.e.eei)
			require.Empty(t, x.ctx.storageUpdate)
			require.Empty(t, x.ctx.outputAccounts)
			require.Empty(t, x.ctx.output)
			require.Empty(t, x.ctx.logs)
			if fault == "rollback" {
				require.ErrorIs(t, err, original)
				require.ErrorIs(t, err, undo)
				_, out, e := x.f.boundary.Commit()
				require.ErrorIs(t, e, undo)
				require.Empty(t, out)
				return
			}
			if fault == "save" {
				require.ErrorIs(t, err, original)
			}
			after, e := x.s.RootHash()
			require.NoError(t, e)
			require.Equal(t, before, after)
			require.Equal(t, journal, x.s.JournalLen())
		})
	}
}
func TestQualDRWAT46NativeCancellationFreshContext(t *testing.T) {
	for _, fault := range []string{"nil-owner", "typed-nil", "context", "typed-nil-context", "storage", "accounts", "output", "logs"} {
		t.Run(fault, func(t *testing.T) {
			x := qualT46Native(t, core.FungibleESDT)
			var owner drwaBootstrapCancellationOwner = x.c
			switch fault {
			case "nil-owner":
				owner = nil
			case "typed-nil":
				var missing *drwa.RegistrationCancellation
				owner = missing
			case "context":
				x.e.eei = nil
			case "typed-nil-context":
				var missing *vmContext
				x.e.eei = missing
			case "storage":
				x.ctx.SetStorage([]byte("prior"), []byte{1})
			case "accounts":
				x.ctx.outputAccounts["prior"] = &vmcommon.OutputAccount{Address: []byte("prior")}
			case "output":
				x.ctx.Finish([]byte("prior"))
			case "logs":
				x.ctx.logs = append(x.ctx.logs, &vmcommon.LogEntry{Identifier: []byte("prior")})
			}
			before, e := x.s.RootHash()
			require.NoError(t, e)
			storage, accounts, output, logs := x.ctx.storageUpdate, x.ctx.outputAccounts, x.ctx.output, x.ctx.logs
			require.Error(t, x.e.cancelDRWABootstrapToken(owner, x.token, x.f.id, []byte("PROGRAM_ADMINISTRATION"), []byte("BOOTSTRAP_CANCEL"), []byte("NATIVE_BOOTSTRAP_STATE")))
			after, e := x.s.RootHash()
			require.NoError(t, e)
			require.Equal(t, before, after)
			require.Zero(t, x.s.JournalLen())
			require.Equal(t, storage, x.ctx.storageUpdate)
			require.Equal(t, accounts, x.ctx.outputAccounts)
			require.Equal(t, output, x.ctx.output)
			require.Equal(t, logs, x.ctx.logs)
		})
	}
}
