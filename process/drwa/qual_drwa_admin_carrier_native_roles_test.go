package drwa

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
	"github.com/stretchr/testify/require"
)

// The origin/dependency/ACK host remains SYNTHETIC. Only the inner role
// mutation is the actual native builtin, over the real native account/trie.
// A controlled ESDTSC caller here establishes no protected protocol origin.
type qualAdminNativeRolesHost struct {
	*qualAdminHost
	builtin     vmcommon.BuiltinFunction
	address     []byte
	rolesKey    []byte
	wrongCaller bool
}

// The selected fault belongs to the system-account identity record. Leave the
// actual native EOA type intact for the builtin's AccountDataHandler interface.
type qualAdminRolesIdentityFault struct{ *qualAdminKeyFault }

func (s *qualAdminRolesIdentityFault) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	if bytes.Equal(address, core.SystemAccountAddress) {
		return s.qualAdminKeyFault.GetExistingAccount(address)
	}
	return s.AccountsAdapter.GetExistingAccount(address)
}

func (h *qualAdminNativeRolesHost) StateHash(_ adminEffectEnvelope) ([]byte, error) {
	a, err := h.store.GetExistingAccount(h.address)
	if err != nil {
		return nil, err
	}
	value, _, err := a.(vmcommon.UserAccountHandler).AccountDataHandler().RetrieveValue(h.rolesKey)
	return blake2b.NewBlake2b().Compute(string(value)), err
}

func (h *qualAdminNativeRolesHost) ApplyNative(e adminEffectEnvelope) (*vmcommon.VMOutput, error) {
	atomic.AddInt32(&h.applyCalls, 1)
	a, err := h.store.GetExistingAccount(h.address)
	if err != nil {
		return nil, err
	}
	function, arguments, err := parsers.NewCallArgsParser().ParseData(string(e.payload))
	if err != nil {
		return nil, err
	}
	caller := bytes.Clone(core.ESDTSCAddress)
	if h.wrongCaller {
		caller = bytes.Clone(h.address)
	}
	out, err := h.builtin.ProcessBuiltinFunction(nil, a.(vmcommon.UserAccountHandler), &vmcommon.ContractCallInput{
		VMInput:  vmcommon.VMInput{CallerAddr: caller, CallValue: big.NewInt(0), Arguments: arguments},
		Function: function, RecipientAddr: bytes.Clone(h.address),
	})
	if err != nil {
		return nil, err
	}
	if err = h.store.SaveAccount(a); err != nil {
		return nil, err
	}
	return out, nil
}

func qualAdminNativeRolesValue(t *testing.T, h *qualAdminNativeRolesHost) []byte {
	t.Helper()
	a, err := h.store.GetExistingAccount(h.address)
	require.NoError(t, err)
	require.Equal(t, big.NewInt(100), a.(vmcommon.UserAccountHandler).GetBalance())
	require.Zero(t, a.GetNonce())
	value, _, err := a.(vmcommon.UserAccountHandler).AccountDataHandler().RetrieveValue(h.rolesKey)
	require.NoError(t, err)
	return value
}

func TestQualDRWAAdminCarrierNativeRoleEffects(t *testing.T) {
	for _, grant := range []bool{true, false} {
		operation := core.BuiltInFunctionSetESDTRole
		if !grant {
			operation = core.BuiltInFunctionUnSetESDTRole
		}
		for _, fault := range []string{"healthy", "ack", "save-account", "identity-key", "wrong-caller", "wrong-result", "duplicate-ack"} {
			t.Run(operation+"/"+fault, func(t *testing.T) {
				f := qualAdminNew(t)
				role := []byte(core.ESDTRoleNFTCreate)
				// Independent ESDTRoles protobuf: repeated bytes field 1.
				withRole := append([]byte{0x0a, byte(len(role))}, role...)
				before, after := []byte{}, withRole
				if !grant {
					before, after = withRole, []byte{}
				}
				key := []byte(core.ProtectedKeyPrefix + core.ESDTRoleIdentifier + core.ESDTKeyIdentifier + string(f.e.tokenID))
				a, err := f.store.GetExistingAccount(qualContainmentAddress)
				require.NoError(t, err)
				require.NoError(t, a.(vmcommon.UserAccountHandler).AccountDataHandler().SaveKeyValue(key, bytes.Clone(before)))
				require.NoError(t, f.store.SaveAccount(a))
				_, err = f.store.Commit()
				require.NoError(t, err)
				f.e.targetKey = bytes.Clone(qualContainmentAddress)
				f.e.discriminator = []byte(operation)
				f.e.payload = []byte(operation + "@" + hex.EncodeToString(f.e.tokenID) + "@" + hex.EncodeToString(role))
				f.e.normalizedDigest = qualAdminDigest("NORMALIZED", []byte(operation), f.e.tokenID, role)
				f.e.predecessor = blake2b.NewBlake2b().Compute(string(before))
				f.e.result = blake2b.NewBlake2b().Compute(string(after))
				builtin, err := builtInFunctions.NewESDTRolesFunc(&marshal.GogoProtoMarshalizer{}, grant)
				require.NoError(t, err)
				host := &qualAdminNativeRolesHost{qualAdminHost: f.host, builtin: builtin, address: bytes.Clone(qualContainmentAddress), rolesKey: key}
				f.host.key = bytes.Clone(qualContainmentAddress)
				original := errors.New("selected native role sink fault")
				store := f.host.store
				switch fault {
				case "ack":
					f.host.ackErr = original
				case "save-account":
					store = &qualAdminNthSave{AccountsAdapter: f.store, failAt: 2, fault: original}
				case "identity-key":
					store = &qualAdminRolesIdentityFault{&qualAdminKeyFault{&qualScopedAccountFault{f.store, f.appliedKey(), original}}}
				case "wrong-caller":
					host.wrongCaller = true
				case "wrong-result":
					f.e.result = blake2b.NewBlake2b().Compute("independently wrong role state")
				}
				f.host.store = store
				f.rebind()
				f.boundary, err = NewRollbackContainment(store)
				require.NoError(t, err)
				f.carrier, err = newAdminCarrier(store, f.boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), []byte("fixture-domain"), 4096, host)
				require.NoError(t, err)
				root, err := f.store.RootHash()
				require.NoError(t, err)
				journal := f.store.JournalLen()
				err = f.carrier.apply(f.encoded, f.proof)
				if fault != "healthy" && fault != "duplicate-ack" {
					require.Error(t, err)
					if fault == "ack" || fault == "save-account" || fault == "identity-key" {
						require.ErrorIs(t, err, original)
					}
					if fault == "wrong-caller" {
						require.ErrorIs(t, err, builtInFunctions.ErrAddressIsNotESDTSystemSC)
					}
					actualRoot, e := f.store.RootHash()
					require.NoError(t, e)
					require.Equal(t, root, actualRoot)
					require.Equal(t, journal, f.store.JournalLen())
					require.True(t, bytes.Equal(before, qualAdminNativeRolesValue(t, host)))
					require.Empty(t, qualRegistryValue(t, f.store, string(f.appliedKey())))
					_, outputs, e := f.boundary.Commit()
					require.NoError(t, e)
					require.Empty(t, outputs)
					return
				}
				require.NoError(t, err)
				if fault == "duplicate-ack" {
					f.host.ackErr = original
					appliedRoot, e := f.store.RootHash()
					require.NoError(t, e)
					appliedJournal := f.store.JournalLen()
					require.ErrorIs(t, f.carrier.apply(f.encoded, f.proof), original)
					actualRoot, e := f.store.RootHash()
					require.NoError(t, e)
					require.Equal(t, appliedRoot, actualRoot)
					require.Equal(t, appliedJournal, f.store.JournalLen())
					f.host.ackErr = nil
				}
				require.NoError(t, f.carrier.apply(f.encoded, f.proof))
				require.Equal(t, int32(1), atomic.LoadInt32(&host.applyCalls))
				require.True(t, bytes.Equal(after, qualAdminNativeRolesValue(t, host)))
				require.Equal(t, f.encoded, qualRegistryValue(t, f.store, string(f.appliedKey())))
				roots, outputs, err := f.boundary.Commit()
				require.NoError(t, err)
				require.Len(t, outputs, 2)
				wantAck := qualRecordFrame([]byte("DRWA/ADMIN_ACK/candidate1"), f.encoded)
				require.Equal(t, [][]byte{wantAck}, outputs[0].ReturnData)
				require.Equal(t, [][]byte{wantAck}, outputs[1].ReturnData)
				require.Len(t, outputs[0].Logs, 1)
				require.Equal(t, []byte(operation), outputs[0].Logs[0].Identifier)
				require.Equal(t, host.address, outputs[0].Logs[0].Address)
				require.Equal(t, [][]byte{f.e.tokenID, {}, {}, role}, outputs[0].Logs[0].Topics)
				require.Empty(t, outputs[1].Logs)
				require.NoError(t, f.store.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
				f.boundary, err = NewRollbackContainment(store)
				require.NoError(t, err)
				f.carrier.boundary = f.boundary
				require.NoError(t, f.carrier.apply(f.encoded, f.proof))
				require.Equal(t, int32(1), atomic.LoadInt32(&host.applyCalls))
				require.True(t, bytes.Equal(after, qualAdminNativeRolesValue(t, host)))
				_, restarted, e := f.boundary.Commit()
				require.NoError(t, e)
				require.Len(t, restarted, 1)
				require.Equal(t, [][]byte{wantAck}, restarted[0].ReturnData)
				require.Empty(t, restarted[0].Logs)
			})
		}
	}
}
