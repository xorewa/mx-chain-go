package drwa

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	commonMock "github.com/multiversx/mx-chain-vm-common-go/mock"
	"github.com/stretchr/testify/require"
)

// Native generated-call admission only; regulated provenance remains SP2-25/68.
func TestQualTransitionR16RolesNative(t *testing.T) {
	for _, mode := range []string{"set", "higher", "repeat", "remove", "caller", "late save"} {
		t.Run(mode+" should preserve latest nonce and role state", func(t *testing.T) {
			store := &qualTransitionReceiverSaveFault{qualNativeStore: qualRegistrationStore(t, 0)}
			marshaller := &marshal.GogoProtoMarshalizer{}
			set := mode != "remove"
			function, err := builtInFunctions.NewESDTRolesFunc(marshaller, set)
			require.NoError(t, err)
			tokenID := []byte("TOKEN-abcdef")
			nonceKey := append([]byte(core.ProtectedKeyPrefix+core.ESDTNFTLatestNonceIdentifier), tokenID...)
			roleKey := append([]byte(core.ProtectedKeyPrefix+core.ESDTRoleIdentifier+core.ESDTKeyIdentifier), tokenID...)
			start := uint64(math.MaxUint64 / 256)
			prior := uint64(4)
			if mode == "higher" || mode == "repeat" || mode == "remove" {
				prior = start + 100
			}
			role := []byte(core.ESDTRoleNFTCreateMultiShard)
			roles := &esdt.ESDTRoles{Roles: [][]byte{[]byte(core.ESDTRoleNFTCreate)}}
			if mode == "repeat" || mode == "remove" {
				roles.Roles = append(roles.Roles, role)
			}
			priorRoles, err := marshaller.Marshal(roles)
			require.NoError(t, err)
			account, err := store.LoadAccount(qualContainmentAddress)
			require.NoError(t, err)
			user := account.(state.UserAccountHandler)
			require.NoError(t, user.SaveKeyValue(nonceKey, new(big.Int).SetUint64(prior).Bytes()))
			require.NoError(t, user.SaveKeyValue(roleKey, priorRoles))
			require.NoError(t, store.SaveAccount(user))
			caller, err := store.LoadAccount(core.ESDTSCAddress)
			require.NoError(t, err)
			require.NoError(t, store.SaveAccount(caller))
			root, err := store.Commit()
			require.NoError(t, err)
			name := core.BuiltInFunctionSetESDTRole
			if !set {
				name = core.BuiltInFunctionUnSetESDTRole
			}
			hook, _ := qualT42Hook(t, store, 1, false)
			require.NoError(t, hook.GetBuiltinFunctionsContainer().Add(name, function))
			input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(core.ESDTSCAddress), CallValue: big.NewInt(0), Arguments: [][]byte{tokenID, role}}, RecipientAddr: bytes.Clone(qualContainmentAddress), Function: name}
			if mode == "caller" {
				input.CallerAddr = bytes.Clone(qualContainmentAddress)
			}
			fault := errors.New("qualification role destination save")
			if mode == "late save" {
				store.fault = fault
			}
			out, err := hook.ProcessBuiltInFunction(input)
			store.fault = nil
			denied := mode == "caller" || mode == "late save"
			if denied {
				require.Nil(t, out)
				expected := fault
				if mode == "caller" {
					expected = builtInFunctions.ErrAddressIsNotESDTSystemSC
				}
				require.ErrorIs(t, err, expected)
				after, e := store.RootHash()
				require.NoError(t, e)
				require.Equal(t, root, after)
				require.Zero(t, store.JournalLen())
			} else {
				require.NoError(t, err)
				require.Equal(t, &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, Logs: []*vmcommon.LogEntry{{Identifier: []byte(name), Address: qualContainmentAddress, Topics: [][]byte{tokenID, {}, {}, role}}}}, out)
			}
			committed, e := store.Commit()
			require.NoError(t, e)
			if denied {
				require.Equal(t, root, committed)
			}
			require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(committed)))
			account, e = store.GetExistingAccount(qualContainmentAddress)
			require.NoError(t, e)
			user = account.(state.UserAccountHandler)
			actualNonce, _, e := user.RetrieveValue(nonceKey)
			require.NoError(t, e)
			wantNonce := prior
			if !denied && set && prior < start {
				wantNonce = start
			}
			require.Equal(t, new(big.Int).SetUint64(wantNonce).Bytes(), actualNonce)
			actualRoles, _, e := user.RetrieveValue(roleKey)
			require.NoError(t, e)
			if denied {
				require.Equal(t, priorRoles, actualRoles)
			} else {
				if set {
					roles.Roles = append(roles.Roles, role)
				} else {
					roles.Roles = roles.Roles[:1]
				}
				want, e := marshaller.Marshal(roles)
				require.NoError(t, e)
				require.Equal(t, want, actualRoles)
			}
			require.Equal(t, big.NewInt(100), user.GetBalance())
		})
	}
}

func TestQualTransitionR16RoleWriteFaults(t *testing.T) {
	for _, failNonce := range []bool{true, false} {
		t.Run(fmt.Sprintf("nonce fault %t should suppress output and later writes", failNonce), func(t *testing.T) {
			marshaller := &marshal.GogoProtoMarshalizer{}
			function, err := builtInFunctions.NewESDTRolesFunc(marshaller, true)
			require.NoError(t, err)
			fault := errors.New("qualification native role storage failure")
			var writes []string
			nonceKey := append([]byte(core.ProtectedKeyPrefix+core.ESDTNFTLatestNonceIdentifier), []byte("TOKEN-abcdef")...)
			account := &commonMock.UserAccountStub{AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
				return &commonMock.DataTrieTrackerStub{
					RetrieveValueCalled: func([]byte) ([]byte, uint32, error) { return nil, 0, nil },
					SaveKeyValueCalled: func(key, value []byte) error {
						writes = append(writes, string(key))
						if bytes.Equal(key, nonceKey) == failNonce {
							return fault
						}
						return nil
					},
				}
			}}
			out, err := function.ProcessBuiltinFunction(nil, account, &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: core.ESDTSCAddress, CallValue: big.NewInt(0), Arguments: [][]byte{[]byte("TOKEN-abcdef"), []byte(core.ESDTRoleNFTCreateMultiShard)}}, RecipientAddr: qualContainmentAddress})
			require.Nil(t, out)
			require.ErrorIs(t, err, fault)
			if failNonce {
				require.Equal(t, []string{string(nonceKey)}, writes)
			} else {
				require.Len(t, writes, 2)
				require.Equal(t, string(nonceKey), writes[0])
			}
		})
	}
}
