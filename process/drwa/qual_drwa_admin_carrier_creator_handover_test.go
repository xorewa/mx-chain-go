package drwa

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/sharding"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
	"github.com/stretchr/testify/require"
)

// Actual native same-shard handover; origin, CEB/work/ACK trust stays synthetic.
// This is no actual System-SC request, prepared lifecycle, canonical transport,
// EOA/guardian proof, NFT creation, real funding or AR-13 retry selection.
type qualAdminCreatorHost struct {
	*qualAdminHost
	builtin                      vmcommon.BuiltinFunction
	old, next, nonceKey, roleKey []byte
}

func (h *qualAdminCreatorHost) values() ([][]byte, error) {
	var result [][]byte
	for _, address := range [][]byte{h.old, h.next} {
		a, err := h.store.GetExistingAccount(address)
		if err != nil {
			return nil, err
		}
		for _, key := range [][]byte{h.nonceKey, h.roleKey} {
			value, _, err := a.(vmcommon.UserAccountHandler).AccountDataHandler().RetrieveValue(key)
			if err != nil {
				return nil, err
			}
			result = append(result, value)
		}
	}
	return result, nil
}

func (h *qualAdminCreatorHost) StateHash(_ adminEffectEnvelope) ([]byte, error) {
	values, err := h.values()
	return blake2b.NewBlake2b().Compute(string(qualRecordFrame(values...))), err
}

func (h *qualAdminCreatorHost) ApplyNative(e adminEffectEnvelope) (*vmcommon.VMOutput, error) {
	atomic.AddInt32(&h.applyCalls, 1)
	a, err := h.store.GetExistingAccount(h.old)
	if err != nil {
		return nil, err
	}
	function, arguments, err := parsers.NewCallArgsParser().ParseData(string(e.payload))
	if err != nil {
		return nil, err
	}
	out, err := h.builtin.ProcessBuiltinFunction(nil, a.(vmcommon.UserAccountHandler), &vmcommon.ContractCallInput{
		VMInput:  vmcommon.VMInput{CallerAddr: bytes.Clone(core.ESDTSCAddress), CallValue: big.NewInt(0), Arguments: arguments},
		Function: function, RecipientAddr: bytes.Clone(h.old),
	})
	if err != nil {
		return nil, err
	}
	if err = h.store.SaveAccount(a); err != nil {
		return nil, err
	}
	return out, nil
}

func TestQualDRWAAdminCarrierNativeCreatorHandover(t *testing.T) {
	for _, family := range []string{core.NonFungibleESDTv2, core.SemiFungibleESDT, core.MetaESDT,
		core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT} {
		for _, used := range []bool{false, true} {
			for _, fault := range []string{"healthy", "ack", "successor-save", "old-save", "identity-key", "provenance", "wrong-result", "counter-drift"} {
				t.Run(fmt.Sprintf("%s/used_%t/%s", family, used, fault), func(t *testing.T) {
					f := qualAdminNew(t)
					coordinator, err := sharding.NewMultiShardCoordinator(3, 1)
					require.NoError(t, err)
					old := bytes.Clone(qualContainmentAddress)
					require.Equal(t, coordinator.SelfId(), coordinator.ComputeId(old))
					var next []byte
					for value := byte(2); value < 255; value++ {
						candidate := bytes.Repeat([]byte{value}, 32)
						if coordinator.ComputeId(candidate) == coordinator.SelfId() {
							next = candidate
							break
						}
					}
					require.Len(t, next, 32)
					nonceKey := []byte(core.ProtectedKeyPrefix + core.ESDTNFTLatestNonceIdentifier + string(f.e.tokenID))
					roleKey := []byte(core.ProtectedKeyPrefix + core.ESDTRoleIdentifier + core.ESDTKeyIdentifier + string(f.e.tokenID))
					burn := []byte(core.ESDTRoleNFTBurn)
					create := []byte(core.ESDTRoleNFTCreate)
					// Independent repeated-bytes protobuf and native unsigned counter bytes.
					before := [][]byte{{7}, qualRecordFrame(create, burn), {}, qualRecordFrame(burn)}
					after := [][]byte{{}, qualRecordFrame(burn), {7}, qualRecordFrame(burn, create)}
					otherKey := []byte(core.ProtectedKeyPrefix + core.ESDTNFTLatestNonceIdentifier + "OTHER-abcdef")
					for index, address := range [][]byte{old, next} {
						a, e := f.store.LoadAccount(address)
						require.NoError(t, e)
						user := a.(vmcommon.UserAccountHandler)
						if index == 1 {
							require.NoError(t, user.AddToBalance(big.NewInt(55)))
							user.IncreaseNonce(3)
							if used {
								require.NoError(t, user.AccountDataHandler().SaveKeyValue(otherKey, []byte{19}))
							}
						}
						require.NoError(t, user.AccountDataHandler().SaveKeyValue(nonceKey, before[2*index]))
						require.NoError(t, user.AccountDataHandler().SaveKeyValue(roleKey, before[2*index+1]))
						require.NoError(t, f.store.SaveAccount(a))
					}
					_, err = f.store.Commit()
					require.NoError(t, err)
					f.e.tokenType = []byte(family) // native builtin itself has no family discriminator
					f.e.targetKey = old
					f.e.discriminator = []byte(core.BuiltInFunctionESDTNFTCreateRoleTransfer)
					f.e.payload = []byte(string(f.e.discriminator) + "@" + hex.EncodeToString(f.e.tokenID) + "@" + hex.EncodeToString(next))
					f.e.normalizedDigest = qualAdminDigest("NORMALIZED", f.e.discriminator, f.e.tokenID, next)
					f.e.predecessor = blake2b.NewBlake2b().Compute(string(qualRecordFrame(before...)))
					f.e.result = blake2b.NewBlake2b().Compute(string(qualRecordFrame(after...)))
					f.host.key = old
					original := errors.New("selected creator handover sink fault")
					store := f.host.store
					switch fault {
					case "ack":
						f.host.ackErr = original
					case "successor-save":
						store = &qualAdminNthSave{AccountsAdapter: f.store, failAt: 1, fault: original}
					case "old-save":
						store = &qualAdminNthSave{AccountsAdapter: f.store, failAt: 2, fault: original}
					case "identity-key":
						store = &qualAdminRolesIdentityFault{&qualAdminKeyFault{&qualScopedAccountFault{f.store, f.appliedKey(), original}}}
					case "wrong-result":
						f.e.result = blake2b.NewBlake2b().Compute("independently wrong handover result")
					}
					f.host.store = store
					f.rebind()
					if fault == "provenance" {
						f.proof[0] ^= 1
					}
					builtin, err := builtInFunctions.NewESDTNFTCreateRoleTransfer(&marshal.GogoProtoMarshalizer{}, store, coordinator)
					require.NoError(t, err)
					host := &qualAdminCreatorHost{f.host, builtin, old, next, nonceKey, roleKey}
					f.boundary, err = NewRollbackContainment(store)
					require.NoError(t, err)
					f.carrier, err = newAdminCarrier(store, f.boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), []byte("fixture-domain"), 4096, host)
					require.NoError(t, err)
					root, err := f.store.RootHash()
					require.NoError(t, err)
					journal := f.store.JournalLen()
					err = f.carrier.apply(f.encoded, f.proof)
					if fault != "healthy" && fault != "counter-drift" {
						require.Error(t, err)
						if fault != "provenance" && fault != "wrong-result" {
							require.ErrorIs(t, err, original)
						}
						if fault == "provenance" {
							require.Zero(t, atomic.LoadInt32(&host.applyCalls))
						} else {
							require.Equal(t, int32(1), atomic.LoadInt32(&host.applyCalls))
						}
						values, e := host.values()
						require.NoError(t, e)
						for i := range before {
							require.True(t, bytes.Equal(before[i], values[i]), "native field %d", i)
						}
						actualRoot, e := f.store.RootHash()
						require.NoError(t, e)
						require.Equal(t, root, actualRoot)
						require.Equal(t, journal, f.store.JournalLen())
						require.Empty(t, qualRegistryValue(t, f.store, string(f.appliedKey())))
						_, outputs, e := f.boundary.Commit()
						require.NoError(t, e)
						require.Empty(t, outputs)
						return
					}
					require.NoError(t, err)
					values, err := host.values()
					require.NoError(t, err)
					for i := range after {
						require.True(t, bytes.Equal(after[i], values[i]), "native field %d", i)
					}
					require.NoError(t, f.carrier.apply(f.encoded, f.proof))
					require.Equal(t, int32(1), atomic.LoadInt32(&host.applyCalls))
					roots, outputs, err := f.boundary.Commit()
					require.NoError(t, err)
					require.Len(t, outputs, 2)
					wantAck := qualRecordFrame([]byte("DRWA/ADMIN_ACK/candidate1"), f.encoded)
					require.Equal(t, [][]byte{wantAck}, outputs[0].ReturnData)
					require.Len(t, outputs[0].Logs, 2)
					for i, address := range [][]byte{old, next} {
						require.Equal(t, f.e.discriminator, outputs[0].Logs[i].Identifier)
						require.Equal(t, address, outputs[0].Logs[i].Address)
						flag := []byte("false")
						if i == 1 {
							flag = []byte("true")
						}
						require.Equal(t, [][]byte{f.e.tokenID, {}, {}, flag}, outputs[0].Logs[i].Topics)
					}
					nativeOutput := outputs[0].OutputAccounts[string(next)]
					require.Equal(t, next, nativeOutput.Address)
					require.Len(t, nativeOutput.OutputTransfers, 1)
					transfer := nativeOutput.OutputTransfers[0]
					require.Equal(t, uint32(1), transfer.Index)
					require.Equal(t, big.NewInt(0), transfer.Value)
					require.Equal(t, core.ESDTSCAddress, transfer.SenderAddress)
					require.Equal(t, []byte(string(f.e.discriminator)+"@"+hex.EncodeToString(f.e.tokenID)+"@07"), transfer.Data)
					require.Equal(t, [][]byte{wantAck}, outputs[1].ReturnData)
					require.Empty(t, outputs[1].Logs)
					require.Empty(t, outputs[1].OutputAccounts)
					require.NoError(t, f.store.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
					if fault == "counter-drift" {
						a, e := f.store.GetExistingAccount(next)
						require.NoError(t, e)
						require.NoError(t, a.(vmcommon.UserAccountHandler).AccountDataHandler().SaveKeyValue(nonceKey, []byte{9}))
						require.NoError(t, f.store.SaveAccount(a))
						_, e = f.store.Commit()
						require.NoError(t, e)
					}
					f.boundary, err = NewRollbackContainment(store)
					require.NoError(t, err)
					f.carrier.boundary = f.boundary
					if fault == "counter-drift" {
						root, e := f.store.RootHash()
						require.NoError(t, e)
						require.Error(t, f.carrier.apply(f.encoded, f.proof))
						current, e := f.store.RootHash()
						require.NoError(t, e)
						require.Equal(t, root, current)
						after[2] = []byte{9}
					} else {
						require.NoError(t, f.carrier.apply(f.encoded, f.proof))
					}
					require.Equal(t, int32(1), atomic.LoadInt32(&host.applyCalls))
					values, err = host.values()
					require.NoError(t, err)
					for i := range after {
						require.True(t, bytes.Equal(after[i], values[i]), "native field %d", i)
					}
					require.Equal(t, f.encoded, qualRegistryValue(t, f.store, string(f.appliedKey())))
					_, restarted, err := f.boundary.Commit()
					require.NoError(t, err)
					if fault == "counter-drift" {
						require.Empty(t, restarted)
					} else {
						require.Len(t, restarted, 1)
						require.Equal(t, [][]byte{wantAck}, restarted[0].ReturnData)
						require.Empty(t, restarted[0].Logs)
					}
					for index, address := range [][]byte{old, next} {
						a, e := f.store.GetExistingAccount(address)
						require.NoError(t, e)
						wantBalance, wantNonce := int64(100), uint64(0)
						if index == 1 {
							wantBalance, wantNonce = 55, 3
							value, _, e := a.(vmcommon.UserAccountHandler).AccountDataHandler().RetrieveValue(otherKey)
							require.NoError(t, e)
							if used {
								require.Equal(t, []byte{19}, value)
							} else {
								require.Empty(t, value)
							}
						}
						require.Equal(t, big.NewInt(wantBalance), a.(vmcommon.UserAccountHandler).GetBalance())
						require.Equal(t, wantNonce, a.GetNonce())
					}
				})
			}
		}
	}
}
