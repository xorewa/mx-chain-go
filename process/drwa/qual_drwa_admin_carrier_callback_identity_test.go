package drwa

import (
	"testing"

	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Callback adversary only: native account writes/journals run, while origin,
// current binding, native effect and ACK provenance remain synthetic fixtures.
type qualAdminCallbackHost struct {
	*qualAdminHost
	afterState, afterApply, afterAck, afterLocal func()
}

func (h *qualAdminCallbackHost) ValidateLocal(e adminEffectEnvelope) error {
	err := h.qualAdminHost.ValidateLocal(e)
	if err == nil && h.afterLocal != nil {
		hook := h.afterLocal
		h.afterLocal = nil
		hook()
	}
	return err
}

func (h *qualAdminCallbackHost) StateHash(e adminEffectEnvelope) ([]byte, error) {
	value, err := h.qualAdminHost.StateHash(e)
	if err == nil && h.afterState != nil {
		hook := h.afterState
		h.afterState = nil
		hook()
	}
	return value, err
}

func (h *qualAdminCallbackHost) ApplyNative(e adminEffectEnvelope) (*vmcommon.VMOutput, error) {
	output, err := h.qualAdminHost.ApplyNative(e)
	if err == nil && h.afterApply != nil {
		h.afterApply()
	}
	return output, err
}

func (h *qualAdminCallbackHost) Ack(e adminEffectEnvelope, ack []byte, output *vmcommon.VMOutput) (*vmcommon.VMOutput, error) {
	output, err := h.qualAdminHost.Ack(e, ack, output)
	if err == nil && h.afterAck != nil {
		h.afterAck()
	}
	return output, err
}

func TestQualDRWAAdminCarrierCallbackIdentity(t *testing.T) {
	for _, name := range []string{"state_creates_identity", "apply_changes_identity", "ack_deletes_identity", "ack_changes_target", "redrive_deletes_identity", "redrive_changes_target"} {
		t.Run(name, func(t *testing.T) {
			f := qualAdminNew(t)
			duplicate := name == "redrive_deletes_identity" || name == "redrive_changes_target"
			if duplicate {
				require.NoError(t, f.carrier.apply(f.encoded, f.proof))
				_, _, err := f.boundary.Commit()
				require.NoError(t, err)
				f.boundary, err = NewRollbackContainment(f.store)
				require.NoError(t, err)
				f.carrier.boundary = f.boundary
			}
			root, err := f.store.RootHash()
			require.NoError(t, err)
			identity := qualRegistryValue(t, f.store, string(f.appliedKey()))
			target := qualRegistryValue(t, f.store, string(f.e.targetKey))
			h := &qualAdminCallbackHost{qualAdminHost: f.host}
			changeIdentity := func() { qualRecordPut(t, f.store, f.appliedKey(), []byte("different applied leg")) }
			deleteIdentity := func() { qualRecordPut(t, f.store, f.appliedKey(), nil) }
			changeTarget := func() { qualRecordPut(t, f.store, f.e.targetKey, []byte("predecessor")) }
			switch name {
			case "state_creates_identity":
				h.afterState = changeIdentity
			case "apply_changes_identity":
				h.afterApply = changeIdentity
			case "ack_deletes_identity", "redrive_deletes_identity":
				h.afterAck = deleteIdentity
			default:
				h.afterAck = changeTarget
			}
			f.carrier.host = h
			require.ErrorIs(t, f.carrier.apply(f.encoded, f.proof), errAdminCarrier)
			require.Equal(t, identity, qualRegistryValue(t, f.store, string(f.appliedKey())))
			require.Equal(t, target, qualRegistryValue(t, f.store, string(f.e.targetKey)))
			after, err := f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
			if name == "state_creates_identity" {
				require.Zero(t, f.host.applyCalls, "receipt conflict denies before the native effect")
			} else {
				require.Equal(t, int32(1), f.host.applyCalls, "duplicate never executes a second effect")
			}
			_, output, err := f.boundary.Commit()
			require.NoError(t, err)
			require.Empty(t, output)
		})
	}
}

func TestQualDRWAAdminCarrierCallbackOtherKey(t *testing.T) {
	for _, stage := range []string{"state", "apply", "ack"} {
		t.Run(stage, func(t *testing.T) {
			f := qualAdminNew(t)
			key := []byte("fixture/admin-callback/" + stage)
			write := func() { qualRecordPut(t, f.store, key, []byte("preserved")) }
			h := &qualAdminCallbackHost{qualAdminHost: f.host}
			switch stage {
			case "state":
				h.afterState = write
			case "apply":
				h.afterApply = write
			case "ack":
				h.afterAck = write
			}
			f.carrier.host = h
			require.NoError(t, f.carrier.apply(f.encoded, f.proof))
			require.Equal(t, f.encoded, qualRegistryValue(t, f.store, string(f.appliedKey())))
			require.Equal(t, []byte("result"), qualRegistryValue(t, f.store, string(f.e.targetKey)))
			require.Equal(t, []byte("preserved"), qualRegistryValue(t, f.store, string(key)))
		})
	}
}

func TestQualDRWAAdminCarrierAuthenticationReceipt(t *testing.T) {
	for _, stage := range []string{"canonical", "local"} {
		for _, predecessor := range []string{"first", "duplicate", "other_key"} {
			t.Run(stage+"/"+predecessor, func(t *testing.T) {
				f := qualAdminNew(t)
				if predecessor == "duplicate" {
					require.NoError(t, f.carrier.apply(f.encoded, f.proof))
					_, _, err := f.boundary.Commit()
					require.NoError(t, err)
					f.boundary, err = NewRollbackContainment(f.store)
					require.NoError(t, err)
					f.carrier.boundary = f.boundary
				}
				root, err := f.store.RootHash()
				require.NoError(t, err)
				identity := qualRegistryValue(t, f.store, string(f.appliedKey()))
				target := qualRegistryValue(t, f.store, string(f.e.targetKey))
				calls := f.host.applyCalls
				other := []byte("fixture/admin-auth/" + stage)
				mutate := func() {
					switch predecessor {
					case "first":
						qualRecordPut(t, f.store, f.appliedKey(), f.encoded)
						qualRecordPut(t, f.store, f.e.targetKey, []byte("result"))
					case "duplicate":
						qualRecordPut(t, f.store, f.appliedKey(), nil)
						qualRecordPut(t, f.store, f.e.targetKey, []byte("predecessor"))
					default:
						qualRecordPut(t, f.store, other, []byte("preserved"))
					}
				}
				h := &qualAdminCallbackHost{qualAdminHost: f.host}
				if stage == "canonical" {
					f.host.verifyHook = mutate
				} else {
					h.afterLocal = mutate
				}
				f.carrier.host = h
				err = f.carrier.apply(f.encoded, f.proof)
				if predecessor == "other_key" {
					require.NoError(t, err)
					require.Equal(t, calls+1, f.host.applyCalls)
					require.Equal(t, []byte("preserved"), qualRegistryValue(t, f.store, string(other)))
					require.Equal(t, f.encoded, qualRegistryValue(t, f.store, string(f.appliedKey())))
					require.Equal(t, []byte("result"), qualRegistryValue(t, f.store, string(f.e.targetKey)))
					return
				}
				require.ErrorIs(t, err, errAdminCarrier)
				require.Equal(t, calls, f.host.applyCalls, "authentication cannot manufacture freshness or a completed leg")
				require.Equal(t, identity, qualRegistryValue(t, f.store, string(f.appliedKey())))
				require.Equal(t, target, qualRegistryValue(t, f.store, string(f.e.targetKey)))
				after, err := f.store.RootHash()
				require.NoError(t, err)
				require.Equal(t, root, after)
				_, out, err := f.boundary.Commit()
				require.NoError(t, err)
				require.Empty(t, out)
			})
		}
	}
}
