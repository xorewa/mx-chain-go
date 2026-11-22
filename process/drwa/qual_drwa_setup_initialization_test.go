package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/sharding"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Root grammars, resource admission and replicated canonical CEB interpretation
// are SYNTHETIC. These tests exercise the native writer/journal, not real
// activation provenance, canonical local application or readiness ACKs.
type qualSetupHost struct {
	t                       *testing.T
	f                       *qualLifecycleFixture
	rootCalls               []bool
	reserves                int
	rootError, reserveError error
	rootHook, reserveHook   func()
	shortRoot, wrongRoot    bool
}

func (h *qualSetupHost) IsInterfaceNil() bool { return h == nil }
func (h *qualSetupHost) EmptyRoot(family uint32, position bool) ([]byte, error) {
	h.rootCalls = append(h.rootCalls, position)
	require.Equal(h.t, h.f.h.fields.tokenType, family)
	if h.rootHook != nil {
		h.rootHook()
	}
	if h.shortRoot {
		return []byte{1}, nil
	}
	if h.wrongRoot {
		return bytes.Repeat([]byte{1}, 32), nil
	}
	return qualSetupRoot(), h.rootError
}
func qualSetupRoot() []byte {
	return bytes.Clone(common.EmptyTrieHash)
}
func (h *qualSetupHost) ReserveInitialization(token []byte, epoch uint64, hash []byte, keys, values [][]byte) error {
	h.reserves++
	require.Equal(h.t, []byte("TOKEN-abcdef"), token)
	require.Equal(h.t, uint64(1), epoch)
	require.Equal(h.t, h.f.hash, hash)
	require.Len(h.t, values, len(keys))
	for i := range keys {
		require.NotEmpty(h.t, values[i])
		require.Empty(h.t, qualActivationValue(h.t, h.f.x.f.store, keys[i]))
		keys[i][0] ^= 1
		values[i][0] ^= 1
	}
	token[0] ^= 1
	hash[0] ^= 1
	// The writer must reload after a real native budget-owner write.
	qualRecordPut(h.t, h.f.x.f.store, []byte("fixture/setup-resource-receipt"), []byte{1})
	if h.reserveHook != nil {
		h.reserveHook()
	}
	return h.reserveError
}

func qualSetupNew(t *testing.T, family uint32, preserve, origin bool) (*qualLifecycleFixture, *setupInitialization, *qualSetupHost) {
	t.Helper()
	f := qualLifecycleNew(t)
	// The local replica is explicitly synthetic. Varying its decoded plan/type
	// is not proof of native intent/genesis admission for these combinations.
	f.h.fields.tokenType = family
	if preserve {
		f.h.fields.closurePlan = []byte("preserve-and-close")
	}
	self := f.h.fields.supplyOriginShard
	if !origin {
		self = (self + 1) % 3
	}
	hook, _ := qualT42Hook(t, f.x.f.store, self, true)
	_, end := qualT42Install(t, hook, self, 1)
	t.Cleanup(end)
	coord, err := sharding.NewMultiShardCoordinator(3, self)
	require.NoError(t, err)
	f.r, err = newCurrentLifecycleReader(f.r.current, f.x.f.boundary, hook, coord)
	require.NoError(t, err)
	f.context, err = hook.EvaluatedHeaderTimeContext()
	require.NoError(t, err)
	h := &qualSetupHost{t: t, f: f}
	s, err := newSetupInitialization(f.r, h, 32)
	require.NoError(t, err)
	return f, s, h
}

func qualSetupKeys() ([]byte, []byte) {
	id := qualRecordFrame([]byte("TOKEN-abcdef"))
	return append([]byte(supplyStatePrefix), id...), append([]byte(positionTrackingPrefix), id...)
}
func qualSetupExecute(f *qualLifecycleFixture, s *setupInitialization) error {
	return f.x.f.boundary.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
		out, err := s.initializeOwned(op, f.context, []byte("TOKEN-abcdef"), 1, f.hash)
		return []*vmcommon.VMOutput{out}, err
	})
}

func TestQualDRWASetupInitializationRequiresOriginalOperation(t *testing.T) {
	for _, scenario := range []string{"success", "late-refusal", "foreign-operation", "resource-refusal"} {
		t.Run(scenario, func(t *testing.T) {
			f, s, h := qualSetupNew(t, uint32(core.Fungible), true, true)
			boundary := f.x.f.boundary
			root, err := f.x.f.store.RootHash()
			require.NoError(t, err)
			journal := f.x.f.store.JournalLen()
			failure := errors.New("synthetic setup failure")
			var foreign *rollbackOperation
			if scenario == "foreign-operation" {
				other, err := NewRollbackContainment(qualRegistrationStore(t, 0))
				require.NoError(t, err)
				require.NoError(t, other.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
					foreign = op
					return nil, nil
				}))
			}
			if scenario == "resource-refusal" {
				h.reserveError = failure
			}
			outputs := len(boundary.outputs)
			err = boundary.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
				if foreign != nil {
					op = foreign
				}
				out, e := s.initializeOwned(op, f.context, []byte("TOKEN-abcdef"), 1, f.hash)
				if e != nil {
					require.Nil(t, out)
					if scenario == "resource-refusal" {
						return nil, nil // resource refusal cannot be swallowed
					}
					return nil, e
				}
				require.Equal(t, vmcommon.Ok, out.ReturnCode)
				if scenario == "late-refusal" {
					return []*vmcommon.VMOutput{out}, failure
				}
				return []*vmcommon.VMOutput{out}, nil
			})
			sk, pk := qualSetupKeys()
			if scenario == "success" {
				require.NoError(t, err)
				require.NotEmpty(t, qualActivationValue(t, f.x.f.store, sk))
				require.NotEmpty(t, qualActivationValue(t, f.x.f.store, pk))
				require.Len(t, boundary.outputs, outputs+1)
				return
			}
			if scenario == "foreign-operation" {
				require.ErrorIs(t, err, errInvalidMetaContext)
				require.Zero(t, h.reserves)
			} else {
				require.ErrorIs(t, err, failure)
				require.Equal(t, 1, h.reserves)
			}
			after, err := f.x.f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
			require.Equal(t, journal, f.x.f.store.JournalLen())
			require.Len(t, boundary.outputs, outputs)
			require.Empty(t, qualActivationValue(t, f.x.f.store, sk))
			require.Empty(t, qualActivationValue(t, f.x.f.store, pk))
		})
	}
}

func TestQualDRWASetupInitializationExplicitFamilyPlanAndLocus(t *testing.T) {
	for _, family := range []core.ESDTType{core.Fungible, core.NonFungibleV2, core.SemiFungible, core.MetaFungible, core.DynamicNFT, core.DynamicSFT, core.DynamicMeta} {
		for _, preserve := range []bool{false, true} {
			for _, origin := range []bool{false, true} {
				t.Run(fmt.Sprintf("family%d/preserve%t/origin%t", family, preserve, origin), func(t *testing.T) {
					f, s, h := qualSetupNew(t, uint32(family), preserve, origin)
					require.NoError(t, qualSetupExecute(f, s))
					sk, pk := qualSetupKeys()
					supply := qualActivationValue(t, f.x.f.store, sk)
					position := qualActivationValue(t, f.x.f.store, pk)
					if origin {
						var root []byte
						if family != core.Fungible {
							root = qualSetupRoot()
						}
						require.Equal(t, qualRecordFrame([]byte{0, 0, 0, 1}, []byte("TOKEN-abcdef"), binary.BigEndian.AppendUint32(nil, uint32(family)), f.h.fields.supplyOrigin,
							binary.BigEndian.AppendUint32(nil, f.h.fields.supplyOriginShard), nil, nil, root, make([]byte, 8)), supply)
					} else {
						require.Empty(t, supply)
					}
					if preserve {
						require.Equal(t, qualRecordFrame([]byte{0, 0, 0, 1}, []byte("TOKEN-abcdef"), binary.BigEndian.AppendUint32(nil, uint32(family)), []byte{1}, qualSetupRoot(), nil, make([]byte, 8)), position)
					} else {
						require.Empty(t, position)
					}
					wantRoots := []bool{}
					if origin && family != core.Fungible {
						wantRoots = append(wantRoots, false)
					}
					if preserve {
						wantRoots = append(wantRoots, true)
					}
					require.Equal(t, wantRoots, append([]bool{}, h.rootCalls...))
					if origin || preserve {
						require.Equal(t, 1, h.reserves)
						require.Equal(t, []byte{1}, qualActivationValue(t, f.x.f.store, []byte("fixture/setup-resource-receipt")))
					} else {
						require.Zero(t, h.reserves)
					}
					// Native initialization alone does not transition or emit an ACK.
					require.Equal(t, qualRecordFrame([]byte("TOKEN-abcdef"), binary.BigEndian.AppendUint64(nil, 1), []byte("SETUP")),
						qualActivationValue(t, f.x.f.store, append([]byte(lifecycleRecordPrefix), qualRecordFrame([]byte("TOKEN-abcdef"))...)))
				})
			}
		}
	}
}

func TestQualDRWASetupInitializationDenialsAndAtomicRefusal(t *testing.T) {
	for _, mode := range []string{"existing supply", "existing position", "sealed", "wrong epoch", "root refusal", "root mutation", "short root", "wrong root", "resource refusal", "resource target write", "resource lifecycle write", "metachain", "save failure"} {
		t.Run(mode, func(t *testing.T) {
			f, s, h := qualSetupNew(t, uint32(core.SemiFungible), true, true)
			sk, pk := qualSetupKeys()
			sentinel := errors.New("synthetic setup input refused")
			switch mode {
			case "existing supply":
				qualRecordPut(t, f.x.f.store, sk, []byte("preserve-existing"))
			case "existing position":
				qualRecordPut(t, f.x.f.store, pk, []byte("preserve-existing"))
			case "sealed":
				qualRecordPut(t, f.x.f.store, append([]byte(lifecycleRecordPrefix), qualRecordFrame([]byte("TOKEN-abcdef"))...), qualRecordFrame([]byte("TOKEN-abcdef"), binary.BigEndian.AppendUint64(nil, 1), []byte("SETUP_SEALED")))
			case "metachain":
				f.r.coordinator, _ = sharding.NewMultiShardCoordinator(3, core.MetachainShardId)
			case "save failure":
				h.reserveHook = func() { f.x.f.store.saveErr = sentinel }
			case "root refusal":
				h.rootError = sentinel
			case "root mutation":
				h.rootHook = func() { qualRecordPut(t, f.x.f.store, []byte("fixture/root-alias"), []byte{1}) }
			case "short root":
				h.shortRoot = true
			case "wrong root":
				h.wrongRoot = true
			case "resource refusal":
				h.reserveError = sentinel
			case "resource target write":
				h.reserveHook = func() { qualRecordPut(t, f.x.f.store, sk, []byte("host-cannot-own-target")) }
			case "resource lifecycle write":
				h.reserveHook = func() {
					qualRecordPut(t, f.x.f.store, append([]byte(lifecycleRecordPrefix), qualRecordFrame([]byte("TOKEN-abcdef"))...), qualRecordFrame([]byte("TOKEN-abcdef"), binary.BigEndian.AppendUint64(nil, 1), []byte("OPEN")))
				}
			}
			root, err := f.x.f.store.RootHash()
			require.NoError(t, err)
			root = bytes.Clone(root)
			journal := f.x.f.store.JournalLen()
			var output *vmcommon.VMOutput
			err = f.x.f.boundary.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
				epoch := uint64(1)
				if mode == "wrong epoch" {
					epoch = 2
				}
				var e error
				output, e = s.initializeOwned(op, f.context, []byte("TOKEN-abcdef"), epoch, f.hash)
				return []*vmcommon.VMOutput{output}, e
			})
			f.x.f.store.saveErr = nil
			require.Error(t, err)
			require.Nil(t, output)
			if mode == "root refusal" || mode == "resource refusal" || mode == "save failure" {
				require.ErrorIs(t, err, sentinel)
			} else if mode == "root mutation" {
				require.ErrorIs(t, err, errInvalidRegistrationRecord)
			} else if mode == "wrong root" || mode == "short root" {
				require.ErrorIs(t, err, errSetupInitialization)
				require.Zero(t, h.reserves)
			} else if mode == "resource lifecycle write" {
				require.ErrorIs(t, err, errCurrentLifecycle)
			} else {
				require.ErrorIs(t, err, errSetupInitialization)
			}
			if mode == "resource refusal" || mode == "resource target write" || mode == "resource lifecycle write" || mode == "save failure" {
				require.Equal(t, 1, h.reserves)
				require.Equal(t, []bool{false, true}, h.rootCalls)
			} else {
				require.Zero(t, h.reserves)
			}
			after, e := f.x.f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, after)
			require.Equal(t, journal, f.x.f.store.JournalLen())
		})
	}
}

func TestQualDRWASetupInitializationNoResetOrStandaloneOwner(t *testing.T) {
	f, s, h := qualSetupNew(t, uint32(core.Fungible), true, true)
	out, err := s.initializeOwned(nil, f.context, []byte("TOKEN-abcdef"), 1, f.hash)
	require.ErrorIs(t, err, errCurrentLifecycle)
	require.Nil(t, out)
	require.Zero(t, h.reserves)
	require.NoError(t, qualSetupExecute(f, s))
	sk, pk := qualSetupKeys()
	supply := bytes.Clone(qualActivationValue(t, f.x.f.store, sk))
	position := bytes.Clone(qualActivationValue(t, f.x.f.store, pk))
	require.ErrorIs(t, qualSetupExecute(f, s), errSetupInitialization)
	require.Equal(t, 1, h.reserves)
	require.Equal(t, supply, qualActivationValue(t, f.x.f.store, sk))
	require.Equal(t, position, qualActivationValue(t, f.x.f.store, pk))
	// A native outer rollback removes both explicit states and the resource write.
	require.NoError(t, f.x.f.boundary.Abort())
	require.Empty(t, qualActivationValue(t, f.x.f.store, sk))
	require.Empty(t, qualActivationValue(t, f.x.f.store, pk))
}

func TestQualDRWASetupInitializationUnavailablePrerequisites(t *testing.T) {
	f, _, host := qualSetupNew(t, uint32(core.Fungible), false, true)
	root, err := f.x.f.store.RootHash()
	require.NoError(t, err)
	root = bytes.Clone(root)
	journal := f.x.f.store.JournalLen()
	for _, mode := range []string{"nil current", "missing current codec", "missing boundary", "nil host"} {
		current := *f.r
		candidate, provider := &current, setupInitializationHost(host)
		switch mode {
		case "nil current":
			candidate = nil
		case "missing current codec":
			current.current = nil
		case "missing boundary":
			current.boundary = nil
		case "nil host":
			provider = nil
		}
		s, e := newSetupInitialization(candidate, provider, 32)
		require.ErrorIs(t, e, errSetupInitialization, mode)
		require.Nil(t, s)
	}
	for _, candidate := range []*setupInitialization{nil, {host: host}} {
		out, e := candidate.initializeOwned(nil, f.context, []byte("TOKEN-abcdef"), 1, f.hash)
		require.ErrorIs(t, e, errSetupInitialization)
		require.Nil(t, out)
	}
	require.Zero(t, host.reserves)
	require.Empty(t, host.rootCalls)
	after, err := f.x.f.store.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
	require.Equal(t, journal, f.x.f.store.JournalLen())
}

func TestQualDRWASetupInitializationNonOriginPositionRootRefusal(t *testing.T) {
	f, s, h := qualSetupNew(t, uint32(core.Fungible), true, false)
	sentinel := errors.New("position root unavailable at non-origin shard")
	h.rootError = sentinel
	root, err := f.x.f.store.RootHash()
	require.NoError(t, err)
	root = bytes.Clone(root)
	journal := f.x.f.store.JournalLen()
	var output *vmcommon.VMOutput
	err = f.x.f.boundary.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
		var e error
		output, e = s.initializeOwned(op, f.context, []byte("TOKEN-abcdef"), 1, f.hash)
		return []*vmcommon.VMOutput{output}, e
	})
	require.Same(t, sentinel, err)
	require.Nil(t, output)
	require.Equal(t, []bool{true}, h.rootCalls)
	require.Zero(t, h.reserves)
	supplyKey, positionKey := qualSetupKeys()
	require.Empty(t, qualActivationValue(t, f.x.f.store, supplyKey))
	require.Empty(t, qualActivationValue(t, f.x.f.store, positionKey))
	after, err := f.x.f.store.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
	require.Equal(t, journal, f.x.f.store.JournalLen())
}
