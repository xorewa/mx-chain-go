package drwa

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/common"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// These are actual native type and global-burn functions, authenticated trie
// witnesses and T08/T04 materialization. The selected header's authority is an
// explicit synthetic fixture, not a native consensus/import or network proof.
func TestQualDRWAT44T45MaterializationBeforeNativeEffects(t *testing.T) {
	families := []string{core.FungibleESDT, core.NonFungibleESDTv2, core.SemiFungibleESDT, core.MetaESDT,
		core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT}
	// Independent native global type encodings, vm-common v1.7.2
	// esdtGlobalSettings.go enum; do not generate them with the SUT.
	types := []byte{1, 3, 5, 4, 6, 7, 8}
	for i, family := range families {
		for _, auto := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/auto_%t", family, auto), func(t *testing.T) {
				f := qualBurnFixtureFor(t, auto, family, "", nil)
				f.args.EnableEpochsHandler.(vmcommon.EpochSubscriberHandler).EpochConfirmed(7, 0)
				root, err := f.db.RootHash()
				require.NoError(t, err)
				require.Error(t, f.b.MaterializeRegistration(f.id, f.w), "no authenticated membership before preparation")
				after, err := f.db.RootHash()
				require.NoError(t, err)
				require.Equal(t, root, after)
				require.Empty(t, qualBurnValue(t, f.db, f.id))
				qualBurnPrepare(t, f)
				for replay := 0; replay < 3; replay++ {
					require.NoError(t, f.b.MaterializeRegistration(f.id, f.w))
					require.Equal(t, []byte{0, types[i]}, qualBurnValue(t, f.db, f.id))
					want, err := core.ConvertESDTTypeToUint32(family)
					require.NoError(t, err)
					actual, err := f.b.metadata.GetTokenType([]byte("ELRONDesdtTOKEN-abcdef"))
					require.NoError(t, err)
					require.Equal(t, want, actual)
					for _, function := range []string{vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll} {
						_, err := f.b.ProcessBuiltinFunction(qualBurnInput(f.id, function))
						require.Error(t, err)
						require.Equal(t, []byte{0, types[i]}, qualBurnValue(t, f.db, f.id))
					}
				}
			})
		}
	}
}

// Native container dispatch, with the actual per-function flag and byte/state
// differential. CallType variants exercise the shared dispatch inputs; they
// do not pretend to be signed/relayed/VM/callback processor executions.
func TestQualDRWAT44T45NativeContainerGuardAndOrdinaryDifferential(t *testing.T) {
	functions := []string{vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll, core.ESDTSetTokenType}
	for _, name := range functions {
		for _, kind := range []vmData.CallType{vmData.DirectCall, vmData.AsynchronousCall, vmData.AsynchronousCallBack} {
			t.Run(fmt.Sprintf("%s/type_%d", name, kind), func(t *testing.T) {
				f, control := qualBurnFixtureFor(t, false, core.FungibleESDT, "", nil), qualBurnFixtureFor(t, false, core.FungibleESDT, "", nil)
				for _, fixture := range []*qualBurnFixture{f, control} {
					fixture.args.EnableEpochsHandler.(vmcommon.EpochSubscriberHandler).EpochConfirmed(7, 0)
					qualBurnPrepare(t, fixture)
				}
				container := builtInFunctions.NewBuiltInFunctionContainer()
				require.NoError(t, container.Add(vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, f.b.set))
				require.NoError(t, container.Add(vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll, f.b.unset))
				require.NoError(t, container.Add(core.ESDTSetTokenType, f.b.ordinaryType))
				require.NoError(t, f.b.BindBuiltinFunctions(container, f.args.Accounts, f.args.EnableEpochsHandler))
				selected, err := container.Get(name)
				require.NoError(t, err)
				require.NoError(t, f.b.BindBuiltinFunctions(container, f.args.Accounts, f.args.EnableEpochsHandler))
				again, err := container.Get(name)
				require.NoError(t, err)
				require.Same(t, selected, again)
				input := qualBurnInput(f.id, name)
				input.CallType = kind
				if name == core.ESDTSetTokenType {
					input.Arguments = append(input.Arguments, []byte(core.FungibleESDT))
				}
				before, err := f.db.RootHash()
				require.NoError(t, err)
				_, err = selected.ProcessBuiltinFunction(nil, nil, input)
				require.Error(t, err)
				after, err := f.db.RootHash()
				require.NoError(t, err)
				require.Equal(t, before, after)
				var native vmcommon.BuiltinFunction
				switch name {
				case core.ESDTSetTokenType:
					native = control.b.ordinaryType
				case vmcommon.BuiltInFunctionESDTSetBurnRoleForAll:
					native = control.b.set
				default:
					native = control.b.unset
				}
				require.Equal(t, native.IsActive(), selected.IsActive())
				// Same complete registry proves this OTHER identifier ordinary.
				input.Arguments[0] = []byte("PLAIN-abcdef")
				actual, actualErr := selected.ProcessBuiltinFunction(nil, nil, input)
				expected, expectedErr := native.ProcessBuiltinFunction(nil, nil, input)
				require.Equal(t, expectedErr, actualErr)
				require.Equal(t, expected, actual)
				a, err := f.db.RootHash()
				require.NoError(t, err)
				b, err := control.db.RootHash()
				require.NoError(t, err)
				require.True(t, bytes.Equal(a, b))
			})
		}
	}
}

type qualRegistrationContainerFault struct {
	vmcommon.BuiltInFunctionContainer
	calls, failAt int
	after         bool
	fault         error
}

func (c *qualRegistrationContainerFault) Replace(name string, fn vmcommon.BuiltinFunction) error {
	c.calls++
	if c.calls == c.failAt {
		if c.after {
			if err := c.BuiltInFunctionContainer.Replace(name, fn); err != nil {
				return err
			}
		}
		return c.fault
	}
	return c.BuiltInFunctionContainer.Replace(name, fn)
}

func TestQualDRWAT44T45NativeContainerBindingFailure(t *testing.T) {
	for index := 1; index <= 3; index++ {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("entry_%d/after_%t", index, after), func(t *testing.T) {
				f := qualBurnFixtureFor(t, false, core.FungibleESDT, "", nil)
				qualBurnPrepare(t, f)
				container := builtInFunctions.NewBuiltInFunctionContainer()
				old := map[string]vmcommon.BuiltinFunction{vmcommon.BuiltInFunctionESDTSetBurnRoleForAll: f.b.set,
					vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll: f.b.unset, core.ESDTSetTokenType: f.b.ordinaryType}
				for name, fn := range old {
					require.NoError(t, container.Add(name, fn))
				}
				original := errors.New("native container replacement")
				fault := &qualRegistrationContainerFault{BuiltInFunctionContainer: container, failAt: index, after: after, fault: original}
				require.ErrorIs(t, f.b.BindBuiltinFunctions(fault, f.args.Accounts, f.args.EnableEpochsHandler), original)
				for name, fn := range old {
					actual, err := container.Get(name)
					require.NoError(t, err)
					require.Same(t, fn, actual)
				}
			})
		}
	}
}

func TestQualDRWAT44T45MaterializationProvenanceAndEpoch(t *testing.T) {
	for _, fault := range []string{"association-manager", "intent-status", "activation", "association-digest", "missing-association", "before-native-type-epoch"} {
		t.Run(fault, func(t *testing.T) {
			fixtureFault := fault
			if fault == "before-native-type-epoch" {
				fixtureFault = ""
			}
			f := qualBurnFixtureFor(t, false, core.FungibleESDT, fixtureFault, nil)
			f.args.EnableEpochsHandler.(vmcommon.EpochSubscriberHandler).EpochConfirmed(7, 0)
			if fault == "before-native-type-epoch" {
				f.args.EnableEpochsHandler.(vmcommon.EpochSubscriberHandler).EpochConfirmed(6, 0)
			}
			qualBurnPrepare(t, f)
			before, err := f.db.RootHash()
			require.NoError(t, err)
			require.Error(t, f.b.MaterializeRegistration(f.id, f.w))
			after, err := f.db.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Empty(t, qualBurnValue(t, f.db, f.id))
			require.False(t, f.b.normalizing)
			if fault == "before-native-type-epoch" {
				require.False(t, f.args.EnableEpochsHandler.IsFlagEnabled(common.DynamicESDTFlag))
			}
		})
	}
}
