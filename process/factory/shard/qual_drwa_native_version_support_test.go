package shard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/forking"
	commonMock "github.com/multiversx/mx-chain-go/common/mock"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process/factory"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

// Development-only T32 adoption experiment, independently specified in
// T32_D04_D08_support_expected_model_01.md before this file. Actual native VM
// construction/selection and TOML gas loaders are exercised; no DRWA parser,
// profile, repair authority, canonical release, network or NORMAL exit is proved.
// The fixture epochs/costs are synthetic inputs, not deployment parameters.
func TestQualDRWANativeVersionTable(t *testing.T) {
	t.Run("three_epoch_intervals", func(t *testing.T) {
		args := createMockVMAccountsArguments()
		args.Config.WasmVMVersions = []config.WasmVMVersionByEpoch{
			{StartEpoch: 4, Version: "v1.4"},
			{StartEpoch: 0, Version: "v1.2"},
			{StartEpoch: 2, Version: "v1.3"},
		}
		vmf, err := NewVMContainerFactory(args)
		require.NoError(t, err)
		for _, tc := range []struct {
			epoch uint32
			want  string
		}{{0, "v1.2"}, {1, "v1.2"}, {2, "v1.3"}, {3, "v1.3"}, {4, "v1.4"}, {5, "v1.4"}, {^uint32(0), "v1.4"}} {
			t.Run(fmt.Sprint(tc.epoch), func(t *testing.T) {
				require.Equal(t, tc.want, vmf.getMatchingVersion(tc.epoch).Version)
			})
		}
		// Native constructor sorts its supplied table, including the caller's
		// shared slice. This is not a privately retained historical manifest.
		require.Equal(t, []config.WasmVMVersionByEpoch{
			{StartEpoch: 0, Version: "v1.2"}, {StartEpoch: 2, Version: "v1.3"}, {StartEpoch: 4, Version: "v1.4"},
		}, args.Config.WasmVMVersions)
	})
	for _, tc := range []struct {
		name string
		rows []config.WasmVMVersionByEpoch
		want error
	}{
		{"missing", nil, ErrEmptyVersionsByEpochsList},
		{"missing_epoch_zero", []config.WasmVMVersionByEpoch{{StartEpoch: 2, Version: "v1.3"}}, ErrInvalidVersionOnEpochValues},
		{"duplicate_start", []config.WasmVMVersionByEpoch{{StartEpoch: 0, Version: "v1.2"}, {StartEpoch: 2, Version: "v1.3"}, {StartEpoch: 2, Version: "v1.4"}}, ErrInvalidVersionOnEpochValues},
		{"oversize_version", []config.WasmVMVersionByEpoch{{StartEpoch: 0, Version: strings.Repeat("x", common.MaxSoftwareVersionLengthInBytes+1)}}, ErrInvalidVersionStringTooLong},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := createMockVMAccountsArguments()
			args.Config.WasmVMVersions = tc.rows
			vmf, err := NewVMContainerFactory(args)
			require.ErrorIs(t, err, tc.want)
			require.Nil(t, vmf)
		})
	}
}

func TestQualDRWANativeVMReplacementIsNotRecordSupport(t *testing.T) {
	args := createMockVMAccountsArguments()
	args.Config.WasmVMVersions = []config.WasmVMVersionByEpoch{
		{StartEpoch: 0, Version: "v1.2"}, {StartEpoch: 2, Version: "v1.3"}, {StartEpoch: 4, Version: "v1.4"},
	}
	notifier := forking.NewGenericEpochNotifier()
	args.EpochNotifier = notifier
	clears := 0
	args.BlockChainHook = &testscommon.BlockChainHookStub{ClearCompiledCodesCalled: func() { clears++ }}
	vmf, err := NewVMContainerFactory(args)
	require.NoError(t, err)
	container, err := vmf.Create() // VM subfactory only; no node factory or network.
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, container.Close()) })
	require.Equal(t, 1, clears) // Initial gas notification clears compiled code.
	previous, err := container.Get(factory.WasmVirtualMachine)
	require.NoError(t, err)
	require.Equal(t, "v1.2", previous.GetVersion())
	for i, tc := range []struct {
		epoch   uint32
		want    string
		changed bool
		clears  int
	}{{1, "v1.2", false, 1}, {2, "v1.3", true, 2}, {3, "v1.3", false, 2},
		{4, "v1.4", true, 3}, {5, "v1.4", false, 3}, {0, "v1.2", true, 5}, {2, "v1.3", true, 6}} {
		t.Run(fmt.Sprintf("step_%d_epoch_%d", i, tc.epoch), func(t *testing.T) {
			// At epoch zero, the prior v1.4 host remains subscribed after Close
			// and clears once for its fixture activation flags, in addition to
			// the factory replacement clear (hostCore/host.go:555-561).
			// Historical notification is a bounded subconstructor experiment,
			// not a node reorg, historical contract replay or recovery proof.
			notifier.CheckEpoch(makeHeaderHandlerStub(tc.epoch))
			current, readErr := container.Get(factory.WasmVirtualMachine)
			require.NoError(t, readErr)
			require.Equal(t, tc.want, current.GetVersion())
			if tc.changed {
				require.NotSame(t, previous, current)
			} else {
				require.Same(t, previous, current)
			}
			require.Equal(t, tc.clears, clears)
			require.Equal(t, 1, container.Len(), "one native Wasm key, not three simultaneous record interpreters")
			require.Equal(t, [][]byte{factory.WasmVirtualMachine}, container.Keys())
			previous = current
		})
	}
}

func TestQualDRWANativeWildcardDoesNotNameInterpretation(t *testing.T) {
	args := createMockVMAccountsArguments()
	args.Config.WasmVMVersions = []config.WasmVMVersionByEpoch{
		{StartEpoch: 0, Version: "v1.2"}, {StartEpoch: 2, Version: "*"}, {StartEpoch: 4, Version: "v1.3"},
	}
	notifier := forking.NewGenericEpochNotifier()
	args.EpochNotifier = notifier
	vmf, err := NewVMContainerFactory(args)
	require.NoError(t, err)
	container, err := vmf.Create()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, container.Close()) })
	first, err := container.Get(factory.WasmVirtualMachine)
	require.NoError(t, err)
	notifier.CheckEpoch(makeHeaderHandlerStub(2))
	wildcard, err := container.Get(factory.WasmVirtualMachine)
	require.NoError(t, err)
	require.Same(t, first, wildcard)
	require.Equal(t, "v1.2", wildcard.GetVersion())
	notifier.CheckEpoch(makeHeaderHandlerStub(4))
	newer, err := container.Get(factory.WasmVirtualMachine)
	require.NoError(t, err)
	require.NotSame(t, first, newer)
	require.Equal(t, "v1.3", newer.GetVersion())
	notifier.CheckEpoch(makeHeaderHandlerStub(2))
	retained, err := container.Get(factory.WasmVirtualMachine)
	require.NoError(t, err)
	require.Same(t, newer, retained)
	require.Equal(t, "v1.3", retained.GetVersion(), "wildcard does not select a specific historical VM")
}

func TestQualDRWANativeGasLoaderRetentionBoundary(t *testing.T) {
	for _, mode := range []string{"activation_and_copy", "missing_at_construction", "removed_after_validation"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			bodies := []string{"[BaseOperationCost]\nAoTPreparePerByte = 31\n", "[BaseOperationCost]\nAoTPreparePerByte = 47\n", "[BaseOperationCost]\nAoTPreparePerByte = 59\n"}
			paths := make([]string, 3)
			for i, body := range bodies {
				paths[i] = filepath.Join(dir, fmt.Sprintf("fixture_%d.toml", i))
				require.NoError(t, os.WriteFile(paths[i], []byte(body), 0600))
			}
			if mode == "missing_at_construction" {
				require.NoError(t, os.Remove(paths[1]))
			}
			args := forking.ArgsNewGasScheduleNotifier{
				ConfigDir: dir, EpochNotifier: forking.NewGenericEpochNotifier(), WasmVMChangeLocker: &sync.RWMutex{},
				GasScheduleConfig: config.GasScheduleConfig{GasScheduleByEpochs: []config.GasScheduleByEpochs{
					{StartEpoch: 0, FileName: filepath.Base(paths[0])}, {StartEpoch: 2, FileName: filepath.Base(paths[1])}, {StartEpoch: 4, FileName: filepath.Base(paths[2])},
				}},
			}
			g, err := forking.NewGasScheduleNotifier(args)
			if mode == "missing_at_construction" {
				require.Error(t, err)
				require.Nil(t, g)
				return
			}
			require.NoError(t, err)
			observed := make([]uint64, 0)
			g.RegisterNotifyHandler(&commonMock.GasScheduleSubscribeHandlerStub{GasScheduleChangeCalled: func(costs map[string]map[string]uint64) {
				observed = append(observed, costs["BaseOperationCost"]["AoTPreparePerByte"])
			}})
			oldCopy := g.LatestGasScheduleCopy()
			require.Equal(t, uint64(31), oldCopy["BaseOperationCost"]["AoTPreparePerByte"])
			if mode == "removed_after_validation" {
				require.NoError(t, os.Remove(paths[1]))
				g.EpochConfirmed(2, 0)
				require.Equal(t, uint64(31), g.LatestGasSchedule()["BaseOperationCost"]["AoTPreparePerByte"])
				require.Equal(t, []uint64{31}, observed, "failed reload cannot publish target gas")
				require.NoError(t, os.WriteFile(paths[1], []byte(bodies[1]), 0600))
				g.EpochConfirmed(1, 0) // Same fixture crosses back before retry.
				g.EpochConfirmed(2, 0)
				require.Equal(t, uint64(47), g.LatestGasSchedule()["BaseOperationCost"]["AoTPreparePerByte"])
				require.Equal(t, []uint64{31, 31, 47}, observed)
				return
			}
			g.EpochConfirmed(1, 0)
			require.Equal(t, []uint64{31}, observed)
			g.EpochConfirmed(2, 0)
			middleCopy := g.LatestGasScheduleCopy()
			require.Equal(t, uint64(47), middleCopy["BaseOperationCost"]["AoTPreparePerByte"])
			g.EpochConfirmed(3, 0)
			g.EpochConfirmed(4, 0)
			require.Equal(t, []uint64{31, 47, 59}, observed)
			require.Equal(t, uint64(31), oldCopy["BaseOperationCost"]["AoTPreparePerByte"])
			require.Equal(t, uint64(47), middleCopy["BaseOperationCost"]["AoTPreparePerByte"])
			middleCopy["BaseOperationCost"]["AoTPreparePerByte"] = 999
			currentCopy := g.LatestGasScheduleCopy()
			currentCopy["BaseOperationCost"]["AoTPreparePerByte"] = 999
			require.Equal(t, uint64(59), g.LatestGasSchedule()["BaseOperationCost"]["AoTPreparePerByte"])
			require.Equal(t, uint64(59), g.LatestGasScheduleCopy()["BaseOperationCost"]["AoTPreparePerByte"])
			g.EpochConfirmed(0, 0)
			require.Equal(t, []uint64{31, 47, 59, 31}, observed)
			require.Equal(t, uint64(31), g.LatestGasScheduleCopy()["BaseOperationCost"]["AoTPreparePerByte"])
		})
	}
}
