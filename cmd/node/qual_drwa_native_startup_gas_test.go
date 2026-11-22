package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common/forking"
	commonMock "github.com/multiversx/mx-chain-go/common/mock"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/stretchr/testify/require"
)

// T09-M45 joins the actual native CLI path/epoch table to the later native gas
// constructor. Native nodeRunner.go uses those same two final configuration
// fields. Prices10001/10002 and future epoch3 are diagnostic inputs, not an
// admitted gas profile. No node, core assembly, VM, NTP or network is started.
// Later reload cases characterize upstream behavior; they do not patch it or
// establish sealed-package continuity, full startup or configuration admission.
func TestQualDRWANativeStartupGasFiles(t *testing.T) {
	for _, name := range []string{
		"loaded_default", "cli_directory_override", "missing_future_file",
		"malformed_future_file", "future_transition",
		"future_removed_after_construction", "future_changed_after_construction",
	} {
		t.Run(name, func(t *testing.T) {
			dir := qualDRWANativeStartupFixtureDir(t)
			future := name != "loaded_default" && name != "cli_directory_override"
			if future {
				epochPath := filepath.Join(dir, "enableEpochs.toml")
				epochBody, err := os.ReadFile(epochPath)
				require.NoError(t, err)
				const entry = `{ StartEpoch = 0, FileName = "gasScheduleV9.toml" },`
				require.Equal(t, 1, strings.Count(string(epochBody), entry))
				// This is an independently specified hostile/transition input,
				// loaded through readConfigs before its native consumer sees it.
				withFuture := strings.Replace(string(epochBody), entry,
					entry+"\n        { StartEpoch = 3, FileName = \"future.toml\" },", 1)
				require.NoError(t, os.WriteFile(epochPath, []byte(withFuture), 0600))
			}
			gasDir := filepath.Join(dir, "gasSchedules")
			var extra []string
			if name == "cli_directory_override" {
				gasDir = filepath.Join(dir, "selected-gas")
				extra = []string{"--" + gasScheduleConfigurationDirectory.Name, gasDir}
			}
			cfgs, err := qualDRWANativeStartup(t, dir, extra...)
			require.NoError(t, err)
			require.Equal(t, gasDir, cfgs.ConfigurationPathsHolder.GasScheduleDirectoryName)
			expectedTable := []config.GasScheduleByEpochs{{StartEpoch: 0, FileName: "gasScheduleV9.toml"}}
			if future {
				expectedTable = append(expectedTable, config.GasScheduleByEpochs{StartEpoch: 3, FileName: "future.toml"})
			}
			require.Equal(t, expectedTable, cfgs.EpochConfig.GasSchedule.GasScheduleByEpochs)
			candidate, err := qualDRWANativeStartupCandidate(t, dir, cfgs)
			require.NoError(t, err)
			require.NoError(t, candidate.CheckEnforcedBlock(3, 440))

			// The input is an unchanged native file inside the repository, available
			// in a clean git export. It is neither notifier-produced nor external.
			body, err := os.ReadFile(filepath.Join("config", "gasSchedules", "gasScheduleV9.toml"))
			require.NoError(t, err)
			require.Equal(t, "817be1f854faf9082f9f254a3596bfb7ee409fae1b5fc82ad2bbbaedd804b230",
				fmt.Sprintf("%x", sha256.Sum256(body)))
			const marker = "StorePerByte      = 10000"
			require.Equal(t, 1, strings.Count(string(body), marker))
			changed := []byte(strings.Replace(string(body), marker, "StorePerByte      = 10001", 1))
			require.NoError(t, os.Mkdir(gasDir, 0700))
			initial := body
			initialPrice := uint64(10000)
			if name == "cli_directory_override" {
				initial, initialPrice = changed, 10001
			}
			require.NoError(t, os.WriteFile(filepath.Join(gasDir, "gasScheduleV9.toml"), initial, 0600))

			futurePath := filepath.Join(gasDir, "future.toml")
			if future {
				if name != "missing_future_file" {
					futureBody := changed
					if name == "malformed_future_file" {
						futureBody = []byte("[\n")
					}
					require.NoError(t, os.WriteFile(futurePath, futureBody, 0600))
				}
			}
			epochs := forking.NewGenericEpochNotifier()
			gas, err := forking.NewGasScheduleNotifier(forking.ArgsNewGasScheduleNotifier{
				GasScheduleConfig: cfgs.EpochConfig.GasSchedule,
				ConfigDir:         cfgs.ConfigurationPathsHolder.GasScheduleDirectoryName,
				EpochNotifier:     epochs, WasmVMChangeLocker: &sync.RWMutex{},
			})
			if name == "missing_future_file" {
				require.ErrorIs(t, err, os.ErrNotExist)
				require.Nil(t, gas)
				return
			}
			if name == "malformed_future_file" {
				require.Error(t, err)
				require.NotErrorIs(t, err, os.ErrNotExist)
				require.Nil(t, gas)
				return
			}
			require.NoError(t, err)
			t.Cleanup(gas.UnRegisterAll)
			t.Cleanup(epochs.UnRegisterAll)
			require.Equal(t, initialPrice, gas.LatestGasScheduleCopy()["BaseOperationCost"]["StorePerByte"])
			require.Equal(t, uint64(200000), gas.LatestGasScheduleCopy()["BuiltInCost"]["ESDTTransfer"])
			var observed []uint64
			gas.RegisterNotifyHandler(&commonMock.GasScheduleSubscribeHandlerStub{
				GasScheduleChangeCalled: func(schedule map[string]map[string]uint64) {
					observed = append(observed, schedule["BaseOperationCost"]["StorePerByte"])
				},
			})
			require.Equal(t, []uint64{initialPrice}, observed)
			if !future {
				return
			}
			epochs.CheckEpoch(&block.HeaderV3{Epoch: 2})
			require.Equal(t, []uint64{10000}, observed)
			futurePrice := uint64(10001)
			switch name {
			case "future_removed_after_construction":
				require.NoError(t, os.Remove(futurePath))
				futurePrice = 10000
			case "future_changed_after_construction":
				changedAgain := []byte(strings.Replace(string(body), marker, "StorePerByte      = 10002", 1))
				require.NoError(t, os.WriteFile(futurePath, changedAgain, 0600))
				futurePrice = 10002
			}
			epochs.CheckEpoch(&block.HeaderV3{Epoch: 3})
			require.Equal(t, futurePrice, gas.LatestGasScheduleCopy()["BaseOperationCost"]["StorePerByte"])
			if name == "future_removed_after_construction" {
				require.Equal(t, []uint64{10000}, observed, "native reload failure retains prior gas without a subscriber update")
			} else {
				require.Equal(t, []uint64{10000, futurePrice}, observed)
			}
			epochs.CheckEpoch(&block.HeaderV3{Epoch: 4})
			require.Equal(t, futurePrice, gas.LatestGasScheduleCopy()["BaseOperationCost"]["StorePerByte"])
			if name == "future_removed_after_construction" {
				require.Equal(t, []uint64{10000}, observed)
			} else {
				require.Equal(t, []uint64{10000, futurePrice}, observed)
			}
		})
	}
}
