package processing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/factory"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/stretchr/testify/require"
)

func TestQualDRWAOriginalIdentityFinalHeaderBoundary(t *testing.T) {
	f, identity := qualD18StartupFactory(t)
	path := f.coreData.PathHandler().DatabasePath()
	f.drwaInitialProgrammeStartup = &config.DRWAInitialProgrammeStartup{OriginalDatabasePath: path}
	header := &block.MetaBlock{}
	require.NoError(t, f.coreData.InternalMarshalizer().Unmarshal(header, identity.Header()))
	require.NoError(t, header.SetValidatorStatsRootHash([]byte("different validator statistics root")))
	loaded, err := f.readConfiguredDRWAIdentity()
	require.NoError(t, err)
	require.Equal(t, identity.Header(), loaded.Header())

	unit, err := f.openFinalizedDRWAGenesis(loaded, header)
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	require.Nil(t, unit)
	unitPath, err := drwaIdentityPath(path)
	require.NoError(t, err)
	_, err = os.Lstat(unitPath)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.Nil(t, f.drwaIdentityOwner.unit)
}

func TestQualDRWAOriginalIdentityAttemptCannotBeReused(t *testing.T) {
	f := &processComponentsFactory{drwaInitialProgrammeStartup: &config.DRWAInitialProgrammeStartup{}}
	components, err := f.Create()
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	require.Nil(t, components)
	require.True(t, f.drwaOriginalGenesisStarted.Load())
	components, err = f.Create()
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	require.Nil(t, components)
	require.Nil(t, f.drwaIdentityOwner.unit)
}

// Labelled technical construction input only; no deployment/creating-owner proof.
type qualD18Path struct {
	storage.PathManagerHandler
	path string
}

func (p *qualD18Path) DatabasePath() string { return p.path }
func (p *qualD18Path) IsInterfaceNil() bool { return p == nil }

type qualD18Core struct {
	factory.CoreComponentsHolder
	path  string
	chain string
}

func (c *qualD18Core) InternalMarshalizer() marshal.Marshalizer {
	return &marshal.GogoProtoMarshalizer{}
}
func (c *qualD18Core) Hasher() hashing.Hasher                  { return blake2b.NewBlake2b() }
func (c *qualD18Core) ChainID() string                         { return c.chain }
func (c *qualD18Core) PathHandler() storage.PathManagerHandler { return &qualD18Path{path: c.path} }
func (c *qualD18Core) IsInterfaceNil() bool                    { return c == nil }

type qualD18VMClose struct {
	process.VirtualMachinesContainerFactory
	close func() error
}

func (c *qualD18VMClose) Close() error         { return c.close() }
func (c *qualD18VMClose) IsInterfaceNil() bool { return c == nil }

type qualD18IdentityClose struct {
	drwaIdentityDB
	close func() error
}

func (c *qualD18IdentityClose) Close() error { return c.close() }

func qualD18StartupFactory(t *testing.T) (*processComponentsFactory, *drwa.DeploymentIdentity) {
	t.Helper()
	identity := qualA77Identity(t)
	root := t.TempDir()
	input := filepath.Join(root, "identity")
	require.NoError(t, os.WriteFile(input, identity.Raw(), 0600))
	pin := sha256.Sum256(identity.Raw())
	cfg := &config.DRWADeploymentIdentityConfig{Path: input, SHA256: hex.EncodeToString(pin[:]), MaxBytes: 4096, MaxChainIDBytes: 64, MaxHeaderBytes: 2048, DB: qualA77IdentityParameters()}
	f := &processComponentsFactory{drwaDeploymentIdentity: cloneDRWAIdentityConfig(cfg), coreData: &qualD18Core{path: filepath.Join(root, "chain"), chain: "synthetic chain"}}
	f.config.EpochStartConfig.GenesisEpoch = 17
	return f, identity
}
func TestQualD18NativeIdentityStartup(t *testing.T) {
	for _, closeFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "restart_close_recreate", true: "failed_close_retains_owner"}[closeFailure], func(t *testing.T) {
			f, identity := qualD18StartupFactory(t)
			// Seed only through the existing labelled primitive. This is not a native
			// fresh-genesis admission or an executable business context.
			seed := &drwaIdentityLifecycle{}
			unit, err := seed.open(f.coreData.PathHandler().DatabasePath(), f.drwaDeploymentIdentity.DB, identity, qualA77IdentityFresh(identity))
			require.NoError(t, err)
			require.NoError(t, unit.Close())
			unit, err = f.openConfiguredDRWAIdentity()
			require.NoError(t, err)
			require.Equal(t, identity.Domain(), unit.Domain())
			_, err = f.openConfiguredDRWAIdentity()
			require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
			order := []string{}
			failure := errors.New("synthetic native close acknowledgement failure")
			db := unit.db
			unit.db = &qualD18IdentityClose{drwaIdentityDB: db, close: func() error {
				order = append(order, "identity")
				err := db.Close()
				if closeFailure {
					return errors.Join(err, failure)
				}
				return err
			}}
			pc := &processComponents{drwaNetworkIdentity: unit, vmFactoryForTxSimulator: &qualD18VMClose{close: func() error { order = append(order, "simulator"); return nil }}, vmFactoryForProcessing: &qualD18VMClose{close: func() error { order = append(order, "processing"); return nil }}}
			managed := &managedProcessComponents{processComponents: pc, factory: f}
			err = managed.Close()
			require.Equal(t, []string{"simulator", "processing", "identity"}, order)
			require.Nil(t, unit.Domain())
			if closeFailure {
				require.ErrorIs(t, err, failure)
				require.Same(t, pc, managed.processComponents)
				_, err = f.openConfiguredDRWAIdentity()
				require.ErrorIs(t, err, failure)
				return
			}
			require.NoError(t, err)
			require.Nil(t, managed.processComponents)
			unit, err = f.openConfiguredDRWAIdentity()
			require.NoError(t, err)
			require.NoError(t, (&processComponents{drwaNetworkIdentity: unit}).Close())
		})
	}
}
func TestQualD18NativeIdentityStartupRefusals(t *testing.T) {
	for _, fault := range []string{"missing_record", "bad_digest", "bad_chain", "bad_epoch", "zero_bound", "absent_file", "symlink", "directory", "missing_core"} {
		t.Run(fault, func(t *testing.T) {
			f, _ := qualD18StartupFactory(t)
			switch fault {
			case "bad_digest":
				f.drwaDeploymentIdentity.SHA256 = "00"
			case "bad_chain":
				f.coreData.(*qualD18Core).chain = "wrong chain"
			case "bad_epoch":
				f.config.EpochStartConfig.GenesisEpoch = 18
			case "zero_bound":
				f.drwaDeploymentIdentity.MaxBytes = 0
			case "absent_file":
				f.drwaDeploymentIdentity.Path = filepath.Join(t.TempDir(), "absent")
			case "symlink":
				p := filepath.Join(t.TempDir(), "link")
				require.NoError(t, os.Symlink(f.drwaDeploymentIdentity.Path, p))
				f.drwaDeploymentIdentity.Path = p
			case "directory":
				f.drwaDeploymentIdentity.Path = t.TempDir()
			case "missing_core":
				f.coreData = nil
			}
			// Actual Create refuses before any native factory side effect. All remaining
			// dependencies are absent, so entering that body would panic, not pass.
			pc, err := f.Create()
			require.Error(t, err)
			require.Nil(t, pc)
			require.Nil(t, f.drwaIdentityOwner.unit)
		})
	}
}
func TestQualD18UnconfiguredNativeCloseComparison(t *testing.T) {
	f := &processComponentsFactory{}
	unit, err := f.openConfiguredDRWAIdentity()
	require.NoError(t, err)
	require.Nil(t, unit)
	for _, failure := range []error{nil, errors.New("ordinary native close error")} {
		run := func(untouched bool) ([]string, error) {
			calls := []string{}
			pc := &processComponents{vmFactoryForTxSimulator: &qualD18VMClose{close: func() error { calls = append(calls, "simulator"); return failure }}, vmFactoryForProcessing: &qualD18VMClose{close: func() error { calls = append(calls, "processing"); return nil }}}
			if untouched {
				err := qualD18UntouchedNativeClose(pc)
				return calls, err
			}
			err := pc.Close()
			return calls, err
		}
		// Evaluate calls before taking their returned slice, including baseline.
		expected, e := run(true)
		actual, a := run(false)
		require.Equal(t, e, a)
		require.Equal(t, expected, actual)
	}
}

// Exact native function body from official mx-chain-go 06c383cf316ab391d60695a4eeb7c085fb40232b,
// factory/processing/processComponents.go; source identity retained in TASK_RECORD.
func qualD18UntouchedNativeClose(pc *processComponents) error {
	if !check.IfNil(pc.blockProcessor) {
		log.LogIfError(pc.blockProcessor.Close())
	}
	if !check.IfNil(pc.executionManager) {
		log.LogIfError(pc.executionManager.Close())
	}
	if !check.IfNil(pc.validatorsProvider) {
		log.LogIfError(pc.validatorsProvider.Close())
	}
	if !check.IfNil(pc.miniBlocksPoolCleaner) {
		log.LogIfError(pc.miniBlocksPoolCleaner.Close())
	}
	if !check.IfNil(pc.txsPoolCleaner) {
		log.LogIfError(pc.txsPoolCleaner.Close())
	}
	if !check.IfNil(pc.epochStartTrigger) {
		log.LogIfError(pc.epochStartTrigger.Close())
	}
	if !check.IfNil(pc.importHandler) {
		log.LogIfError(pc.importHandler.Close())
	}
	// only calling close on the mainInterceptorsContainer as it should be the same interceptors on full archive
	if !check.IfNil(pc.mainInterceptorsContainer) {
		log.LogIfError(pc.mainInterceptorsContainer.Close())
	}
	if !check.IfNil(pc.vmFactoryForTxSimulator) {
		log.LogIfError(pc.vmFactoryForTxSimulator.Close())
	}
	if !check.IfNil(pc.vmFactoryForProcessing) {
		log.LogIfError(pc.vmFactoryForProcessing.Close())
	}
	if !check.IfNil(pc.txsSender) {
		log.LogIfError(pc.txsSender.Close())
	}
	if !check.IfNil(pc.interceptedDataVerifierFactory) {
		log.LogIfError(pc.interceptedDataVerifierFactory.Close())
	}
	if !check.IfNil(pc.aotSelector) {
		log.LogIfError(pc.aotSelector.Close())
	}
	if !check.IfNil(pc.blockTracker) {
		log.LogIfError(pc.blockTracker.Close())
	}

	return nil
}

// Synthetic technical input only, through the actual existing loader. No
// profile/default, deployment identity or native fresh-admission fact is supplied.
func TestQualD18IdentityNativeConfigurationLoader(t *testing.T) {
	fixture := filepath.Join("..", "..", "cmd", "node", "config", "config.toml")
	legacy, err := common.LoadMainConfig(fixture)
	require.NoError(t, err)
	require.Nil(t, legacy.GeneralSettings.DRWADeploymentIdentity)
	raw, err := os.ReadFile(fixture)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "synthetic-config.toml")
	table := fmt.Sprintf(`
[GeneralSettings.DRWADeploymentIdentity]
Path = %q
SHA256 = "synthetic-not-a-deployment-pin"
MaxBytes = 4096
MaxChainIDBytes = 64
MaxHeaderBytes = 2048
[GeneralSettings.DRWADeploymentIdentity.DB]
MaxBatchSize = 1
`, path)
	require.NoError(t, os.WriteFile(path, append(raw, []byte(table)...), 0600))
	loaded, err := common.LoadMainConfig(path)
	require.NoError(t, err)
	input := loaded.GeneralSettings.DRWADeploymentIdentity
	require.NotNil(t, input)
	require.Equal(t, path, input.Path)
	require.Equal(t, "synthetic-not-a-deployment-pin", input.SHA256)
	require.Equal(t, 4096, input.MaxBytes)
	require.Equal(t, 64, input.MaxChainIDBytes)
	require.Equal(t, 2048, input.MaxHeaderBytes)
	require.EqualValues(t, 1, input.DB.MaxBatchSize)
	cloned := cloneDRWAIdentityConfig(input)
	input.Path = "synthetic changed input"
	input.DB.MaxBatchSize = 2
	require.Equal(t, path, cloned.Path)
	require.EqualValues(t, 1, cloned.DB.MaxBatchSize)
	before, err := json.Marshal(legacy.GeneralSettings)
	require.NoError(t, err)
	after, err := json.Marshal(loaded.GeneralSettings)
	require.NoError(t, err)
	require.Equal(t, before, after, "optional technical pointer is not an ordinary JSON API change")
}

func TestQualD18IdentityRefusalAttribution(t *testing.T) {
	for _, fault := range []string{"wrong_pin", "wrong_chain", "wrong_epoch", "zero_bound", "absent_file", "directory", "direct_symlink", "parent_symlink_dotdot", "missing_core"} {
		t.Run(fault, func(t *testing.T) {
			f, identity := qualD18StartupFactory(t)
			seed := &drwaIdentityLifecycle{}
			unit, err := seed.open(f.coreData.PathHandler().DatabasePath(), f.drwaDeploymentIdentity.DB, identity, qualA77IdentityFresh(identity))
			require.NoError(t, err)
			require.NoError(t, unit.Close())
			unit, err = f.openConfiguredDRWAIdentity()
			require.NoError(t, err)
			require.NoError(t, unit.Close())
			validInput := cloneDRWAIdentityConfig(f.drwaDeploymentIdentity)
			validCore := *f.coreData.(*qualD18Core)
			validConfig := f.config
			before := f.drwaIdentityOwner.unit
			switch fault {
			case "wrong_pin":
				f.drwaDeploymentIdentity.SHA256 = hex.EncodeToString(make([]byte, sha256.Size))
			case "wrong_chain":
				f.coreData.(*qualD18Core).chain = "synthetic other chain"
			case "wrong_epoch":
				f.config.EpochStartConfig.GenesisEpoch++
			case "zero_bound":
				f.drwaDeploymentIdentity.MaxBytes = 0
			case "absent_file":
				f.drwaDeploymentIdentity.Path = filepath.Join(t.TempDir(), "missing")
			case "directory":
				f.drwaDeploymentIdentity.Path = t.TempDir()
			case "direct_symlink":
				alias := filepath.Join(t.TempDir(), "alias")
				require.NoError(t, os.Symlink(validInput.Path, alias))
				f.drwaDeploymentIdentity.Path = alias
			case "parent_symlink_dotdot":
				root := t.TempDir()
				other := t.TempDir()
				inside := filepath.Join(other, "inside")
				require.NoError(t, os.Mkdir(inside, 0700))
				require.NoError(t, os.WriteFile(filepath.Join(other, "identity"), identity.Raw(), 0600))
				alias := filepath.Join(root, "alias")
				require.NoError(t, os.Symlink(inside, alias))
				f.drwaDeploymentIdentity.Path = alias + "/../identity" // Join would erase the adversarial component.
			case "missing_core":
				f.coreData = nil
			}
			unit, err = f.openConfiguredDRWAIdentity()
			if unit != nil {
				require.NoError(t, unit.Close())
			} // Retain/close an unexpected baseline acceptance before failing.
			require.Error(t, err, "named guard must refuse with an otherwise valid retained record")
			require.Nil(t, unit)
			require.Same(t, before, f.drwaIdentityOwner.unit)
			f.drwaDeploymentIdentity = validInput
			f.coreData = &validCore
			f.config = validConfig
			unit, err = f.openConfiguredDRWAIdentity()
			require.NoError(t, err, "restored positive technical control")
			require.NoError(t, unit.Close())
		})
	}
}
