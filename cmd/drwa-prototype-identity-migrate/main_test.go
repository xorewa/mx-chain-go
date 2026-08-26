package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	coreBlake2b "github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/stretchr/testify/require"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"

	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype/networkidentity"
)

func TestRunExtractRequiresRoleAndLineageBoundTopology(t *testing.T) {
	t.Parallel()

	fixture := newExtractionFixture(t)
	opts := fixture.opts

	require.NoError(t, run(opts))
	extracted, err := os.ReadFile(opts.headerOutputPath)
	require.NoError(t, err)
	require.Equal(t, fixture.finalHeader, extracted)

	evidenceBytes, err := os.ReadFile(opts.evidencePath)
	require.NoError(t, err)
	var evidence migrationEvidence
	require.NoError(t, json.Unmarshal(evidenceBytes, &evidence))
	require.Equal(t, "ROLE_AND_LINEAGE_BOUND_METACHAIN_FINAL_WITH_FOUR_OBSERVER_PRECURSOR_NO_NODE_MUTATION", evidence.Status)
	require.Equal(t, "NOT_APPLIED_EXTRACTION_ONLY", evidence.Provenance)
	require.Len(t, evidence.ObserverRootIdentities, 4)
	require.Len(t, evidence.ObserverObservations, 4)
	require.Equal(t, fixture.bindingPath, evidence.BindingPath)
	require.NotEmpty(t, evidence.BindingSHA256)
	require.Equal(t, opts.headerOutputPath, evidence.HeaderOutputPath)
	require.Equal(t, fixture.planSHA, evidence.TransitionPlanSHA256)
	require.Equal(t, fixture.traceSHA, evidence.TransitionTraceSHA256)
	for index, observation := range evidence.ObserverObservations {
		require.Equal(t, []int{0, 1, 2, 3}, observation.NumericPartitions)
		require.Len(t, observation.PartitionIdentities, 4)
		require.Equal(t, 1, observation.PrecursorMatchCount)
		require.NotEmpty(t, observation.PrecursorSHA256)
		require.NotEmpty(t, observation.PrecursorBlake2b)
		if index == 3 {
			require.Equal(t, 1, observation.FinalMatchCount)
			require.NotEmpty(t, observation.FinalSHA256)
			require.NotEmpty(t, observation.FinalBlake2b)
		} else {
			require.Zero(t, observation.FinalMatchCount)
			require.Empty(t, observation.FinalSHA256)
			require.Empty(t, observation.FinalBlake2b)
		}
	}

	wrongFixture := newExtractionFixture(t)
	wrongOpts := wrongFixture.opts
	wrong := append([]byte(nil), wrongFixture.precursor...)
	wrong[len(wrong)-1] ^= 0xff
	putLevelDBValue(t, filepath.Join(wrongFixture.roots["2"], "0"), []byte(core.EpochStartIdentifier(0)), wrong)
	require.Error(t, run(wrongOpts))
	_, err = os.Stat(wrongOpts.headerOutputPath)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestRunExtractRejectsRoleTopologyAndProvenanceMutations(t *testing.T) {
	t.Run("cross-role partition alias", func(t *testing.T) {
		fixture := newExtractionFixture(t)
		expectedHash, err := decode32("canonical", fixture.opts.expectedCanonicalHash)
		require.NoError(t, err)
		expectedDomain, err := decode32("domain", fixture.opts.expectedDomain)
		require.NoError(t, err)
		var shard0Identity string
		scanner := func(root *heldDirectory, partitions int, precursor string, hash [32]byte) (scannedObserverRoot, error) {
			observation, scanErr := scanObserverRoot(root, partitions, precursor, hash)
			if scanErr != nil {
				return observation, scanErr
			}
			if root.role == "0" {
				shard0Identity = observation.partitionIDs[0]
			}
			if root.role == "1" {
				observation.partitionIDs[0] = shard0Identity
			}
			return observation, nil
		}
		require.ErrorContains(
			t,
			runExtractAmendedWithScanner(fixture.opts, 0, expectedHash, expectedDomain, scanner),
			"alias filesystem identity",
		)
	})

	t.Run("role path swap", func(t *testing.T) {
		fixture := newExtractionFixture(t)
		fixture.opts.shard0ObserverMetaDB, fixture.opts.shard1ObserverMetaDB =
			fixture.opts.shard1ObserverMetaDB, fixture.opts.shard0ObserverMetaDB
		require.ErrorContains(t, run(fixture.opts), "manifest-derived path")
	})

	t.Run("finalized header on shard observer", func(t *testing.T) {
		fixture := newExtractionFixture(t)
		canonicalHash, err := decode32("canonical", fixture.opts.expectedCanonicalHash)
		require.NoError(t, err)
		putLevelDBValue(t, filepath.Join(fixture.roots["0"], "3"), canonicalHash[:], fixture.finalHeader)
		require.ErrorContains(t, run(fixture.opts), "unexpectedly contains finalized header")
	})

	t.Run("finalized header under noncanonical key is absent", func(t *testing.T) {
		fixture := newExtractionFixture(t)
		canonicalHash, err := decode32("canonical", fixture.opts.expectedCanonicalHash)
		require.NoError(t, err)
		deleteLevelDBValue(t, filepath.Join(fixture.roots["metachain"], "2"), canonicalHash[:])
		putLevelDBValue(t, filepath.Join(fixture.roots["metachain"], "2"), []byte("wrong-key"), fixture.finalHeader)
		require.ErrorContains(t, run(fixture.opts), "expected exactly one finalized header, found 0")
	})

	t.Run("one unequal precursor", func(t *testing.T) {
		fixture := newExtractionFixture(t)
		changed := mutateMetaHeader(t, fixture.precursor, func(meta *block.MetaBlock) { meta.Round++ })
		putLevelDBValue(t, filepath.Join(fixture.roots["2"], "0"), []byte(core.EpochStartIdentifier(0)), changed)
		require.ErrorContains(t, run(fixture.opts), "precursor differs")
	})

	t.Run("four equal precursors drift from final", func(t *testing.T) {
		fixture := newExtractionFixture(t)
		changed := mutateMetaHeader(t, fixture.precursor, func(meta *block.MetaBlock) { meta.Round++ })
		for _, role := range []string{"0", "1", "2", "metachain"} {
			putLevelDBValue(t, filepath.Join(fixture.roots[role], "0"), []byte(core.EpochStartIdentifier(0)), changed)
		}
		require.ErrorContains(t, run(fixture.opts), "differs from precursor outside ValidatorStatsRootHash")
	})

	t.Run("embedded plan differs outside timestamp", func(t *testing.T) {
		fixture := newExtractionFixture(t)
		trace := readJSONMapTest(t, fixture.tracePath)
		embedded := trace["plan"].(map[string]interface{})
		embedded["status"] = "MUTATED"
		fixture.opts.expectedTraceSHA = writeJSONTest(t, fixture.tracePath, trace)
		require.ErrorContains(t, run(fixture.opts), "differs outside top-level created_utc")
	})

	t.Run("executed archive work differs from plan", func(t *testing.T) {
		fixture := newExtractionFixture(t)
		trace := readJSONMapTest(t, fixture.tracePath)
		trace["archived_work"] = filepath.Join(fixture.root, "unexecuted-archive")
		fixture.opts.expectedTraceSHA = writeJSONTest(t, fixture.tracePath, trace)
		require.ErrorContains(t, run(fixture.opts), "archived work path")
	})

	t.Run("transition plan role assignment is duplicated", func(t *testing.T) {
		fixture := newExtractionFixture(t)
		plan := readJSONMapTest(t, fixture.planPath)
		nodes := plan["processes"].(map[string]interface{})["nodes"].([]interface{})
		argv := nodes[1].(map[string]interface{})["argv"].([]interface{})
		for index := range argv {
			if argv[index] == "-destination-shard-as-observer" {
				argv[index+1] = "0"
				break
			}
		}
		updateFixturePlanAndTrace(t, &fixture, plan)
		require.ErrorContains(t, run(fixture.opts), "duplicate observer role")
	})

	t.Run("binding main config mismatch", func(t *testing.T) {
		fixture := newExtractionFixture(t)
		binding := readJSONMapTest(t, fixture.bindingPath)
		binding["stable_hashes"].(map[string]interface{})["main_config"] = strings.Repeat("0", 64)
		fixture.opts.expectedBindingSHA = writeJSONTest(t, fixture.bindingPath, binding)
		require.ErrorContains(t, run(fixture.opts), "main-config hashes differ")
	})

	t.Run("requested chain differs from production config", func(t *testing.T) {
		fixture := newExtractionFixture(t)
		fixture.opts.chainID = "different-chain"
		require.ErrorContains(t, run(fixture.opts), "production-loaded chain ID differs")
	})

	t.Run("production config chain ID mutation is rejected", func(t *testing.T) {
		fixture := newExtractionFixture(t)
		updateFixtureConfigs(t, &fixture, func(value string) string {
			return strings.Replace(value, `ChainID = "local-testnet"`, `ChainID = "changed-chain"`, 1)
		})
		require.ErrorContains(t, run(fixture.opts), "production-loaded chain ID differs")
	})

	t.Run("production config genesis epoch mutation is rejected", func(t *testing.T) {
		fixture := newExtractionFixture(t)
		updateFixtureConfigs(t, &fixture, func(value string) string {
			return strings.Replace(value, "GenesisEpoch = 0", "GenesisEpoch = 1", 1)
		})
		require.ErrorContains(t, run(fixture.opts), "production-loaded canonical epoch differs")
	})

	t.Run("production config hardfork epoch selection is rejected", func(t *testing.T) {
		fixture := newExtractionFixture(t)
		updateFixtureConfigs(t, &fixture, func(value string) string {
			value = strings.Replace(value, "AfterHardFork = false", "AfterHardFork = true", 1)
			return strings.Replace(value, "StartEpoch = 100", "StartEpoch = 7", 1)
		})
		require.ErrorContains(t, run(fixture.opts), "production-loaded canonical epoch differs")
	})

	t.Run("wrong transition plan hash", func(t *testing.T) {
		fixture := newExtractionFixture(t)
		fixture.opts.expectedPlanSHA = strings.Repeat("0", 64)
		require.ErrorContains(t, run(fixture.opts), "transition plan")
		require.ErrorContains(t, run(fixture.opts), "does not match expected")
	})

	t.Run("missing LevelDB partition is rejected for every partition", func(t *testing.T) {
		for partition := 0; partition < 4; partition++ {
			partition := partition
			t.Run(strconv.Itoa(partition), func(t *testing.T) {
				fixture := newExtractionFixture(t)
				require.NoError(t, os.RemoveAll(filepath.Join(fixture.roots["0"], strconv.Itoa(partition))))
				require.ErrorContains(t, run(fixture.opts), "exact LevelDB partition set")
			})
		}
	})

	t.Run("extra numeric LevelDB partition is rejected", func(t *testing.T) {
		fixture := newExtractionFixture(t)
		putLevelDBValue(t, filepath.Join(fixture.roots["0"], "4"), []byte("extra"), []byte("value"))
		require.ErrorContains(t, run(fixture.opts), "unexpected numeric LevelDB partition")
	})
}

func TestRunExtractOutputLocusRejectsEveryMutationWithoutArchiveWrite(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *extractionFixture)
	}{
		{name: "header within archived node", mutate: func(_ *testing.T, fixture *extractionFixture) {
			fixture.opts.headerOutputPath = filepath.Join(fixture.archiveNode, "canonical-header.bin")
		}},
		{name: "header input alias", mutate: func(_ *testing.T, fixture *extractionFixture) {
			fixture.opts.headerOutputPath = fixture.opts.bindingPath
		}},
		{name: "header arbitrary outside artifacts", mutate: func(_ *testing.T, fixture *extractionFixture) {
			fixture.opts.headerOutputPath = filepath.Join(fixture.root, "canonical-header.bin")
		}},
		{name: "header wrong artifacts child", mutate: func(_ *testing.T, fixture *extractionFixture) {
			fixture.opts.headerOutputPath = filepath.Join(fixture.root, "artifacts", "wrong-header.bin")
		}},
		{name: "header symlink", mutate: func(t *testing.T, fixture *extractionFixture) {
			require.NoError(t, os.Symlink(filepath.Join(fixture.root, "binding.json"), fixture.opts.headerOutputPath))
		}},
		{name: "evidence within observer root", mutate: func(_ *testing.T, fixture *extractionFixture) {
			fixture.opts.evidencePath = filepath.Join(fixture.roots["0"], "extraction.json")
		}},
		{name: "evidence aliases header", mutate: func(_ *testing.T, fixture *extractionFixture) {
			fixture.opts.evidencePath = fixture.opts.headerOutputPath
		}},
		{name: "evidence arbitrary outside artifacts", mutate: func(_ *testing.T, fixture *extractionFixture) {
			fixture.opts.evidencePath = filepath.Join(fixture.root, "extraction.json")
		}},
		{name: "evidence wrong artifacts child", mutate: func(_ *testing.T, fixture *extractionFixture) {
			fixture.opts.evidencePath = filepath.Join(fixture.root, "artifacts", "wrong-extraction.json")
		}},
		{name: "evidence symlink", mutate: func(t *testing.T, fixture *extractionFixture) {
			require.NoError(t, os.Symlink(filepath.Join(fixture.root, "binding.json"), fixture.opts.evidencePath))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newExtractionFixture(t)
			before, err := scanCheckpointTree(filepath.Join(fixture.root, "node_working_dirs.archived-test"))
			require.NoError(t, err)
			test.mutate(t, &fixture)
			require.Error(t, run(fixture.opts))
			after, err := scanCheckpointTree(filepath.Join(fixture.root, "node_working_dirs.archived-test"))
			require.NoError(t, err)
			require.Equal(t, before.Entries, after.Entries)
		})
	}
}

func TestExtractionRootAndPrecursorHardening(t *testing.T) {
	t.Run("symlink root refused", func(t *testing.T) {
		realRoot := t.TempDir()
		alias := filepath.Join(t.TempDir(), "alias")
		require.NoError(t, os.Symlink(realRoot, alias))
		_, err := openDirectoryNoSymlink("0", alias)
		require.ErrorContains(t, err, "symlink or alias path refused")
	})

	t.Run("symlink output parent refused", func(t *testing.T) {
		realParent := t.TempDir()
		alias := filepath.Join(t.TempDir(), "alias")
		require.NoError(t, os.Symlink(realParent, alias))
		err := writeExclusiveDurable(filepath.Join(alias, "output.json"), []byte("{}\n"), 0o600)
		require.ErrorContains(t, err, "symlink or alias path refused")
		_, statErr := os.Stat(filepath.Join(realParent, "output.json"))
		require.ErrorIs(t, statErr, os.ErrNotExist)
	})

	t.Run("duplicate device inode refused", func(t *testing.T) {
		rootPath := t.TempDir()
		first, err := openDirectoryNoSymlink("0", rootPath)
		require.NoError(t, err)
		defer first.file.Close()
		second, err := openDirectoryNoSymlink("1", rootPath)
		require.NoError(t, err)
		defer second.file.Close()
		identities := make(map[string]string)
		require.NoError(t, rememberDistinctRootIdentity(identities, first))
		require.ErrorContains(t, rememberDistinctRootIdentity(identities, second), "duplicate device/inode")
	})

	t.Run("nonzero precursor validator root refused", func(t *testing.T) {
		final, _, _ := testIdentity(t, "local-testnet", 0)
		require.ErrorContains(t, verifyPrecursor("local-testnet", 0, final), "not exactly 32 zero bytes")
	})

	t.Run("noncanonical precursor refused", func(t *testing.T) {
		final, _, _ := testIdentity(t, "local-testnet", 0)
		precursor := mutateMetaHeader(t, final, func(meta *block.MetaBlock) {
			meta.ValidatorStatsRootHash = make([]byte, 32)
			meta.Nonce = 1
		})
		require.Equal(t, byte(0x08), precursor[0])
		reordered := append(append([]byte(nil), precursor[2:]...), precursor[:2]...)
		require.ErrorContains(t, verifyPrecursor("local-testnet", 0, reordered), "not canonical")
	})

	t.Run("empty final validator root refused", func(t *testing.T) {
		fixture := newExtractionFixture(t)
		emptyFinal := mutateMetaHeader(t, fixture.finalHeader, func(meta *block.MetaBlock) {
			meta.ValidatorStatsRootHash = nil
		})
		require.ErrorContains(t, verifyPrecursorFinalRelation(fixture.precursor, emptyFinal), "exactly 32 non-zero bytes")
	})

	t.Run("non UTC plan timestamp refused", func(t *testing.T) {
		standalone := []byte(`{"created_utc":"2026-08-25T01:00:00+01:00","status":"x"}`)
		embedded := []byte(`{"created_utc":"2026-08-25T00:00:00Z","status":"x"}`)
		require.ErrorContains(t, verifyEmbeddedPlan(standalone, embedded), "valid UTC")
	})
}

func TestDeriveObserverRootsTranslatesFullRelativePathNotBasename(t *testing.T) {
	activeRoot := filepath.Join(t.TempDir(), "active")
	archivedRoot := filepath.Join(t.TempDir(), "archived")
	plan := transitionPlanDocument{}
	for index := 0; index < 16; index++ {
		working := filepath.Join(activeRoot, fmt.Sprintf("node-%d", index))
		argv := []string{"node", "-working-directory", working}
		if index < 4 {
			role := []string{"0", "1", "2", "metachain"}[index]
			if index == 0 {
				working = filepath.Join(activeRoot, "region-a", "node-0")
				argv = []string{"node", "-working-directory", working}
			}
			argv = append(argv, "-destination-shard-as-observer", role, "-operation-mode", "db-lookup-extension")
		}
		plan.Processes.Nodes = append(plan.Processes.Nodes, struct {
			Argv []string `json:"argv"`
		}{Argv: argv})
	}
	roots, err := deriveObserverRoots(plan, archivedRoot, "local-testnet", 0)
	require.NoError(t, err)
	require.Equal(
		t,
		filepath.Join(archivedRoot, "region-a", "node-0", "db", "local-testnet", "Epoch_0", "Shard_0", "MetaBlock"),
		roots["0"],
	)
	require.NotEqual(t, filepath.Join(archivedRoot, "node-0", "db", "local-testnet", "Epoch_0", "Shard_0", "MetaBlock"), roots["0"])
}

func TestRunNodePlanMigrateReopenAndRefuseSecondMigration(t *testing.T) {
	root := t.TempDir()
	headerBytes, canonicalHash, domain := testIdentity(t, "local-testnet", 0)
	opts := baseTestOptions(t, root, headerBytes, canonicalHash, domain)
	opts.mode = "plan"
	require.NoError(t, run(opts))

	planBytes, err := os.ReadFile(opts.evidencePath)
	require.NoError(t, err)
	var plan migrationEvidence
	require.NoError(t, json.Unmarshal(planBytes, &plan))
	require.Equal(t, "DRY_VALIDATED_16_NODE_PLAN_BOUND_ABSENT_TARGET_NO_NODE_MUTATION", plan.Status)
	require.Equal(t, "PLANNED_EMERGENCY_MIGRATION_NOT_APPLIED", plan.Provenance)
	require.NotNil(t, plan.TargetAbsentBefore)
	require.True(t, *plan.TargetAbsentBefore)

	opts.mode = "migrate"
	opts.evidencePath = filepath.Join(opts.rehearsalRoot, "migrate-disabled.json")
	require.ErrorContains(t, run(opts), "mechanically disabled")
	_, err = os.Stat(opts.targetDBPath)
	require.ErrorIs(t, err, os.ErrNotExist)

	opts.mode = "rehearse"
	require.ErrorContains(t, run(opts), "mechanically disabled")
}

func TestRunNodePlanEvidenceLocusRejectsEveryMutationWithoutTargetWrite(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *options)
	}{
		{name: "target path", mutate: func(_ *testing.T, opts *options) { opts.evidencePath = opts.targetDBPath }},
		{name: "within destination node", mutate: func(_ *testing.T, opts *options) {
			opts.evidencePath = filepath.Join(opts.nodeRoot, "evidence.json")
		}},
		{name: "input alias", mutate: func(_ *testing.T, opts *options) { opts.evidencePath = opts.headerPath }},
		{name: "arbitrary outside artifacts", mutate: func(_ *testing.T, opts *options) {
			opts.evidencePath = filepath.Join(filepath.Dir(opts.rehearsalRoot), "outside.json")
		}},
		{name: "wrong artifacts child", mutate: func(_ *testing.T, opts *options) {
			opts.evidencePath = filepath.Join(opts.rehearsalRoot, "artifacts", "wrong-name.json")
		}},
		{name: "symlink", mutate: func(t *testing.T, opts *options) {
			require.NoError(t, os.Symlink(t.TempDir(), opts.evidencePath))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			headerBytes, canonicalHash, domain := testIdentity(t, "local-testnet", 0)
			opts := baseTestOptions(t, root, headerBytes, canonicalHash, domain)
			opts.mode = "plan"
			test.mutate(t, &opts)
			err := run(opts)
			require.Error(t, err)
			require.NoFileExists(t, opts.targetDBPath)
		})
	}
}

func TestRunNodePlanRejectsTraversalNodeIDWithoutWrite(t *testing.T) {
	root := t.TempDir()
	headerBytes, canonicalHash, domain := testIdentity(t, "local-testnet", 0)
	opts := baseTestOptions(t, root, headerBytes, canonicalHash, domain)
	opts.mode = "plan"

	var plan migrationPlanDocument
	readJSONTest(t, opts.migrationPlanPath, &plan)
	plan.Nodes[0].ID = "../escape"
	opts.expectedMigrationPlanSHA = writeJSONTest(t, opts.migrationPlanPath, plan)

	require.ErrorContains(t, run(opts), "invalid migration node identity")
	require.NoFileExists(t, filepath.Join(opts.rehearsalRoot, "escape.json"))
	require.NoFileExists(t, opts.targetDBPath)
}

func TestRunCheckpointWritesOnlyVerifiedClosedCopyManifest(t *testing.T) {
	root := t.TempDir()
	headerBytes, canonicalHash, domain := testIdentity(t, "local-testnet", 0)
	opts := baseTestOptions(t, root, headerBytes, canonicalHash, domain)

	var plan migrationPlanDocument
	readJSONTest(t, opts.migrationPlanPath, &plan)
	require.NoError(t, os.Remove(plan.CheckpointManifestPath))
	plan.CheckpointManifestSHA256 = ""
	opts.expectedMigrationPlanSHA = writeJSONTest(t, opts.migrationPlanPath, plan)
	opts.mode = "checkpoint"
	opts.checkpointOutputPath = plan.CheckpointManifestPath

	require.NoError(t, run(opts))
	var manifest checkpointCopyManifest
	readJSONTest(t, opts.checkpointOutputPath, &manifest)
	require.Equal(t, "CLOSED_SOURCE_TO_ISOLATED_DESTINATION_BYTE_IDENTICAL", manifest.Status)
	require.Len(t, manifest.Nodes, 16)
	_, err := os.Stat(opts.targetDBPath)
	require.ErrorIs(t, err, os.ErrNotExist)

	require.ErrorContains(t, run(opts), "already exists")
}

func TestRunCheckpointOutputLocusRejectsEveryMutationWithoutNodeWrite(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *options, migrationPlanDocument)
	}{
		{name: "target path", mutate: func(_ *testing.T, opts *options, _ migrationPlanDocument) {
			opts.checkpointOutputPath = opts.targetDBPath
		}},
		{name: "within destination node", mutate: func(_ *testing.T, opts *options, _ migrationPlanDocument) {
			opts.checkpointOutputPath = filepath.Join(opts.nodeRoot, "checkpoint-copy-manifest.json")
		}},
		{name: "within source node", mutate: func(_ *testing.T, opts *options, plan migrationPlanDocument) {
			opts.checkpointOutputPath = filepath.Join(plan.Nodes[0].SourceNodeRoot, "checkpoint-copy-manifest.json")
		}},
		{name: "input alias", mutate: func(_ *testing.T, opts *options, _ migrationPlanDocument) {
			opts.checkpointOutputPath = opts.headerPath
		}},
		{name: "arbitrary outside artifacts", mutate: func(_ *testing.T, opts *options, _ migrationPlanDocument) {
			opts.checkpointOutputPath = filepath.Join(opts.rehearsalRoot, "checkpoint-copy-manifest.json")
		}},
		{name: "wrong artifacts child", mutate: func(_ *testing.T, opts *options, _ migrationPlanDocument) {
			opts.checkpointOutputPath = filepath.Join(opts.rehearsalRoot, "artifacts", "wrong-checkpoint.json")
		}},
		{name: "symlink", mutate: func(t *testing.T, opts *options, _ migrationPlanDocument) {
			require.NoError(t, os.Symlink(t.TempDir(), opts.checkpointOutputPath))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			headerBytes, canonicalHash, domain := testIdentity(t, "local-testnet", 0)
			opts := baseTestOptions(t, root, headerBytes, canonicalHash, domain)
			var plan migrationPlanDocument
			readJSONTest(t, opts.migrationPlanPath, &plan)
			require.NoError(t, os.Remove(plan.CheckpointManifestPath))
			plan.CheckpointManifestSHA256 = ""
			opts.expectedMigrationPlanSHA = writeJSONTest(t, opts.migrationPlanPath, plan)
			opts.mode = "checkpoint"
			opts.checkpointOutputPath = plan.CheckpointManifestPath
			before := make(map[string][]checkpointTreeEntry, len(plan.Nodes)*2)
			for _, node := range plan.Nodes {
				for _, path := range []string{node.SourceNodeRoot, node.NodeRoot} {
					scan, err := scanCheckpointTree(path)
					require.NoError(t, err)
					before[path] = scan.Entries
				}
			}
			test.mutate(t, &opts, plan)
			require.Error(t, run(opts))
			require.NoFileExists(t, opts.targetDBPath)
			for path, entries := range before {
				scan, err := scanCheckpointTree(path)
				require.NoError(t, err)
				require.Equal(t, entries, scan.Entries)
			}
		})
	}
}

func TestRunNodeRejectsIdentityBindingAndLockFailures(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	headerBytes, canonicalHash, domain := testIdentity(t, "local-testnet", 0)
	opts := baseTestOptions(t, root, headerBytes, canonicalHash, domain)
	opts.mode = "plan"

	opts.expectedBindingSHA = hex.EncodeToString(make([]byte, 32))
	require.ErrorContains(t, run(opts), "binding")

	opts = baseTestOptions(t, root, headerBytes, canonicalHash, domain)
	opts.mode = "plan"
	opts.targetDBPath = filepath.Join(root, "wrong-shard", "PrototypeNetworkIdentityStorageDB")
	require.ErrorContains(t, run(opts), "differs from exact 16-node migration-plan entry")

	opts = baseTestOptions(t, root, headerBytes, canonicalHash, domain)
	opts.mode = "plan"
	require.NoError(t, os.MkdirAll(opts.targetDBPath, 0o700))
	locked, err := leveldb.OpenFile(opts.targetDBPath, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, locked.Close()) })
	require.ErrorContains(t, run(opts), "checkpoint-copy node")
}

func TestRunNodePlanPermitsRunningNodeWithoutOpeningTargetDB(t *testing.T) {
	root := t.TempDir()
	headerBytes, canonicalHash, domain := testIdentity(t, "local-testnet", 0)
	opts := baseTestOptions(t, root, headerBytes, canonicalHash, domain)
	opts.mode = "plan"

	cmd := exec.Command(os.Args[0], "-test.run=^TestMigrationHelperProcess$")
	cmd.Dir = opts.nodeRoot
	cmd.Env = append(os.Environ(), "DRWA_MIGRATION_HELPER_PROCESS=1")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	require.Eventually(t, func() bool { return requireNodeStopped(opts.nodeRoot) != nil }, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, run(opts))
}

func TestRunNodeRejectsReboundExtractionAndLineageEvidence(t *testing.T) {
	t.Run("cross-role extraction partition alias", func(t *testing.T) {
		root := t.TempDir()
		headerBytes, canonicalHash, domain := testIdentity(t, "local-testnet", 0)
		opts := baseTestOptions(t, root, headerBytes, canonicalHash, domain)
		opts.mode = "plan"

		var evidence migrationEvidence
		readJSONTest(t, opts.extractionEvidencePath, &evidence)
		evidence.ObserverObservations[1].PartitionIdentities[0] = evidence.ObserverObservations[0].PartitionIdentities[0]
		opts.expectedExtractionEvidenceSHA = writeJSONTest(t, opts.extractionEvidencePath, evidence)
		var plan migrationPlanDocument
		readJSONTest(t, opts.migrationPlanPath, &plan)
		plan.ExtractionEvidenceSHA256 = opts.expectedExtractionEvidenceSHA
		opts.expectedMigrationPlanSHA = writeJSONTest(t, opts.migrationPlanPath, plan)
		require.ErrorContains(t, run(opts), "alias filesystem identity")
	})

	t.Run("contradictory top-level extraction digest", func(t *testing.T) {
		root := t.TempDir()
		headerBytes, canonicalHash, domain := testIdentity(t, "local-testnet", 0)
		opts := baseTestOptions(t, root, headerBytes, canonicalHash, domain)
		opts.mode = "plan"

		var evidence migrationEvidence
		readJSONTest(t, opts.extractionEvidencePath, &evidence)
		evidence.PrecursorSHA256 = strings.Repeat("a", 64)
		opts.expectedExtractionEvidenceSHA = writeJSONTest(t, opts.extractionEvidencePath, evidence)
		var plan migrationPlanDocument
		readJSONTest(t, opts.migrationPlanPath, &plan)
		plan.ExtractionEvidenceSHA256 = opts.expectedExtractionEvidenceSHA
		opts.expectedMigrationPlanSHA = writeJSONTest(t, opts.migrationPlanPath, plan)
		require.ErrorContains(t, run(opts), "top-level precursor digests differ")
	})

	t.Run("unequal precursor digest rebound", func(t *testing.T) {
		root := t.TempDir()
		headerBytes, canonicalHash, domain := testIdentity(t, "local-testnet", 0)
		opts := baseTestOptions(t, root, headerBytes, canonicalHash, domain)
		opts.mode = "plan"

		var evidence migrationEvidence
		readJSONTest(t, opts.extractionEvidencePath, &evidence)
		evidence.ObserverObservations[1].PrecursorSHA256 = strings.Repeat("a", 64)
		opts.expectedExtractionEvidenceSHA = writeJSONTest(t, opts.extractionEvidencePath, evidence)
		var plan migrationPlanDocument
		readJSONTest(t, opts.migrationPlanPath, &plan)
		plan.ExtractionEvidenceSHA256 = opts.expectedExtractionEvidenceSHA
		opts.expectedMigrationPlanSHA = writeJSONTest(t, opts.migrationPlanPath, plan)
		require.ErrorContains(t, run(opts), "precursor digests differ")
	})

	t.Run("role relabel preserving counts", func(t *testing.T) {
		root := t.TempDir()
		headerBytes, canonicalHash, domain := testIdentity(t, "local-testnet", 0)
		opts := baseTestOptions(t, root, headerBytes, canonicalHash, domain)
		opts.mode = "plan"
		var plan migrationPlanDocument
		readJSONTest(t, opts.migrationPlanPath, &plan)
		plan.Nodes[0].Role, plan.Nodes[1].Role = plan.Nodes[1].Role, plan.Nodes[0].Role
		opts.expectedMigrationPlanSHA = writeJSONTest(t, opts.migrationPlanPath, plan)
		require.ErrorContains(t, run(opts), "differs from executed transition lineage")
	})

	t.Run("destination inode rebound", func(t *testing.T) {
		root := t.TempDir()
		headerBytes, canonicalHash, domain := testIdentity(t, "local-testnet", 0)
		opts := baseTestOptions(t, root, headerBytes, canonicalHash, domain)
		opts.mode = "plan"
		var plan migrationPlanDocument
		readJSONTest(t, opts.migrationPlanPath, &plan)
		plan.Nodes[0].NodeRootInode++
		opts.expectedMigrationPlanSHA = writeJSONTest(t, opts.migrationPlanPath, plan)
		require.ErrorContains(t, run(opts), "destination filesystem identity mismatch")
	})

	t.Run("target symlink refused", func(t *testing.T) {
		root := t.TempDir()
		headerBytes, canonicalHash, domain := testIdentity(t, "local-testnet", 0)
		opts := baseTestOptions(t, root, headerBytes, canonicalHash, domain)
		opts.mode = "plan"
		require.NoError(t, os.Symlink(t.TempDir(), opts.targetDBPath))
		require.Error(t, run(opts))
	})

	t.Run("destination tree extra file rejected", func(t *testing.T) {
		root := t.TempDir()
		headerBytes, canonicalHash, domain := testIdentity(t, "local-testnet", 0)
		opts := baseTestOptions(t, root, headerBytes, canonicalHash, domain)
		opts.mode = "plan"
		require.NoError(t, os.WriteFile(filepath.Join(opts.nodeRoot, "unexpected"), []byte("x"), 0o600))
		require.ErrorContains(t, run(opts), "destination tree differs")
	})

	t.Run("destination special mode drift rejected by verifier", func(t *testing.T) {
		root := t.TempDir()
		headerBytes, canonicalHash, domain := testIdentity(t, "local-testnet", 0)
		opts := baseTestOptions(t, root, headerBytes, canonicalHash, domain)
		opts.mode = "plan"
		require.NoError(t, os.Chmod(opts.nodeRoot, os.ModeSticky|0o700))
		require.ErrorContains(t, run(opts), "destination tree differs")
	})

	t.Run("candidate binary drift rejected", func(t *testing.T) {
		root := t.TempDir()
		headerBytes, canonicalHash, domain := testIdentity(t, "local-testnet", 0)
		opts := baseTestOptions(t, root, headerBytes, canonicalHash, domain)
		opts.mode = "plan"
		var plan migrationPlanDocument
		readJSONTest(t, opts.migrationPlanPath, &plan)
		require.NoError(t, os.WriteFile(plan.CandidateBinaryPath, []byte("drift\n"), 0o700))
		require.ErrorContains(t, run(opts), "candidate binary")
	})
}

func TestScanCheckpointTreeRejectsSymlinksAndHardlinks(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.Symlink(t.TempDir(), filepath.Join(root, "alias")))
		_, err := scanCheckpointTree(root)
		require.ErrorContains(t, err, "symlink refused")
	})
	t.Run("hardlink", func(t *testing.T) {
		root := t.TempDir()
		first := filepath.Join(root, "first")
		require.NoError(t, os.WriteFile(first, []byte("same"), 0o600))
		require.NoError(t, os.Link(first, filepath.Join(root, "second")))
		_, err := scanCheckpointTree(root)
		require.ErrorContains(t, err, "hard-linked regular file refused")
	})
}

func TestCheckpointTreeRecordsSpecialModeBitsAndRejectsCrossTreeAlias(t *testing.T) {
	t.Run("special mode bits are part of the copy contract", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, "sticky")
		require.NoError(t, os.Mkdir(path, 0o700))
		require.NoError(t, os.Chmod(path, os.ModeSticky|0o700))

		scan, err := scanCheckpointTree(root)
		require.NoError(t, err)
		var found checkpointTreeEntry
		for _, entry := range scan.Entries {
			if entry.RelativePath == "sticky" {
				found = entry
			}
		}
		require.NotZero(t, found.Mode&uint32(os.ModeSticky))

		drifted := append([]checkpointTreeEntry(nil), scan.Entries...)
		for index := range drifted {
			if drifted[index].RelativePath == "sticky" {
				drifted[index].Mode &^= uint32(os.ModeSticky)
			}
		}
		require.False(t, equalCheckpointEntries(scan.Entries, drifted))
	})

	t.Run("source and destination inode sets must be disjoint", func(t *testing.T) {
		source := map[string]string{"1:10": "source-a:file"}
		destination := map[string]string{"1:10": "destination-a:file"}
		require.ErrorContains(t, requireDisjointCheckpointIdentities(source, destination), "aliases source")
	})

	t.Run("manifest verifier wires cross-tree disjointness", func(t *testing.T) {
		root := t.TempDir()
		headerBytes, canonicalHash, domain := testIdentity(t, "local-testnet", 0)
		opts := baseTestOptions(t, root, headerBytes, canonicalHash, domain)
		var plan migrationPlanDocument
		readJSONTest(t, opts.migrationPlanPath, &plan)

		sourceScan, err := scanCheckpointTree(plan.Nodes[0].SourceNodeRoot)
		require.NoError(t, err)
		var aliasedIdentity string
		for identity := range sourceScan.Identities {
			aliasedIdentity = identity
			break
		}
		require.NotEmpty(t, aliasedIdentity)
		scanner := func(path string) (checkpointTreeScan, error) {
			scan, scanErr := scanCheckpointTree(path)
			if scanErr == nil && path == plan.Nodes[0].NodeRoot {
				scan.Identities[aliasedIdentity] = "injected-bind-alias"
			}
			return scan, scanErr
		}
		require.ErrorContains(t, verifyCheckpointCopyManifestWithScanner(plan, scanner), "aliases source")
		_, err = buildCheckpointManifest(plan, opts, scanner)
		require.ErrorContains(t, err, "aliases source")
	})
}

func TestRequireNodeStoppedDetectsProcessWorkingDirectory(t *testing.T) {
	nodeRoot := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestMigrationHelperProcess$")
	cmd.Dir = nodeRoot
	cmd.Env = append(os.Environ(), "DRWA_MIGRATION_HELPER_PROCESS=1")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	require.Eventually(t, func() bool {
		return requireNodeStopped(nodeRoot) != nil
	}, 2*time.Second, 10*time.Millisecond)
	require.ErrorContains(t, requireNodeStopped(nodeRoot), "still uses target root")
}

func TestMigrationHelperProcess(t *testing.T) {
	if os.Getenv("DRWA_MIGRATION_HELPER_PROCESS") != "1" {
		return
	}
	time.Sleep(30 * time.Second)
}

func TestVerifyHeaderRejectsNonCanonicalAndSemanticMismatches(t *testing.T) {
	t.Parallel()

	headerBytes, canonicalHash, domain := testIdentity(t, "local-testnet", 7)
	_, err := verifyHeader("wrong", 7, headerBytes, canonicalHash, domain)
	require.ErrorContains(t, err, "chain ID")
	_, err = verifyHeader("local-testnet", 8, headerBytes, canonicalHash, domain)
	require.ErrorContains(t, err, "header epoch")

	badDomain := domain
	badDomain[0] ^= 0xff
	_, err = verifyHeader("local-testnet", 7, headerBytes, canonicalHash, badDomain)
	require.ErrorContains(t, err, "network domain")

	meta := &block.MetaBlock{}
	marshalizer := &marshal.GogoProtoMarshalizer{}
	require.NoError(t, marshalizer.Unmarshal(meta, headerBytes))
	meta.Nonce = 1
	canonicalWithNonce, err := marshalizer.Marshal(meta)
	require.NoError(t, err)
	require.Equal(t, byte(0x08), canonicalWithNonce[0])
	reordered := append(append([]byte(nil), canonicalWithNonce[2:]...), canonicalWithNonce[:2]...)
	reorderedHashBytes := coreBlake2b.NewBlake2b().Compute(string(reordered))
	reorderedHash := [32]byte{}
	copy(reorderedHash[:], reorderedHashBytes)
	reorderedDomain, err := drwaprototype.DeriveNetworkDomain([]byte("local-testnet"), reorderedHash)
	require.NoError(t, err)
	_, err = verifyHeader("local-testnet", 7, reordered, reorderedHash, reorderedDomain)
	require.ErrorContains(t, err, "not canonical")
}

func TestStrictEvidenceJSONRejectsUnknownDuplicateAndTrailingValues(t *testing.T) {
	var plan migrationPlanDocument
	require.ErrorContains(t, strictDecodeJSON([]byte(`{"unknown":true}`), &plan), "unknown field")
	require.ErrorContains(t, strictDecodeJSON([]byte(`{"schema":"one","schema":"two"}`), &plan), "duplicate JSON object key")
	require.ErrorContains(t, strictDecodeJSON([]byte(`{} {}`), &plan), "multiple JSON values")

	var generic map[string]interface{}
	require.ErrorContains(t, decodeJSONNoDuplicates([]byte(`{"status":"one","status":"two"}`), &generic), "duplicate JSON object key")
}

func baseTestOptions(t *testing.T, root string, headerBytes []byte, canonicalHash, domain [32]byte) options {
	t.Helper()
	rehearsalRoot := filepath.Join(root, "isolated-rehearsal")
	if err := os.MkdirAll(rehearsalRoot, 0o700); err != nil {
		panic(err)
	}
	if err := os.MkdirAll(filepath.Join(rehearsalRoot, "artifacts"), 0o700); err != nil {
		panic(err)
	}
	headerPath := filepath.Join(rehearsalRoot, "artifacts", "canonical-header.bin")
	if err := os.WriteFile(headerPath, headerBytes, 0o600); err != nil {
		panic(err)
	}
	binding := map[string]interface{}{
		"canonical_metachain_genesis_hash": hex.EncodeToString(canonicalHash[:]),
		"network_domain":                   hex.EncodeToString(domain[:]),
	}
	bindingBytes, err := json.Marshal(binding)
	if err != nil {
		panic(err)
	}
	bindingPath := filepath.Join(rehearsalRoot, "binding.json")
	if err = os.WriteFile(bindingPath, bindingBytes, 0o600); err != nil {
		panic(err)
	}
	bindingSHA := sha256.Sum256(bindingBytes)
	headerSHA := sha256.Sum256(headerBytes)
	archiveNode := filepath.Join(root, "node.archived")
	archiveWork := filepath.Join(root, "node_working_dirs.archived")
	require.NoError(t, os.MkdirAll(archiveNode, 0o700))
	require.NoError(t, os.MkdirAll(archiveWork, 0o700))
	var transitionNodes []interface{}
	type sourceFixture struct {
		id, role, shard, root string
		dev, ino              uint64
	}
	var sources []sourceFixture
	for _, shard := range []string{"0", "1", "2", "metachain"} {
		for index := 0; index < 4; index++ {
			role := "validator"
			if index == 0 {
				role = "observer"
			}
			id := fmt.Sprintf("%s-%s-%d", role, shard, index)
			activeRoot := filepath.Join(root, "active", id)
			sourceRoot := filepath.Join(archiveWork, id)
			require.NoError(t, os.MkdirAll(filepath.Join(sourceRoot, "db", "local-testnet", "Static", "Shard_"+shard), 0o700))
			argv := []string{"node", "-working-directory", activeRoot, "-config", "./config/config_validator.toml"}
			if role == "observer" {
				argv = append(argv, "-destination-shard-as-observer", shard, "-operation-mode", "db-lookup-extension")
			}
			transitionNodes = append(transitionNodes, map[string]interface{}{"argv": argv})
			info, statErr := os.Stat(sourceRoot)
			require.NoError(t, statErr)
			stat := info.Sys().(*syscall.Stat_t)
			sources = append(sources, sourceFixture{id: id, role: role, shard: shard, root: sourceRoot, dev: uint64(stat.Dev), ino: stat.Ino})
		}
	}
	lineagePlan := map[string]interface{}{
		"created_utc": "2026-08-25T00:00:00Z", "status": readyTransitionPlan,
		"live_generation_hashes": map[string]interface{}{"nodes_setup": strings.Repeat("3", 64)},
		"live_hashes":            map[string]interface{}{"old_observer": strings.Repeat("4", 64), "old_validator": strings.Repeat("4", 64)},
		"processes":              map[string]interface{}{"nodes": transitionNodes},
		"targets":                map[string]interface{}{"archived_node": archiveNode, "archived_work": archiveWork},
	}
	transitionPlanPath := filepath.Join(rehearsalRoot, "transition-plan.json")
	transitionPlanSHA := writeJSONTest(t, transitionPlanPath, lineagePlan)
	embeddedLineagePlan := cloneJSONMap(t, lineagePlan)
	embeddedLineagePlan["created_utc"] = "2026-08-25T00:00:01Z"
	lineageTrace := map[string]interface{}{
		"archived_node": archiveNode, "archived_work": archiveWork,
		"status": verifiedTransitionStatus, "plan": embeddedLineagePlan,
	}
	transitionTracePath := filepath.Join(rehearsalRoot, "transition-trace.json")
	transitionTraceSHA := writeJSONTest(t, transitionTracePath, lineageTrace)
	expectedEnvelope, err := networkidentity.Encode(networkidentity.Record{
		SchemaVersion: networkidentity.Version,
		Epoch:         0,
		Provenance:    networkidentity.EmergencyMigration,
		ChainID:       []byte("local-testnet"),
		CanonicalHash: canonicalHash,
		NetworkDomain: domain,
		HeaderBytes:   headerBytes,
	})
	require.NoError(t, err)
	expectedEnvelopeSHA := sha256.Sum256(expectedEnvelope)
	extractionEvidence := migrationEvidence{
		Schema:                     "drwa.s1.prototype-network-identity-migration.v2",
		Status:                     extractionCompleteStatus,
		Mode:                       "extract",
		TimestampUTC:               "2026-08-25T00:00:00Z",
		ChainID:                    "local-testnet",
		CanonicalEpoch:             0,
		Provenance:                 "NOT_APPLIED_EXTRACTION_ONLY",
		CanonicalHash:              hex.EncodeToString(canonicalHash[:]),
		NetworkDomain:              hex.EncodeToString(domain[:]),
		HeaderSHA256:               hex.EncodeToString(headerSHA[:]),
		HeaderLength:               len(headerBytes),
		IdentitySchemaVersion:      networkidentity.Version,
		StorageKeyHex:              hex.EncodeToString(networkidentity.Key(0)),
		EnvelopeSHA256:             hex.EncodeToString(expectedEnvelopeSHA[:]),
		EnvelopeLength:             len(expectedEnvelope),
		HeaderOutputPath:           headerPath,
		BindingPath:                bindingPath,
		BindingSHA256:              hex.EncodeToString(bindingSHA[:]),
		TransitionPlanPath:         transitionPlanPath,
		TransitionPlanSHA256:       transitionPlanSHA,
		TransitionTracePath:        transitionTracePath,
		TransitionTraceSHA256:      transitionTraceSHA,
		MainConfigSHA256:           strings.Repeat("4", 64),
		NodesSetupSHA256:           strings.Repeat("3", 64),
		PrecursorSHA256:            strings.Repeat("1", 64),
		PrecursorBlake2b:           strings.Repeat("2", 64),
		AuthoritativeRuntimeCredit: 0,
	}
	for roleIndex, role := range []string{"0", "1", "2", "metachain"} {
		observationRoot := filepath.Join(rehearsalRoot, "extraction", role)
		require.NoError(t, os.MkdirAll(observationRoot, 0o700))
		info, statErr := os.Stat(observationRoot)
		require.NoError(t, statErr)
		stat := info.Sys().(*syscall.Stat_t)
		observation := observerObservationEvidence{
			Role: role, CanonicalRoot: observationRoot,
			RootDevice: uint64(stat.Dev), RootInode: stat.Ino,
			NumericPartitions: []int{0, 1, 2, 3},
			PartitionIdentities: []string{
				fmt.Sprintf("0:1:%d", roleIndex*10+1),
				fmt.Sprintf("1:1:%d", roleIndex*10+2),
				fmt.Sprintf("2:1:%d", roleIndex*10+3),
				fmt.Sprintf("3:1:%d", roleIndex*10+4),
			},
			PrecursorMatchCount: 1, PrecursorSHA256: strings.Repeat("1", 64), PrecursorBlake2b: strings.Repeat("2", 64),
		}
		if role == "metachain" {
			observation.FinalMatchCount = 1
			observation.FinalSHA256 = hex.EncodeToString(headerSHA[:])
			observation.FinalBlake2b = hex.EncodeToString(canonicalHash[:])
		}
		extractionEvidence.ObserverObservations = append(extractionEvidence.ObserverObservations, observation)
		extractionEvidence.ObserverMetaDBs = append(extractionEvidence.ObserverMetaDBs, observationRoot)
		extractionEvidence.ObserverRootIdentities = append(
			extractionEvidence.ObserverRootIdentities,
			fmt.Sprintf("%s:%d:%d:%s", role, stat.Dev, stat.Ino, observationRoot),
		)
	}
	extractionEvidencePath := filepath.Join(rehearsalRoot, "artifacts", "extraction.json")
	extractionEvidenceSHA := writeJSONTest(t, extractionEvidencePath, extractionEvidence)

	var nodes []migrationPlanNode
	var selected migrationPlanNode
	for _, source := range sources {
		id := source.id
		nodeRoot := filepath.Join(rehearsalRoot, id)
		if err = os.MkdirAll(filepath.Join(nodeRoot, "db", "local-testnet", "Static", "Shard_"+source.shard), 0o700); err != nil {
			panic(err)
		}
		nodeInfo, statErr := os.Stat(nodeRoot)
		require.NoError(t, statErr)
		nodeStat := nodeInfo.Sys().(*syscall.Stat_t)
		node := migrationPlanNode{
			ID: id, Role: source.role, ShardID: source.shard,
			SourceNodeRoot: source.root, SourceRootDevice: source.dev, SourceRootInode: source.ino,
			NodeRoot: nodeRoot, NodeRootDevice: uint64(nodeStat.Dev), NodeRootInode: nodeStat.Ino,
			TargetDBPath: filepath.Join(nodeRoot, "db", "local-testnet", "Static", "Shard_"+source.shard, "PrototypeNetworkIdentityStorageDB"),
		}
		if source.shard == "0" && source.role == "observer" {
			selected = node
		}
		nodes = append(nodes, node)
	}
	checkpointManifest := checkpointCopyManifest{
		Schema:     "drwa.s1.prototype-network-identity-checkpoint-copy.v1",
		Status:     "CLOSED_SOURCE_TO_ISOLATED_DESTINATION_BYTE_IDENTICAL",
		CreatedUTC: "2026-08-25T00:00:00Z",
	}
	for _, node := range nodes {
		sourceScan, scanErr := scanCheckpointTree(node.SourceNodeRoot)
		require.NoError(t, scanErr)
		destinationScan, scanErr := scanCheckpointTree(node.NodeRoot)
		require.NoError(t, scanErr)
		require.Equal(t, sourceScan.Entries, destinationScan.Entries)
		checkpointManifest.Nodes = append(checkpointManifest.Nodes, checkpointNodeManifest{
			ID: node.ID, SourceRoot: node.SourceNodeRoot, DestinationRoot: node.NodeRoot, Entries: sourceScan.Entries,
		})
	}
	checkpointManifestPath := filepath.Join(rehearsalRoot, "artifacts", "checkpoint-copy-manifest.json")
	checkpointManifestSHA := writeJSONTest(t, checkpointManifestPath, checkpointManifest)
	candidateBinaryPath := filepath.Join(rehearsalRoot, "node-candidate")
	require.NoError(t, os.WriteFile(candidateBinaryPath, []byte("test candidate\n"), 0o700))
	candidateBinaryBytes, err := os.ReadFile(candidateBinaryPath)
	require.NoError(t, err)
	candidateBinarySHA := sha256.Sum256(candidateBinaryBytes)
	candidateConfigBytes, err := os.ReadFile("../../cmd/node/config/config.toml")
	require.NoError(t, err)
	candidateConfigBytes = []byte(strings.Replace(string(candidateConfigBytes), `ChainID = "undefined"`, `ChainID = "local-testnet"`, 1))
	validatorConfigPath := filepath.Join(rehearsalRoot, "config_validator.toml")
	observerConfigPath := filepath.Join(rehearsalRoot, "config_observer.toml")
	require.NoError(t, os.WriteFile(validatorConfigPath, candidateConfigBytes, 0o600))
	require.NoError(t, os.WriteFile(observerConfigPath, candidateConfigBytes, 0o600))
	candidateConfigSHA := sha256.Sum256(candidateConfigBytes)
	migrationPlan := migrationPlanDocument{
		Schema: migrationPlanSchema, Status: migrationPlanReadyRehearsal,
		CreatedUTC: "2026-08-25T00:00:00Z", ChainID: "local-testnet", CanonicalEpoch: 0,
		CanonicalHash: hex.EncodeToString(canonicalHash[:]), NetworkDomain: hex.EncodeToString(domain[:]),
		BindingPath: bindingPath, BindingSHA256: hex.EncodeToString(bindingSHA[:]),
		ExtractionEvidencePath: extractionEvidencePath, ExtractionEvidenceSHA256: extractionEvidenceSHA,
		TransitionPlanPath: transitionPlanPath, TransitionPlanSHA256: transitionPlanSHA,
		TransitionTracePath: transitionTracePath, TransitionTraceSHA256: transitionTraceSHA,
		MainConfigSHA256: strings.Repeat("4", 64), NodesSetupSHA256: strings.Repeat("3", 64),
		CheckpointManifestPath: checkpointManifestPath, CheckpointManifestSHA256: checkpointManifestSHA,
		CandidateBinaryPath: candidateBinaryPath, CandidateBinarySHA256: hex.EncodeToString(candidateBinarySHA[:]),
		ValidatorConfigPath: validatorConfigPath, ValidatorConfigSHA256: hex.EncodeToString(candidateConfigSHA[:]),
		ObserverConfigPath: observerConfigPath, ObserverConfigSHA256: hex.EncodeToString(candidateConfigSHA[:]),
		HeaderPath: headerPath, HeaderSHA256: hex.EncodeToString(headerSHA[:]),
		RehearsalRoot: rehearsalRoot, Nodes: nodes,
	}
	migrationPlanPath := filepath.Join(rehearsalRoot, "migration-plan.json")
	migrationPlanSHA := writeJSONTest(t, migrationPlanPath, migrationPlan)
	return options{
		chainID:                       "local-testnet",
		epoch:                         0,
		expectedCanonicalHash:         hex.EncodeToString(canonicalHash[:]),
		expectedDomain:                hex.EncodeToString(domain[:]),
		bindingPath:                   bindingPath,
		expectedBindingSHA:            hex.EncodeToString(bindingSHA[:]),
		migrationPlanPath:             migrationPlanPath,
		expectedMigrationPlanSHA:      migrationPlanSHA,
		extractionEvidencePath:        extractionEvidencePath,
		expectedExtractionEvidenceSHA: extractionEvidenceSHA,
		headerPath:                    headerPath,
		targetDBPath:                  selected.TargetDBPath,
		nodeRoot:                      selected.NodeRoot,
		shardID:                       selected.ShardID,
		rehearsalRoot:                 rehearsalRoot,
		evidencePath:                  filepath.Join(rehearsalRoot, "artifacts", "plan-"+selected.ID+".json"),
	}
}

func testIdentity(t *testing.T, chainID string, epoch uint32) ([]byte, [32]byte, [32]byte) {
	t.Helper()
	meta := &block.MetaBlock{
		Epoch:                  epoch,
		ChainID:                []byte(chainID),
		RootHash:               bytes32(1),
		ValidatorStatsRootHash: bytes32(33),
	}
	headerBytes, err := (&marshal.GogoProtoMarshalizer{}).Marshal(meta)
	require.NoError(t, err)
	canonicalHashBytes := coreBlake2b.NewBlake2b().Compute(string(headerBytes))
	canonicalHash := [32]byte{}
	copy(canonicalHash[:], canonicalHashBytes)
	require.NotEqual(t, sha256.Sum256(headerBytes), canonicalHash, "canonical header hash must use the configured Blake2b hasher")
	domain, err := drwaprototype.DeriveNetworkDomain([]byte(chainID), canonicalHash)
	require.NoError(t, err)
	return headerBytes, canonicalHash, domain
}

func bytes32(first byte) []byte {
	result := make([]byte, 32)
	for index := range result {
		result[index] = first + byte(index)
	}
	return result
}

func putLevelDBValue(t *testing.T, path string, key, value []byte) {
	t.Helper()
	db, err := leveldb.OpenFile(path, nil)
	require.NoError(t, err)
	require.NoError(t, db.Put(key, value, &opt.WriteOptions{Sync: true}))
	require.NoError(t, db.Close())
}

func deleteLevelDBValue(t *testing.T, path string, key []byte) {
	t.Helper()
	db, err := leveldb.OpenFile(path, nil)
	require.NoError(t, err)
	require.NoError(t, db.Delete(key, &opt.WriteOptions{Sync: true}))
	require.NoError(t, db.Close())
}

type extractionFixture struct {
	root        string
	archiveNode string
	opts        options
	finalHeader []byte
	precursor   []byte
	roots       map[string]string
	planPath    string
	planSHA     string
	tracePath   string
	traceSHA    string
	bindingPath string
}

func newExtractionFixture(t *testing.T) extractionFixture {
	t.Helper()

	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "artifacts"), 0o700))
	archiveNode := filepath.Join(root, "node.archived-test")
	archiveWork := filepath.Join(root, "node_working_dirs.archived-test")
	require.NoError(t, os.MkdirAll(filepath.Join(archiveNode, "config"), 0o700))
	require.NoError(t, os.MkdirAll(archiveWork, 0o700))

	configBytes, err := os.ReadFile("../../cmd/node/config/config.toml")
	require.NoError(t, err)
	configBytes = []byte(strings.Replace(string(configBytes), `ChainID = "undefined"`, `ChainID = "local-testnet"`, 1))
	validatorConfigPath := filepath.Join(archiveNode, "config", "config_validator.toml")
	observerConfigPath := filepath.Join(archiveNode, "config", "config_observer.toml")
	require.NoError(t, os.WriteFile(validatorConfigPath, configBytes, 0o600))
	require.NoError(t, os.WriteFile(observerConfigPath, configBytes, 0o600))
	configSHA := sha256.Sum256(configBytes)
	configSHAHex := hex.EncodeToString(configSHA[:])

	nodesSetupBytes := []byte("{\"startTime\":1}\n")
	nodesSetupPath := filepath.Join(archiveNode, "config", "nodesSetup.json")
	require.NoError(t, os.WriteFile(nodesSetupPath, nodesSetupBytes, 0o600))
	nodesSetupSHA := sha256.Sum256(nodesSetupBytes)
	nodesSetupSHAHex := hex.EncodeToString(nodesSetupSHA[:])

	finalHeader, canonicalHash, domain := testIdentity(t, "local-testnet", 0)
	finalMeta := &block.MetaBlock{}
	require.NoError(t, (&marshal.GogoProtoMarshalizer{}).Unmarshal(finalMeta, finalHeader))
	finalMeta.ValidatorStatsRootHash = make([]byte, 32)
	precursor, err := (&marshal.GogoProtoMarshalizer{}).Marshal(finalMeta)
	require.NoError(t, err)

	activeWork := filepath.Join(root, "node_working_dirs")
	roles := []string{"0", "1", "2", "metachain"}
	planNodes := make([]interface{}, 0, 4)
	roots := make(map[string]string)
	for index, role := range roles {
		observerName := "observer" + strconv.Itoa(index)
		workingDirectory := filepath.Join(activeWork, observerName)
		planNodes = append(planNodes, map[string]interface{}{
			"argv": []string{
				"node",
				"-destination-shard-as-observer", role,
				"-working-directory", workingDirectory,
				"-operation-mode", "db-lookup-extension",
			},
		})
		roots[role] = filepath.Join(
			archiveWork,
			observerName,
			"db",
			"local-testnet",
			"Epoch_0",
			"Shard_"+role,
			"MetaBlock",
		)
		for partition := 0; partition < 4; partition++ {
			putLevelDBValue(t, filepath.Join(roots[role], strconv.Itoa(partition)), []byte("fixture"), []byte("fixture"))
		}
		putLevelDBValue(t, filepath.Join(roots[role], "0"), []byte(core.EpochStartIdentifier(0)), precursor)
	}
	for index := 0; index < 12; index++ {
		planNodes = append(planNodes, map[string]interface{}{
			"argv": []string{
				"node",
				"-working-directory", filepath.Join(activeWork, "validator"+strconv.Itoa(index)),
				"-config", "./config/config_validator.toml",
			},
		})
	}
	putLevelDBValue(t, filepath.Join(roots["metachain"], "2"), canonicalHash[:], finalHeader)

	plan := map[string]interface{}{
		"created_utc": "2026-08-25T00:00:00+00:00",
		"status":      readyTransitionPlan,
		"live_generation_hashes": map[string]interface{}{
			"nodes_setup": nodesSetupSHAHex,
		},
		"live_hashes": map[string]interface{}{
			"old_observer":  configSHAHex,
			"old_validator": configSHAHex,
		},
		"processes": map[string]interface{}{"nodes": planNodes},
		"targets": map[string]interface{}{
			"archived_node": archiveNode,
			"archived_work": archiveWork,
		},
	}
	planPath := filepath.Join(root, "transition-plan.json")
	planSHA := writeJSONTest(t, planPath, plan)
	embeddedPlan := cloneJSONMap(t, plan)
	embeddedPlan["created_utc"] = "2026-08-25T00:00:01Z"
	trace := map[string]interface{}{
		"archived_node": archiveNode,
		"archived_work": archiveWork,
		"status":        verifiedTransitionStatus,
		"plan":          embeddedPlan,
	}
	tracePath := filepath.Join(root, "transition-trace.json")
	traceSHA := writeJSONTest(t, tracePath, trace)

	binding := map[string]interface{}{
		"canonical_metachain_genesis_hash": hex.EncodeToString(canonicalHash[:]),
		"network_domain":                   hex.EncodeToString(domain[:]),
		"nodes_setup_sha256":               nodesSetupSHAHex,
		"stable_hashes": map[string]interface{}{
			"main_config": configSHAHex,
		},
	}
	bindingPath := filepath.Join(root, "binding.json")
	bindingSHA := writeJSONTest(t, bindingPath, binding)

	opts := options{
		mode:                    "extract",
		chainID:                 "local-testnet",
		epoch:                   0,
		expectedCanonicalHash:   hex.EncodeToString(canonicalHash[:]),
		expectedDomain:          hex.EncodeToString(domain[:]),
		bindingPath:             bindingPath,
		expectedBindingSHA:      bindingSHA,
		transitionPlanPath:      planPath,
		expectedPlanSHA:         planSHA,
		transitionTracePath:     tracePath,
		expectedTraceSHA:        traceSHA,
		headerOutputPath:        filepath.Join(root, "artifacts", "canonical-header.bin"),
		evidencePath:            filepath.Join(root, "artifacts", "extraction.json"),
		rehearsalRoot:           root,
		shard0ObserverMetaDB:    roots["0"],
		shard1ObserverMetaDB:    roots["1"],
		shard2ObserverMetaDB:    roots["2"],
		metachainObserverMetaDB: roots["metachain"],
	}
	return extractionFixture{
		root:        root,
		archiveNode: archiveNode,
		opts:        opts,
		finalHeader: finalHeader,
		precursor:   precursor,
		roots:       roots,
		planPath:    planPath,
		planSHA:     planSHA,
		tracePath:   tracePath,
		traceSHA:    traceSHA,
		bindingPath: bindingPath,
	}
}

func updateFixturePlanAndTrace(t *testing.T, fixture *extractionFixture, plan map[string]interface{}) {
	t.Helper()
	fixture.planSHA = writeJSONTest(t, fixture.planPath, plan)
	fixture.opts.expectedPlanSHA = fixture.planSHA
	embedded := cloneJSONMap(t, plan)
	embedded["created_utc"] = "2026-08-25T00:00:01Z"
	trace := readJSONMapTest(t, fixture.tracePath)
	trace["plan"] = embedded
	fixture.traceSHA = writeJSONTest(t, fixture.tracePath, trace)
	fixture.opts.expectedTraceSHA = fixture.traceSHA
}

func updateFixtureConfigs(t *testing.T, fixture *extractionFixture, mutate func(string) string) {
	t.Helper()
	validatorPath := filepath.Join(fixture.archiveNode, "config", "config_validator.toml")
	observerPath := filepath.Join(fixture.archiveNode, "config", "config_observer.toml")
	current, err := os.ReadFile(validatorPath)
	require.NoError(t, err)
	changed := []byte(mutate(string(current)))
	require.NotEqual(t, current, changed, "config mutation must change bytes")
	require.NoError(t, os.WriteFile(validatorPath, changed, 0o600))
	require.NoError(t, os.WriteFile(observerPath, changed, 0o600))
	digest := sha256.Sum256(changed)
	digestHex := hex.EncodeToString(digest[:])

	plan := readJSONMapTest(t, fixture.planPath)
	plan["live_hashes"].(map[string]interface{})["old_validator"] = digestHex
	plan["live_hashes"].(map[string]interface{})["old_observer"] = digestHex
	updateFixturePlanAndTrace(t, fixture, plan)

	binding := readJSONMapTest(t, fixture.bindingPath)
	binding["stable_hashes"].(map[string]interface{})["main_config"] = digestHex
	fixture.opts.expectedBindingSHA = writeJSONTest(t, fixture.bindingPath, binding)
}

func writeJSONTest(t *testing.T, path string, value interface{}) string {
	t.Helper()
	encoded, err := json.MarshalIndent(value, "", "  ")
	require.NoError(t, err)
	encoded = append(encoded, '\n')
	require.NoError(t, os.WriteFile(path, encoded, 0o600))
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func readJSONTest(t *testing.T, path string, destination interface{}) {
	t.Helper()
	value, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(value, destination))
}

func cloneJSONMap(t *testing.T, source map[string]interface{}) map[string]interface{} {
	t.Helper()
	encoded, err := json.Marshal(source)
	require.NoError(t, err)
	result := make(map[string]interface{})
	require.NoError(t, json.Unmarshal(encoded, &result))
	return result
}

func readJSONMapTest(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	value, err := os.ReadFile(path)
	require.NoError(t, err)
	result := make(map[string]interface{})
	require.NoError(t, json.Unmarshal(value, &result))
	return result
}

func mutateMetaHeader(t *testing.T, source []byte, mutate func(*block.MetaBlock)) []byte {
	t.Helper()
	marshalizer := &marshal.GogoProtoMarshalizer{}
	meta := &block.MetaBlock{}
	require.NoError(t, marshalizer.Unmarshal(meta, source))
	mutate(meta)
	result, err := marshalizer.Marshal(meta)
	require.NoError(t, err)
	return result
}
