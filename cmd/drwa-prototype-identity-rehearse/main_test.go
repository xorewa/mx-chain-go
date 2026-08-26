package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	coreBlake2b "github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	identityverify "github.com/multiversx/mx-chain-go/cmd/internal/drwaprototypeidentityverify"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype/networkidentity"
	"github.com/stretchr/testify/require"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"golang.org/x/sys/unix"
)

func TestRunRejectsHostProcess(t *testing.T) {
	require.ErrorContains(t, runWithBoundary(options{}, 2, allowIsolation), "container PID 1")
}

func TestContainerWriterRequiresEveryExternalArtifactDigest(t *testing.T) {
	for _, field := range []string{"plan", "identity tool", "isolation contract"} {
		t.Run(field, func(t *testing.T) {
			fixture := newWriterFixture(t, "")
			switch field {
			case "plan":
				fixture.opts.expectedPlanSHA = ""
			case "identity tool":
				fixture.opts.expectedIdentityToolSHA = ""
			case "isolation contract":
				fixture.opts.expectedContractSHA = ""
			}
			err := runFixture(t, fixture, fixture.opts, allowIsolation)
			require.ErrorContains(t, err, "is required and must be canonical")
			require.NoFileExists(t, fixture.opts.journalPath)
			assertAllTargetsAbsent(t, fixture.plan)
		})
	}
}

func TestContainerWriterRejectsWrongExternalArtifactDigests(t *testing.T) {
	for _, field := range []string{"plan", "identity tool", "isolation contract"} {
		t.Run(field, func(t *testing.T) {
			fixture := newWriterFixture(t, "")
			switch field {
			case "plan":
				fixture.opts.expectedPlanSHA = strings.Repeat("0", 64)
			case "identity tool":
				fixture.opts.expectedIdentityToolSHA = strings.Repeat("0", 64)
			case "isolation contract":
				fixture.opts.expectedContractSHA = strings.Repeat("0", 64)
			}
			err := runFixture(t, fixture, fixture.opts, allowIsolation)
			require.ErrorContains(t, err, "does not match expected")
			require.NoFileExists(t, fixture.opts.journalPath)
			assertAllTargetsAbsent(t, fixture.plan)
		})
	}
}

func TestContainerWriterRejectsEveryExactDockerCommandBoundaryMutation(t *testing.T) {
	mutations := map[string]func(*isolationContract){
		"image ID":        func(value *isolationContract) { value.ContainerImageID = "sha256:" + strings.Repeat("2", 64) },
		"image digest":    func(value *isolationContract) { value.ContainerImageDigest = "other@sha256:" + strings.Repeat("2", 64) },
		"platform":        func(value *isolationContract) { value.ContainerPlatform = "linux/arm64" },
		"container name":  func(value *isolationContract) { value.ContainerName = "../escape" },
		"hostname":        func(value *isolationContract) { value.ContainerHostname += "-other" },
		"user uid":        func(value *isolationContract) { value.ContainerUserUID = 0 },
		"user gid":        func(value *isolationContract) { value.ContainerUserGID = 0 },
		"pull policy":     func(value *isolationContract) { value.ContainerPullPolicy = "always" },
		"auto remove":     func(value *isolationContract) { value.ContainerAutoRemove = true },
		"PID mode":        func(value *isolationContract) { value.ContainerPIDMode = "private" },
		"entrypoint":      func(value *isolationContract) { value.ContainerEntrypoint += ".other" },
		"mount source":    func(value *isolationContract) { value.ContainerMountSource = filepath.Dir(value.RehearsalRoot) },
		"mount target":    func(value *isolationContract) { value.ContainerMountTarget = filepath.Dir(value.RehearsalRoot) },
		"read-only mount": func(value *isolationContract) { value.ContainerMountReadWrite = false },
		"seccomp digest":  func(value *isolationContract) { value.SeccompProfileSHA256 = strings.Repeat("0", 64) },
		"seccomp mount":   func(value *isolationContract) { value.SeccompMountReadOnly = false },
		"missing input mount": func(value *isolationContract) {
			value.ReadOnlyInputMounts = value.ReadOnlyInputMounts[:1]
		},
		"extra input mount": func(value *isolationContract) {
			value.ReadOnlyInputMounts = append(value.ReadOnlyInputMounts, value.ReadOnlyInputMounts[0])
		},
		"writable input mount": func(value *isolationContract) {
			value.ReadOnlyInputMounts[0].ReadOnly = false
		},
		"wrong input target": func(value *isolationContract) {
			value.ReadOnlyInputMounts[0].Target = value.RehearsalRoot
		},
		"wrong input device": func(value *isolationContract) {
			value.ReadOnlyInputMounts[0].Device++
		},
		"wrong input inode": func(value *isolationContract) {
			value.ReadOnlyInputMounts[0].Inode++
		},
		"unknown input purpose": func(value *isolationContract) {
			value.ReadOnlyInputMounts[0].Purpose = "unknown"
		},
		"plan path":       func(value *isolationContract) { value.MigrationPlanPath += ".other" },
		"identity path":   func(value *isolationContract) { value.IdentityToolPath += ".other" },
		"contract path":   func(value *isolationContract) { value.IsolationContractPath += ".other" },
		"journal path":    func(value *isolationContract) { value.JournalPath += ".other" },
		"summary path":    func(value *isolationContract) { value.SummaryPath += ".other" },
		"network mode":    func(value *isolationContract) { value.NetworkMode = "host" },
		"writable root":   func(value *isolationContract) { value.ReadOnlyContainerRoot = false },
		"capabilities":    func(value *isolationContract) { value.DroppedCapabilities = "NET_ADMIN" },
		"new privileges":  func(value *isolationContract) { value.NoNewPrivileges = false },
		"host network ns": func(value *isolationContract) { value.HostNetworkNamespace = "" },
		"runtime credit":  func(value *isolationContract) { value.AuthoritativeCredit = 1 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			fixture := newWriterFixture(t, "")
			mutate(&fixture.contract)
			fixture.opts.expectedContractSHA = writeJSON(t, fixture.opts.isolationContractPath, fixture.contract)
			err := runFixture(t, fixture, fixture.opts, allowIsolation)
			require.Error(t, err)
			require.NoFileExists(t, fixture.opts.journalPath)
			assertAllTargetsAbsent(t, fixture.plan)
		})
	}
}

func TestWriterSeccompProfileRejectsSemanticDriftWithMatchingDigest(t *testing.T) {
	fixture := newWriterFixture(t, "")
	require.NoError(t, validateSeccompProfile(fixture.contract.SeccompProfilePath, fixture.contract.SeccompProfileSHA256))

	driftedSHA := writeJSON(t, fixture.contract.SeccompProfilePath, map[string]interface{}{
		"defaultAction": "SCMP_ACT_ALLOW",
		"architectures": []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"},
		"syscalls": []map[string]interface{}{{
			"names": []string{"bind"}, "action": "SCMP_ACT_ERRNO", "errnoRet": 1,
		}},
	})
	require.ErrorContains(t, validateSeccompProfile(fixture.contract.SeccompProfilePath, driftedSHA), "differs")
}

func TestEvidenceBindingManifestRejectsEveryIdentityMutation(t *testing.T) {
	fixture := newWriterFixture(t, "")
	require.Len(t, fixture.contract.EvidenceBindings, 16)
	bindings, err := validateEvidenceBindings(fixture.contract, fixture.plan)
	require.NoError(t, err)
	require.Len(t, bindings, 16)

	mutations := map[string]func(*isolationContract){
		"missing": func(contract *isolationContract) {
			contract.EvidenceBindings = contract.EvidenceBindings[:15]
		},
		"duplicate node": func(contract *isolationContract) {
			contract.EvidenceBindings[1].NodeID = contract.EvidenceBindings[0].NodeID
		},
		"unknown node": func(contract *isolationContract) {
			contract.EvidenceBindings[0].NodeID = "unknown"
		},
		"noncanonical digest": func(contract *isolationContract) {
			contract.EvidenceBindings[0].SHA256 = "ABC"
		},
		"zero size": func(contract *isolationContract) {
			contract.EvidenceBindings[0].Size = 0
		},
		"outside artifacts": func(contract *isolationContract) {
			contract.EvidenceBindings[0].Path = filepath.Join(fixture.root, "outside.json")
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := fixture.contract
			changed.EvidenceBindings = append([]evidenceBinding(nil), fixture.contract.EvidenceBindings...)
			mutate(&changed)
			_, err = validateEvidenceBindings(changed, fixture.plan)
			require.Error(t, err)
		})
	}

	first := fixture.contract.EvidenceBindings[0]
	for name, mutate := range map[string]func(*evidenceBinding){
		"wrong digest": func(binding *evidenceBinding) { binding.SHA256 = strings.Repeat("0", 64) },
		"wrong size":   func(binding *evidenceBinding) { binding.Size++ },
		"wrong node":   func(binding *evidenceBinding) { binding.NodeID = fixture.plan.Nodes[1].ID },
	} {
		t.Run(name, func(t *testing.T) {
			changed := first
			mutate(&changed)
			_, _, err = validateBoundVerifierEvidence(changed, fixture.plan, fixture.plan.Nodes[0])
			require.Error(t, err)
		})
	}
}

func TestStrictDecodeRejectsUnknownAndDuplicateFields(t *testing.T) {
	var plan migrationPlan
	require.ErrorContains(t, strictDecode([]byte(`{"unknown":true}`), &plan), "unknown field")
	require.ErrorContains(t, strictDecode([]byte(`{"schema":"a","schema":"b"}`), &plan), "duplicate JSON object key")
}

func TestBoundVerifierEvidenceRejectsEveryV2TupleBindingMutation(t *testing.T) {
	fixture := newWriterFixture(t, "")
	node := fixture.plan.Nodes[0]
	originalPath := fixture.contract.EvidenceBindings[0].Path
	originalBytes, err := os.ReadFile(originalPath)
	require.NoError(t, err)
	var original verifierEvidence
	require.NoError(t, strictDecode(originalBytes, &original))

	mutations := map[string]func(*verifierEvidence){
		"schema":                  func(value *verifierEvidence) { value.Schema = "wrong" },
		"chain ID":                func(value *verifierEvidence) { value.ChainID += "-wrong" },
		"epoch":                   func(value *verifierEvidence) { value.CanonicalEpoch++ },
		"provenance":              func(value *verifierEvidence) { value.Provenance = "wrong" },
		"canonical hash":          func(value *verifierEvidence) { value.CanonicalHash = strings.Repeat("0", 64) },
		"network domain":          func(value *verifierEvidence) { value.NetworkDomain = strings.Repeat("0", 64) },
		"header hash":             func(value *verifierEvidence) { value.HeaderSHA256 = strings.Repeat("0", 64) },
		"identity schema version": func(value *verifierEvidence) { value.IdentitySchemaVersion++ },
		"storage key":             func(value *verifierEvidence) { value.StorageKeyHex = strings.Repeat("0", len(value.StorageKeyHex)) },
		"envelope hash":           func(value *verifierEvidence) { value.EnvelopeSHA256 = strings.Repeat("0", 64) },
		"envelope length":         func(value *verifierEvidence) { value.EnvelopeLength++ },
	}
	for name, mutate := range mutations {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			changed := original
			mutate(&changed)
			path := filepath.Join(fixture.root, "artifacts", "mutated-"+strings.ReplaceAll(name, " ", "-")+".json")
			digest := writeJSON(t, path, changed)
			info, statErr := os.Stat(path)
			require.NoError(t, statErr)
			binding := evidenceBinding{NodeID: node.ID, Path: path, SHA256: digest, Size: int(info.Size())}
			_, _, validateErr := validateBoundVerifierEvidence(binding, fixture.plan, node)
			require.Error(t, validateErr)
		})
	}
}

func TestContainerWriterRevalidatesThenDurablyWritesExactlySixteen(t *testing.T) {
	fixture := newWriterFixture(t, "")
	require.NoError(t, runFixture(t, fixture, fixture.opts, allowIsolation))

	var result summary
	readJSON(t, fixture.opts.summaryPath, &result)
	require.Equal(t, "ALL_SIXTEEN_EMERGENCY_IDENTITIES_DURABLE_NO_NODE_LAUNCHED_NO_RUNTIME_CREDIT", result.Status)
	require.Len(t, result.CompletedNodes, 16)
	require.True(t, result.DurableCloseReopenVerified)
	for _, node := range fixture.plan.Nodes {
		db, openErr := leveldb.OpenFile(node.TargetDBPath, &opt.Options{ReadOnly: true, ErrorIfMissing: true})
		require.NoError(t, openErr)
		value, getErr := db.Get(networkidentity.Key(0), nil)
		require.NoError(t, getErr)
		record, decodeErr := networkidentity.Decode(value, []byte(fixture.plan.ChainID))
		require.NoError(t, decodeErr)
		require.Equal(t, networkidentity.EmergencyMigration, record.Provenance)
		require.Equal(t, fixture.header, record.HeaderBytes)
		require.NoError(t, db.Close())
	}

	events := readJournal(t, fixture.opts.journalPath)
	firstWrite := -1
	allRevalidated := -1
	for index, event := range events {
		if event.Status == "ALL_SIXTEEN_REVALIDATED_BEFORE_FIRST_WRITE" {
			allRevalidated = index
		}
		if event.Status == "NODE_WRITE_RESERVED" && firstWrite < 0 {
			firstWrite = index
		}
	}
	require.GreaterOrEqual(t, allRevalidated, 0)
	require.Greater(t, firstWrite, allRevalidated)
	require.NoError(t, reconcileJournalEvidenceBindings(fixture.opts.journalPath))
	require.Error(t, runFixture(t, fixture, fixture.opts, allowIsolation))
}

func TestJournalEvidenceBindingDetectsPostValidationReplacement(t *testing.T) {
	fixture := newWriterFixture(t, "")
	require.NoError(t, runFixture(t, fixture, fixture.opts, allowIsolation))
	events := readJournal(t, fixture.opts.journalPath)
	var evidenceEvent journalEvent
	for _, event := range events {
		if event.Status == "NODE_REVALIDATED_TARGET_ABSENT" {
			evidenceEvent = event
			break
		}
	}
	require.NotEmpty(t, evidenceEvent.PlanEvidence)
	require.Len(t, evidenceEvent.EvidenceSHA, 64)
	require.Positive(t, evidenceEvent.EvidenceSize)
	require.NoError(t, os.WriteFile(evidenceEvent.PlanEvidence, []byte("{}\n"), 0o600))
	require.Error(t, reconcileJournalEvidenceBindings(fixture.opts.journalPath))
}

func TestContainerWriterRejectsRouteBeforeReservingEvidence(t *testing.T) {
	fixture := newWriterFixture(t, "")
	err := runFixture(t, fixture, fixture.opts, func(isolationContract, migrationPlan) error { return errors.New("non-loopback route") })
	require.ErrorContains(t, err, "non-loopback route")
	require.NoFileExists(t, fixture.opts.journalPath)
	require.NoFileExists(t, fixture.opts.summaryPath)
	assertAllTargetsAbsent(t, fixture.plan)
}

func TestContainerWriterVerifierFailureLeavesEveryTargetAbsent(t *testing.T) {
	fixture := newWriterFixture(t, "node-07")
	err := runFixture(t, fixture, fixture.opts, allowIsolation)
	require.ErrorContains(t, err, "mutation-boundary revalidation node-07")
	assertAllTargetsAbsent(t, fixture.plan)

	events := readJournal(t, fixture.opts.journalPath)
	for _, event := range events {
		require.NotEqual(t, "NODE_WRITE_RESERVED", event.Status)
	}
}

func TestBoundVerifierEvidenceRejectsPathReplacement(t *testing.T) {
	fixture := newWriterFixture(t, "")
	binding := fixture.contract.EvidenceBindings[0]
	_, _, err := validateBoundVerifierEvidence(binding, fixture.plan, fixture.plan.Nodes[0])
	require.NoError(t, err)
	replacement := binding.Path + ".replacement"
	require.NoError(t, os.WriteFile(replacement, []byte("{}\n"), 0o600))
	require.NoError(t, os.Rename(replacement, binding.Path))
	_, _, err = validateBoundVerifierEvidence(binding, fixture.plan, fixture.plan.Nodes[0])
	require.ErrorContains(t, err, "does not match expected")
}

func TestSealedVerifierDetectsInPlaceMutation(t *testing.T) {
	fixture := newWriterFixture(t, "")
	sealed, err := openVerifiedExecutable(fixture.opts.identityToolPath, fixture.opts.expectedIdentityToolSHA)
	require.NoError(t, err)
	defer sealed.Close()

	mutated, err := os.ReadFile(fixture.opts.identityToolPath)
	require.NoError(t, err)
	mutated[len(mutated)-1] ^= 1
	require.NoError(t, os.WriteFile(fixture.opts.identityToolPath, mutated, 0o700))
	require.ErrorContains(t, sealed.verifyUnchanged(), "bytes changed")
}

func TestVerifierExecutionSnapshotIsAnonymousAndReadOnly(t *testing.T) {
	fixture := newWriterFixture(t, "")
	sealed, err := openVerifiedExecutable(fixture.opts.identityToolPath, fixture.opts.expectedIdentityToolSHA)
	require.NoError(t, err)
	defer sealed.Close()

	info, err := sealed.file.Stat()
	require.NoError(t, err)
	stat := info.Sys().(*syscall.Stat_t)
	require.Zero(t, stat.Nlink)
	require.Equal(t, os.FileMode(0o500), info.Mode().Perm())
	require.Equal(t,
		unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL,
		sealed.snapshotSeals&(unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL),
	)
	writeFD, err := syscall.Open(fmt.Sprintf("/proc/self/fd/%d", sealed.file.Fd()), syscall.O_WRONLY, 0)
	if err == nil {
		_, writeErr := syscall.Write(writeFD, []byte{'X'})
		require.Error(t, writeErr)
		_ = syscall.Close(writeFD)
	}
	_, err = sealed.file.WriteAt([]byte{'X'}, 0)
	require.Error(t, err)

	original, err := os.ReadFile(fixture.opts.identityToolPath)
	require.NoError(t, err)
	mutated := append([]byte(nil), original...)
	mutated[len(mutated)-1] ^= 1
	require.NoError(t, os.WriteFile(fixture.opts.identityToolPath, mutated, 0o700))

	_, err = sealed.file.Seek(0, 0)
	require.NoError(t, err)
	snapshot, err := io.ReadAll(sealed.file)
	require.NoError(t, err)
	require.Equal(t, original, snapshot)
	require.NotEqual(t, mutated, snapshot)
}

func TestContainerWriterExistingTargetLeavesOtherTargetsAbsent(t *testing.T) {
	fixture := newWriterFixture(t, "")
	preexisting := fixture.plan.Nodes[len(fixture.plan.Nodes)-1].TargetDBPath
	require.NoError(t, os.Mkdir(preexisting, 0o700))
	err := runFixture(t, fixture, fixture.opts, allowIsolation)
	require.ErrorContains(t, err, "target already exists before all-node preflight")
	for _, node := range fixture.plan.Nodes[:len(fixture.plan.Nodes)-1] {
		require.NoDirExists(t, node.TargetDBPath)
	}
	require.DirExists(t, preexisting)
}

func TestContainerWriterRejectsSymlinkedBoundInput(t *testing.T) {
	fixture := newWriterFixture(t, "")
	linkPath := filepath.Join(filepath.Dir(fixture.opts.planPath), "plan-link.json")
	require.NoError(t, os.Symlink(fixture.opts.planPath, linkPath))
	fixture.opts.planPath = linkPath
	err := runFixture(t, fixture, fixture.opts, allowIsolation)
	require.ErrorContains(t, err, "symbolic-link")
	require.NoFileExists(t, fixture.opts.journalPath)
	assertAllTargetsAbsent(t, fixture.plan)
}

func TestOutputDirectoryRejectsIntermediateSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "artifacts")))
	directory, err := openOutputDirectory(
		root,
		filepath.Join(root, "artifacts", "journal.jsonl"),
		filepath.Join(root, "artifacts", "summary.json"),
	)
	require.Error(t, err)
	require.Nil(t, directory)
	require.NoFileExists(t, filepath.Join(outside, "journal.jsonl"))
}

func TestLevelDBWritePredicatesAreExplicitlyPinned(t *testing.T) {
	require.True(t, exclusiveDBOptions().ErrorIfExist)
	require.True(t, synchronousWriteOptions().Sync)
}

func TestSynchronousWriteQualificationIsBoundToExactStorageDependencyPin(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	goMod, err := os.ReadFile(filepath.Join(repoRoot, "go.mod"))
	require.NoError(t, err)
	require.Contains(
		t,
		string(goMod),
		"replace github.com/multiversx/mx-chain-storage-go => github.com/xorewa/mx-chain-storage-go v0.0.0-20260714091422-a9e4a9bb00bb",
		"any storage dependency repin must invalidate and rerun synchronous-write qualification",
	)
}

type crashWriteSpec struct {
	Node     migrationPlanNode `json:"node"`
	Plan     migrationPlan     `json:"plan"`
	Envelope []byte            `json:"envelope"`
	Header   []byte            `json:"header"`
}

func TestSynchronousPutSurvivesProcessExitBeforeClose(t *testing.T) {
	if specPath := os.Getenv("DRWA_REHEARSAL_CRASH_WRITE_SPEC"); specPath != "" {
		var spec crashWriteSpec
		readJSON(t, specPath, &spec)
		err := writeAndReopenWithHooks(spec.Node, spec.Plan, spec.Envelope, spec.Header, nil, func() {
			os.Exit(0)
		})
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(91)
	}

	fixture := newWriterFixture(t, "")
	node := fixture.plan.Nodes[0]
	record, err := networkIdentityRecordForPlan(fixture.plan, fixture.header)
	require.NoError(t, err)
	envelope, err := networkidentity.Encode(record)
	require.NoError(t, err)
	specPath := filepath.Join(fixture.root, "artifacts", "crash-write-spec.json")
	_ = writeJSON(t, specPath, crashWriteSpec{Node: node, Plan: fixture.plan, Envelope: envelope, Header: fixture.header})
	command := exec.Command(os.Args[0], "-test.run=^TestSynchronousPutSurvivesProcessExitBeforeClose$")
	command.Env = append(os.Environ(), "DRWA_REHEARSAL_CRASH_WRITE_SPEC="+specPath)
	require.NoError(t, command.Run())

	db, err := leveldb.OpenFile(node.TargetDBPath, &opt.Options{ReadOnly: true, ErrorIfMissing: true})
	require.NoError(t, err)
	stored, err := db.Get(networkidentity.Key(fixture.plan.CanonicalEpoch), nil)
	require.NoError(t, err)
	require.NoError(t, db.Close())
	require.Equal(t, envelope, stored)
	record, err = networkidentity.Decode(stored, []byte(fixture.plan.ChainID))
	require.NoError(t, err)
	require.NoError(t, verifyCanonicalHeader(fixture.plan, record.HeaderBytes))
}

func TestWriteAndReopenRejectsTargetCreatedAtOpenBoundary(t *testing.T) {
	fixture := newWriterFixture(t, "")
	node := fixture.plan.Nodes[0]
	record, err := networkIdentityRecordForPlan(fixture.plan, fixture.header)
	require.NoError(t, err)
	envelope, err := networkidentity.Encode(record)
	require.NoError(t, err)
	err = writeAndReopenWithHooks(node, fixture.plan, envelope, fixture.header, func() error {
		return os.Mkdir(node.TargetDBPath, 0o700)
	}, nil)
	require.Error(t, err)
	entries, readErr := os.ReadDir(node.TargetDBPath)
	require.NoError(t, readErr)
	require.Empty(t, entries)
}

func TestWriteAndReopenRejectsDetachedAndReplacedShardParent(t *testing.T) {
	fixture := newWriterFixture(t, "")
	node := fixture.plan.Nodes[0]
	record, err := networkIdentityRecordForPlan(fixture.plan, fixture.header)
	require.NoError(t, err)
	envelope, err := networkidentity.Encode(record)
	require.NoError(t, err)
	parent := filepath.Dir(node.TargetDBPath)
	detached := parent + ".detached"
	err = writeAndReopenWithHooks(node, fixture.plan, envelope, fixture.header, func() error {
		if renameErr := os.Rename(parent, detached); renameErr != nil {
			return renameErr
		}
		return os.Mkdir(parent, 0o700)
	}, nil)
	require.ErrorContains(t, err, "parent filesystem identity changed")
	require.NoDirExists(t, node.TargetDBPath)
	require.DirExists(t, filepath.Join(detached, filepath.Base(node.TargetDBPath)))
}

func TestWriteAndReopenRejectsDetachedShardParentWithoutReplacement(t *testing.T) {
	fixture := newWriterFixture(t, "")
	node := fixture.plan.Nodes[0]
	record, err := networkIdentityRecordForPlan(fixture.plan, fixture.header)
	require.NoError(t, err)
	envelope, err := networkidentity.Encode(record)
	require.NoError(t, err)
	parent := filepath.Dir(node.TargetDBPath)
	detached := parent + ".detached"
	err = writeAndReopenWithHooks(node, fixture.plan, envelope, fixture.header, func() error {
		return os.Rename(parent, detached)
	}, nil)
	require.ErrorContains(t, err, "exact target parent no longer resolves")
	require.NoDirExists(t, node.TargetDBPath)
	require.DirExists(t, filepath.Join(detached, filepath.Base(node.TargetDBPath)))
}

func TestWriteAndReopenRejectsDetachedAndReplacedNodeRoot(t *testing.T) {
	fixture := newWriterFixture(t, "")
	node := fixture.plan.Nodes[0]
	record, err := networkIdentityRecordForPlan(fixture.plan, fixture.header)
	require.NoError(t, err)
	envelope, err := networkidentity.Encode(record)
	require.NoError(t, err)
	detached := node.NodeRoot + ".detached"
	err = writeAndReopenWithBoundaryHooks(node, fixture.plan, envelope, fixture.header, func() error {
		if renameErr := os.Rename(node.NodeRoot, detached); renameErr != nil {
			return renameErr
		}
		return os.MkdirAll(filepath.Dir(node.TargetDBPath), 0o700)
	}, nil, nil)
	require.ErrorContains(t, err, "parent filesystem identity changed")
	require.NoDirExists(t, node.TargetDBPath)
	detachedTarget := filepath.Join(detached, "db", fixture.plan.ChainID, "Static", "Shard_"+node.ShardID, filepath.Base(node.TargetDBPath))
	require.DirExists(t, detachedTarget)
}

func TestWriteAndReopenRejectsDetachedNodeRootWithoutReplacement(t *testing.T) {
	fixture := newWriterFixture(t, "")
	node := fixture.plan.Nodes[0]
	record, err := networkIdentityRecordForPlan(fixture.plan, fixture.header)
	require.NoError(t, err)
	envelope, err := networkidentity.Encode(record)
	require.NoError(t, err)
	detached := node.NodeRoot + ".detached"
	err = writeAndReopenWithBoundaryHooks(node, fixture.plan, envelope, fixture.header, func() error {
		return os.Rename(node.NodeRoot, detached)
	}, nil, nil)
	require.ErrorContains(t, err, "exact target parent no longer resolves")
	require.NoDirExists(t, node.TargetDBPath)
	detachedTarget := filepath.Join(detached, "db", fixture.plan.ChainID, "Static", "Shard_"+node.ShardID, filepath.Base(node.TargetDBPath))
	require.DirExists(t, detachedTarget)
}

func TestFailureJournalIsFsyncedForEveryInjectedWriteBoundary(t *testing.T) {
	for _, fault := range []string{"PUT", "CLOSE", "REOPEN", "GET", "DECODE"} {
		t.Run(fault, func(t *testing.T) {
			fixture := newWriterFixture(t, "")
			err := runWithBoundaryAndWriterAndVerifier(fixture.opts, 1, allowIsolation, func(migrationPlanNode, migrationPlan, []byte, []byte) error {
				return errors.New("injected " + fault)
			}, fixtureBoundaryVerifier(t, fixture))
			require.ErrorContains(t, err, "injected "+fault)
			events := readJournal(t, fixture.opts.journalPath)
			require.Equal(t, "ATTEMPT_FAILED_NO_RETRY", events[len(events)-1].Status)
			require.Contains(t, events[len(events)-1].Detail, "NODE_SYNCHRONOUS_WRITE_CLOSE_REOPEN")
			require.Empty(t, events[len(events)-1].Completed)
			assertAllTargetsAbsent(t, fixture.plan)
		})
	}
}

func TestFailureJournalPreservesCompletedNodesAndStopsLaterWrites(t *testing.T) {
	fixture := newWriterFixture(t, "")
	writes := 0
	err := runWithBoundaryAndWriterAndVerifier(fixture.opts, 1, allowIsolation, func(
		node migrationPlanNode,
		plan migrationPlan,
		envelope []byte,
		header []byte,
	) error {
		writes++
		if writes == 2 {
			return errors.New("injected second-node failure")
		}
		return writeAndReopen(node, plan, envelope, header)
	}, fixtureBoundaryVerifier(t, fixture))
	require.ErrorContains(t, err, "injected second-node failure")
	events := readJournal(t, fixture.opts.journalPath)
	last := events[len(events)-1]
	require.Equal(t, "ATTEMPT_FAILED_NO_RETRY", last.Status)
	require.Equal(t, []string{"node-00"}, last.Completed)
	require.DirExists(t, fixture.plan.Nodes[0].TargetDBPath)
	for _, node := range fixture.plan.Nodes[1:] {
		require.NoDirExists(t, node.TargetDBPath)
	}
}

func TestSummaryReservationFailureLeavesNonEmptyFailureJournal(t *testing.T) {
	fixture := newWriterFixture(t, "")
	require.NoError(t, os.WriteFile(fixture.opts.summaryPath, []byte("preexisting"), 0o600))
	err := runFixture(t, fixture, fixture.opts, allowIsolation)
	require.ErrorContains(t, err, "reserve summary")
	events := readJournal(t, fixture.opts.journalPath)
	require.Equal(t, "ATTEMPT_RESERVED_NO_NODE_WRITTEN", events[0].Status)
	require.Equal(t, "ATTEMPT_FAILED_NO_RETRY", events[len(events)-1].Status)
	require.Contains(t, events[len(events)-1].Detail, "RESERVE_SUMMARY")
	assertAllTargetsAbsent(t, fixture.plan)
}

func TestVerifyCanonicalHeaderRejectsEveryBoundIdentityMutation(t *testing.T) {
	fixture := newWriterFixture(t, "")
	require.NoError(t, verifyCanonicalHeader(fixture.plan, fixture.header))
	mutations := map[string]func(*migrationPlan){
		"chain":  func(plan *migrationPlan) { plan.ChainID = "other-chain" },
		"epoch":  func(plan *migrationPlan) { plan.CanonicalEpoch++ },
		"hash":   func(plan *migrationPlan) { plan.CanonicalHash = strings.Repeat("0", 64) },
		"domain": func(plan *migrationPlan) { plan.NetworkDomain = strings.Repeat("0", 64) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := fixture.plan
			mutate(&changed)
			require.Error(t, verifyCanonicalHeader(changed, fixture.header))
		})
	}
	require.Error(t, verifyCanonicalHeader(fixture.plan, append(append([]byte(nil), fixture.header...), 0)))
}

func TestRuntimeIsolationParsersAreExact(t *testing.T) {
	fields := parseColonFields("NoNewPrivs:\t1\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nSeccomp:\t2\n")
	require.Equal(t, "1", fields["NoNewPrivs"])
	require.Equal(t, "0000000000000000", fields["CapEff"])
	require.Equal(t, "2", fields["Seccomp"])
	require.NoError(t, validateIsolationStatus(fields))
	for _, field := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		t.Run(field, func(t *testing.T) {
			mutated := make(map[string]string, len(fields))
			for key, value := range fields {
				mutated[key] = value
			}
			mutated[field] = "0000000000000001"
			require.ErrorContains(t, validateIsolationStatus(mutated), field)
		})
	}
	mounts := "1 0 0:1 / / ro,relatime - overlay overlay ro\n2 1 0:2 / /tmp/rehearsal rw,nosuid - ext4 /dev/x rw\n3 1 0:3 / /tmp/writer-seccomp.json ro,nosuid - ext4 /dev/x ro\n4 1 0:4 / /tmp/archive ro,nosuid - ext4 /dev/x ro\n5 1 0:5 / /tmp/qualification ro,nosuid - ext4 /dev/x ro"
	mode, found := mountMode(mounts, "/")
	require.True(t, found)
	require.Equal(t, "ro", mode)
	mode, found = mountMode(mounts, "/tmp/rehearsal")
	require.True(t, found)
	require.Equal(t, "rw", mode)
	contract := isolationContract{
		RehearsalRoot: "/tmp/rehearsal", SeccompProfilePath: "/tmp/writer-seccomp.json",
		ReadOnlyInputMounts: []readOnlyInputMount{
			{Purpose: "closed-checkpoint-archive", Target: "/tmp/archive"},
			{Purpose: "qualification-lineage", Target: "/tmp/qualification"},
		},
	}
	require.NoError(t, validateIsolationMounts(mounts, contract))
	changed := contract
	changed.SeccompProfilePath = "/tmp/missing-seccomp.json"
	require.Error(t, validateIsolationMounts(mounts, changed))
	require.Error(t, validateIsolationMounts(strings.Replace(mounts, "/tmp/writer-seccomp.json ro,", "/tmp/writer-seccomp.json rw,", 1), contract))
	require.Error(t, validateIsolationMounts(strings.Replace(mounts, "/tmp/archive ro,", "/tmp/archive rw,", 1), contract))
	changed = contract
	changed.ReadOnlyInputMounts = changed.ReadOnlyInputMounts[:1]
	require.NoError(t, validateIsolationMounts(mounts, changed))
	changed.ReadOnlyInputMounts[0].Target = "/tmp/missing-archive"
	require.Error(t, validateIsolationMounts(mounts, changed))
}

func TestDeriveRequiredReadOnlyRootsRejectsBroadAndMisplacedInputs(t *testing.T) {
	fixture := newWriterFixture(t, "")

	archiveRoot, qualificationRoot, err := deriveRequiredReadOnlyRoots(fixture.plan)
	require.NoError(t, err)
	require.Equal(t, filepath.Dir(fixture.plan.Nodes[0].SourceNodeRoot), archiveRoot)
	require.True(t, pathWithin(qualificationRoot, fixture.plan.BindingPath))
	require.True(t, pathWithin(qualificationRoot, fixture.plan.TransitionPlanPath))
	require.True(t, pathWithin(qualificationRoot, fixture.plan.TransitionTracePath))

	t.Run("source root is not a direct archive child", func(t *testing.T) {
		changed := fixture.plan
		changed.Nodes = append([]migrationPlanNode(nil), fixture.plan.Nodes...)
		changed.Nodes[0].SourceNodeRoot = filepath.Join(changed.Nodes[0].SourceNodeRoot, "nested")
		_, _, deriveErr := deriveRequiredReadOnlyRoots(changed)
		require.ErrorContains(t, deriveErr, "direct children")
	})

	t.Run("internal artifact escapes rehearsal artifacts", func(t *testing.T) {
		changed := fixture.plan
		changed.HeaderPath = filepath.Join(changed.RehearsalRoot, "header.bin")
		_, _, deriveErr := deriveRequiredReadOnlyRoots(changed)
		require.ErrorContains(t, deriveErr, "not a direct rehearsal artifacts child")
	})

	t.Run("lineage path escapes to filesystem root", func(t *testing.T) {
		changed := fixture.plan
		changed.TransitionTracePath = "/var/tmp/unrelated-transition-trace.json"
		_, _, deriveErr := deriveRequiredReadOnlyRoots(changed)
		require.ErrorContains(t, deriveErr, "exact qualification")
	})

	t.Run("lineage path creates a non-root broad common ancestor", func(t *testing.T) {
		changed := fixture.plan
		changed.TransitionTracePath = filepath.Join(filepath.Dir(qualificationRoot), "unrelated", "trace.json")
		_, _, deriveErr := deriveRequiredReadOnlyRoots(changed)
		require.ErrorContains(t, deriveErr, "exact qualification")
	})

	t.Run("qualification lineage overlaps rehearsal", func(t *testing.T) {
		changed := fixture.plan
		lineageRoot := filepath.Join(changed.RehearsalRoot, "qualification")
		changed.BindingPath = filepath.Join(lineageRoot, "runtime", "S1", "binding.json")
		changed.TransitionPlanPath = filepath.Join(lineageRoot, "traces", "plan.json")
		changed.TransitionTracePath = filepath.Join(lineageRoot, "traces", "trace.json")
		_, _, deriveErr := deriveRequiredReadOnlyRoots(changed)
		require.ErrorContains(t, deriveErr, "overlaps the rehearsal root")
	})

	t.Run("archive overlaps qualification lineage", func(t *testing.T) {
		changed := fixture.plan
		changed.Nodes = append([]migrationPlanNode(nil), fixture.plan.Nodes...)
		for index := range changed.Nodes {
			changed.Nodes[index].SourceNodeRoot = filepath.Join(qualificationRoot, changed.Nodes[index].ID)
		}
		_, _, deriveErr := deriveRequiredReadOnlyRoots(changed)
		require.ErrorContains(t, deriveErr, "roots overlap")
	})
}

func TestRuntimeIsolationLiveProbe(t *testing.T) {
	root := os.Getenv("DRWA_REHEARSAL_ISOLATION_PROBE_ROOT")
	if root == "" {
		t.Skip("container-only runtime isolation probe")
	}
	hostNamespace := os.Getenv("DRWA_REHEARSAL_HOST_NETNS")
	require.NotEmpty(t, hostNamespace)
	seccompPath := os.Getenv("DRWA_REHEARSAL_SECCOMP_PATH")
	require.NotEmpty(t, seccompPath)
	archivePath := os.Getenv("DRWA_REHEARSAL_ARCHIVE_PATH")
	qualificationPath := os.Getenv("DRWA_REHEARSAL_QUALIFICATION_PATH")
	require.NotEmpty(t, archivePath)
	require.NotEmpty(t, qualificationPath)
	executable, err := os.Executable()
	require.NoError(t, err)
	hostname, err := os.Hostname()
	require.NoError(t, err)
	require.NoError(t, requireRuntimeIsolation(
		isolationContract{
			HostNetworkNamespace: hostNamespace, ContainerUserUID: os.Geteuid(), ContainerUserGID: os.Getegid(),
			ContainerEntrypoint: executable, ContainerHostname: hostname, SeccompProfilePath: seccompPath,
			RehearsalRoot: root,
			ReadOnlyInputMounts: []readOnlyInputMount{
				{Purpose: "closed-checkpoint-archive", Target: archivePath},
				{Purpose: "qualification-lineage", Target: qualificationPath},
			},
		},
		migrationPlan{RehearsalRoot: root},
	))
}

func TestActualReadOnlyVerifierContract(t *testing.T) {
	planPath := os.Getenv("DRWA_REHEARSAL_ACTUAL_PLAN")
	if planPath == "" {
		t.Skip("external exact-artifact verifier integration")
	}
	evidencePath := os.Getenv("DRWA_REHEARSAL_ACTUAL_EVIDENCE")
	require.NotEmpty(t, evidencePath)
	planBytes, planSHA, err := readExactRegular(planPath, os.Getenv("DRWA_REHEARSAL_ACTUAL_PLAN_SHA"))
	require.NoError(t, err)
	var plan migrationPlan
	require.NoError(t, strictDecode(planBytes, &plan))
	require.NoError(t, validatePlan(plan))
	evidenceBytes, evidenceSHA, err := readExactRegular(evidencePath, "")
	require.NoError(t, err)
	binding := evidenceBinding{NodeID: plan.Nodes[0].ID, Path: evidencePath, SHA256: evidenceSHA, Size: len(evidenceBytes)}
	_, _, err = validateBoundVerifierEvidence(binding, plan, plan.Nodes[0])
	require.NoError(t, err)

	t.Run("wrong evidence digest", func(t *testing.T) {
		changed := binding
		changed.SHA256 = strings.Repeat("0", 64)
		_, _, err = validateBoundVerifierEvidence(changed, plan, plan.Nodes[0])
		require.Error(t, err)
	})
	t.Run("wrong shard binding", func(t *testing.T) {
		changed := plan.Nodes[0]
		changed.ShardID = "2"
		_, _, err = validateBoundVerifierEvidence(binding, plan, changed)
		require.Error(t, err)
	})
	require.NotEmpty(t, planSHA)
}

type writerFixture struct {
	root     string
	header   []byte
	plan     migrationPlan
	contract isolationContract
	opts     options
}

func runFixture(
	t *testing.T,
	fixture writerFixture,
	opts options,
	isolationCheck func(isolationContract, migrationPlan) error,
) error {
	t.Helper()
	return runWithBoundaryAndWriterAndVerifier(
		opts, 1, isolationCheck, writeAndReopen, fixtureBoundaryVerifier(t, fixture),
	)
}

// fixtureBoundaryVerifier isolates the writer's unit/fault tests from the much larger
// lineage fixture. Production always supplies identityverify.VerifyPlanBoundary. Exact
// production integration is exercised separately against all 16 closed-archive plans.
func fixtureBoundaryVerifier(t *testing.T, fixture writerFixture) planBoundaryVerifier {
	t.Helper()
	return func(request identityverify.PlanRequest) (identityverify.PlanEvidence, error) {
		if request.MigrationPlanPath != fixture.opts.planPath {
			return identityverify.PlanEvidence{}, errors.New("fixture migration-plan path mismatch")
		}
		header, err := os.ReadFile(request.HeaderPath)
		if err != nil {
			return identityverify.PlanEvidence{}, err
		}
		digest := sha256.Sum256(header)
		record, err := networkIdentityRecordForPlan(fixture.plan, header)
		if err != nil {
			return identityverify.PlanEvidence{}, err
		}
		envelope, err := networkidentity.Encode(record)
		if err != nil {
			return identityverify.PlanEvidence{}, err
		}
		envelopeDigest := sha256.Sum256(envelope)
		return identityverify.PlanEvidence{
			Schema: "drwa.s1.prototype-network-identity-migration.v2",
			Status: "DRY_VALIDATED_16_NODE_PLAN_BOUND_ABSENT_TARGET_NO_NODE_MUTATION",
			Mode:   "plan", ChainID: request.ChainID, CanonicalEpoch: request.Epoch,
			Provenance:    "PLANNED_EMERGENCY_MIGRATION_NOT_APPLIED",
			CanonicalHash: request.ExpectedCanonicalHash, NetworkDomain: request.ExpectedDomain,
			HeaderSHA256: hex.EncodeToString(digest[:]), HeaderLength: len(header),
			IdentitySchemaVersion: networkidentity.Version, StorageKeyHex: hex.EncodeToString(networkidentity.Key(request.Epoch)),
			EnvelopeSHA256: hex.EncodeToString(envelopeDigest[:]), EnvelopeLength: len(envelope),
			HeaderOutputPath: request.HeaderPath, BindingPath: request.BindingPath,
			BindingSHA256: request.ExpectedBindingSHA, TargetDBPath: request.TargetDBPath,
			NodeRoot: request.NodeRoot, ShardID: request.ShardID,
			TargetAbsentBefore: true, AuthoritativeRunCredit: 0,
		}, nil
	}
}

func newWriterFixture(t *testing.T, failingNodeID string) writerFixture {
	t.Helper()
	root := t.TempDir()
	archiveRoot := t.TempDir()
	qualificationRoot := filepath.Join(t.TempDir(), "qualification")
	artifacts := filepath.Join(root, "artifacts")
	require.NoError(t, os.MkdirAll(artifacts, 0o700))
	headerPath := filepath.Join(artifacts, "header.bin")
	metaHeader := &block.MetaBlock{
		Epoch: 0, ChainID: []byte("local-testnet"),
		RootHash: bytes32(1), ValidatorStatsRootHash: bytes32(33),
	}
	header, err := (&marshal.GogoProtoMarshalizer{}).Marshal(metaHeader)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(headerPath, header, 0o600))
	headerSHA := sha256.Sum256(header)

	canonicalHashBytes := coreBlake2b.NewBlake2b().Compute(string(header))
	var canonicalHash [32]byte
	copy(canonicalHash[:], canonicalHashBytes)
	domain, err := drwaprototype.DeriveNetworkDomain([]byte("local-testnet"), canonicalHash)
	require.NoError(t, err)
	bindingPath := filepath.Join(qualificationRoot, "runtime", "S1", "binding.json")
	transitionPlanPath := filepath.Join(qualificationRoot, "traces", "transition-plan.json")
	transitionTracePath := filepath.Join(qualificationRoot, "traces", "transition-trace.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(bindingPath), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Dir(transitionPlanPath), 0o700))
	bindingSHA := writeBytes(t, bindingPath, []byte("binding"), 0o600)
	transitionPlanSHA := writeBytes(t, transitionPlanPath, []byte("transition-plan"), 0o600)
	transitionTraceSHA := writeBytes(t, transitionTracePath, []byte("transition-trace"), 0o600)
	extractionPath := filepath.Join(artifacts, "extraction.json")
	checkpointPath := filepath.Join(artifacts, "checkpoint.json")
	candidatePath := filepath.Join(artifacts, "candidate")
	validatorPath := filepath.Join(artifacts, "validator.toml")
	observerPath := filepath.Join(artifacts, "observer.toml")
	extractionSHA := writeBytes(t, extractionPath, []byte("extraction"), 0o600)
	checkpointSHA := writeBytes(t, checkpointPath, []byte("checkpoint"), 0o600)
	candidateSHA := writeBytes(t, candidatePath, []byte("candidate"), 0o700)
	validatorSHA := writeBytes(t, validatorPath, []byte("validator"), 0o600)
	observerSHA := writeBytes(t, observerPath, []byte("observer"), 0o600)
	plan := migrationPlan{
		Schema: planSchema, Status: planStatus, CreatedUTC: "2026-08-25T00:00:00Z",
		ChainID: "local-testnet", CanonicalEpoch: 0,
		CanonicalHash: hex.EncodeToString(canonicalHash[:]), NetworkDomain: hex.EncodeToString(domain[:]),
		BindingPath: bindingPath, BindingSHA256: bindingSHA,
		ExtractionEvidencePath: extractionPath, ExtractionEvidenceSHA256: extractionSHA,
		TransitionPlanPath: transitionPlanPath, TransitionPlanSHA256: transitionPlanSHA,
		TransitionTracePath: transitionTracePath, TransitionTraceSHA256: transitionTraceSHA,
		MainConfigSHA256: strings.Repeat("7", 64), NodesSetupSHA256: strings.Repeat("8", 64),
		CheckpointManifestPath: checkpointPath, CheckpointManifestSHA256: checkpointSHA,
		CandidateBinaryPath: candidatePath, CandidateBinarySHA256: candidateSHA,
		ValidatorConfigPath: validatorPath, ValidatorConfigSHA256: validatorSHA,
		ObserverConfigPath: observerPath, ObserverConfigSHA256: observerSHA,
		HeaderPath: headerPath, HeaderSHA256: hex.EncodeToString(headerSHA[:]), RehearsalRoot: root,
	}
	for index := 0; index < 16; index++ {
		shard := []string{"0", "1", "2", "metachain"}[index%4]
		nodeRoot := filepath.Join(root, fmt.Sprintf("node-%02d", index))
		sourceRoot := filepath.Join(archiveRoot, fmt.Sprintf("node-%02d", index))
		target := filepath.Join(nodeRoot, "db", "local-testnet", "Static", "Shard_"+shard, "PrototypeNetworkIdentityStorageDB")
		require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o700))
		require.NoError(t, os.MkdirAll(sourceRoot, 0o700))
		info, err := os.Stat(nodeRoot)
		require.NoError(t, err)
		stat := info.Sys().(*syscall.Stat_t)
		sourceInfo, err := os.Stat(sourceRoot)
		require.NoError(t, err)
		sourceStat := sourceInfo.Sys().(*syscall.Stat_t)
		role := "validator"
		if index < 4 {
			role = "observer"
		}
		plan.Nodes = append(plan.Nodes, migrationPlanNode{
			ID: fmt.Sprintf("node-%02d", index), Role: role, ShardID: shard,
			SourceNodeRoot: sourceRoot, SourceRootDevice: uint64(sourceStat.Dev), SourceRootInode: sourceStat.Ino,
			NodeRoot: nodeRoot, NodeRootDevice: uint64(stat.Dev), NodeRootInode: stat.Ino, TargetDBPath: target,
		})
	}
	planPath := filepath.Join(artifacts, "migration-plan.json")
	planSHA := writeJSON(t, planPath, plan)
	toolPath := filepath.Join(artifacts, "identity-tool")
	record, err := networkIdentityRecordForPlan(plan, header)
	require.NoError(t, err)
	envelope, err := networkidentity.Encode(record)
	require.NoError(t, err)
	envelopeDigest := sha256.Sum256(envelope)
	tool := []byte(fmt.Sprintf(`#!/bin/sh
evidence=""
node_root=""
target=""
shard=""
while [ "$#" -gt 0 ]; do
  key="$1"
  shift
  case "$key" in
    --evidence) evidence="$1" ;;
    --node-root) node_root="$1" ;;
    --target-db) target="$1" ;;
    --shard-id) shard="$1" ;;
  esac
  shift
done
if [ %q != "" ] && [ "${node_root##*/}" = %q ]; then
  exit 23
fi
printf '{"schema":"drwa.s1.prototype-network-identity-migration.v2","status":"DRY_VALIDATED_16_NODE_PLAN_BOUND_ABSENT_TARGET_NO_NODE_MUTATION","mode":"plan","timestamp_utc":"2026-08-25T00:00:00Z","chain_id":"local-testnet","canonical_epoch":0,"provenance":"PLANNED_EMERGENCY_MIGRATION_NOT_APPLIED","canonical_metachain_genesis_hash":"%s","network_domain":"%s","header_sha256":"%s","header_length":%d,"identity_schema_version":2,"storage_key_hex":"%s","envelope_sha256":"%s","envelope_length":%d,"header_output_path":"%s","binding_path":"binding","binding_sha256":"%s","target_db_path":"%%s","node_root":"%%s","shard_id":"%%s","target_absent_before":true,"authoritative_runtime_credit":0}\n' "$target" "$node_root" "$shard" > "$evidence"
`, failingNodeID, failingNodeID, plan.CanonicalHash, plan.NetworkDomain, plan.HeaderSHA256, len(header), hex.EncodeToString(networkidentity.Key(plan.CanonicalEpoch)), hex.EncodeToString(envelopeDigest[:]), len(envelope), headerPath, plan.BindingSHA256))
	require.NoError(t, os.WriteFile(toolPath, tool, 0o700))
	toolSHA := sha256.Sum256(tool)
	selfPath, err := os.Executable()
	require.NoError(t, err)
	_, selfSHA, err := readExactRegular(selfPath, "")
	require.NoError(t, err)
	evidenceBindings := make([]evidenceBinding, 0, len(plan.Nodes))
	for _, node := range plan.Nodes {
		result := verifierEvidence{
			Schema: "drwa.s1.prototype-network-identity-migration.v2",
			Status: "DRY_VALIDATED_16_NODE_PLAN_BOUND_ABSENT_TARGET_NO_NODE_MUTATION", Mode: "plan",
			TimestampUTC: "2026-08-25T00:00:00Z", ChainID: plan.ChainID, CanonicalEpoch: plan.CanonicalEpoch,
			Provenance: "PLANNED_EMERGENCY_MIGRATION_NOT_APPLIED", CanonicalHash: plan.CanonicalHash,
			NetworkDomain: plan.NetworkDomain, HeaderSHA256: plan.HeaderSHA256, HeaderLength: len(header),
			IdentitySchemaVersion: networkidentity.Version, StorageKeyHex: hex.EncodeToString(networkidentity.Key(plan.CanonicalEpoch)),
			EnvelopeSHA256: hex.EncodeToString(envelopeDigest[:]), EnvelopeLength: len(envelope),
			HeaderOutputPath: plan.HeaderPath, BindingPath: plan.BindingPath, BindingSHA256: plan.BindingSHA256,
			TargetDBPath: node.TargetDBPath, NodeRoot: node.NodeRoot, ShardID: node.ShardID,
			TargetAbsentBefore: true, AuthoritativeRunCredit: 0,
		}
		if node.ID == failingNodeID {
			result.ShardID = "wrong"
		}
		path := filepath.Join(artifacts, "plan-"+node.ID+".json")
		digest := writeJSON(t, path, result)
		info, err := os.Stat(path)
		require.NoError(t, err)
		evidenceBindings = append(evidenceBindings, evidenceBinding{NodeID: node.ID, Path: path, SHA256: digest, Size: int(info.Size())})
	}
	contract := isolationContract{
		Schema: "drwa.s1.prototype-network-identity-isolation-contract.v1",
		Status: "AUDITED_DOCKER_NETWORK_NONE_REHEARSAL_ONLY", NetworkMode: "none",
		ContainerImageID:     "sha256:" + strings.Repeat("1", 64),
		ContainerImageDigest: "fixture@sha256:" + strings.Repeat("1", 64), ContainerPlatform: "linux/amd64",
		ContainerName: "writer-fixture", ContainerHostname: "writer-fixture",
		ContainerUserUID: os.Geteuid(), ContainerUserGID: os.Getegid(), ContainerPullPolicy: "never",
		ContainerPIDMode: "default-private", ContainerEntrypoint: filepath.Join(artifacts, "identity-rehearsal-writer-candidate"),
		ContainerMountSource: root, ContainerMountTarget: root, ContainerMountReadWrite: true,
		ReadOnlyContainerRoot: true, DroppedCapabilities: "ALL", NoNewPrivileges: true,
		RehearsalRoot: root, MigrationPlanPath: planPath, MigrationPlanSHA256: planSHA,
		IdentityToolPath: toolPath, IdentityToolSHA256: hex.EncodeToString(toolSHA[:]), WriterSHA256: selfSHA,
		EvidenceBindings:     evidenceBindings,
		SeccompProfilePath:   filepath.Join(artifacts, "writer-seccomp.json"),
		SeccompMountReadOnly: true,
		HostNetworkNamespace: "net:[host-fixture]",
		AuthoritativeCredit:  0,
	}
	for purpose, path := range map[string]string{
		"closed-checkpoint-archive": archiveRoot,
		"qualification-lineage":     qualificationRoot,
	} {
		info, statErr := os.Stat(path)
		require.NoError(t, statErr)
		stat := info.Sys().(*syscall.Stat_t)
		contract.ReadOnlyInputMounts = append(contract.ReadOnlyInputMounts, readOnlyInputMount{
			Purpose: purpose, Source: path, Target: path, ReadOnly: true,
			Device: uint64(stat.Dev), Inode: stat.Ino,
		})
	}
	contractPath := filepath.Join(artifacts, "writer-isolation-contract.json")
	contract.IsolationContractPath = contractPath
	contract.JournalPath = filepath.Join(artifacts, "writer-journal.jsonl")
	contract.SummaryPath = filepath.Join(artifacts, "writer-summary.json")
	contract.SeccompProfileSHA256 = writeJSON(t, contract.SeccompProfilePath, map[string]interface{}{
		"defaultAction": "SCMP_ACT_ALLOW",
		"architectures": []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"},
		"syscalls": []map[string]interface{}{{
			"names": []string{"bind", "connect"}, "action": "SCMP_ACT_ERRNO", "errnoRet": 1,
		}},
	})
	contractSHA := writeJSON(t, contractPath, contract)
	opts := options{
		planPath: planPath, expectedPlanSHA: planSHA,
		identityToolPath: toolPath, expectedIdentityToolSHA: hex.EncodeToString(toolSHA[:]),
		isolationContractPath: contractPath, expectedContractSHA: contractSHA,
		journalPath: contract.JournalPath,
		summaryPath: contract.SummaryPath,
	}
	return writerFixture{root: root, header: header, plan: plan, contract: contract, opts: opts}
}

func allowIsolation(isolationContract, migrationPlan) error {
	return nil
}

func bytes32(first byte) []byte {
	result := make([]byte, 32)
	for index := range result {
		result[index] = first + byte(index)
	}
	return result
}

func assertAllTargetsAbsent(t *testing.T, plan migrationPlan) {
	t.Helper()
	for _, node := range plan.Nodes {
		require.NoDirExists(t, node.TargetDBPath)
	}
}

func readJournal(t *testing.T, path string) []journalEvent {
	t.Helper()
	value, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(value)), "\n")
	events := make([]journalEvent, 0, len(lines))
	for _, line := range lines {
		var event journalEvent
		require.NoError(t, json.Unmarshal([]byte(line), &event))
		events = append(events, event)
	}
	return events
}

func writeJSON(t *testing.T, path string, value interface{}) string {
	t.Helper()
	encoded, err := json.MarshalIndent(value, "", "  ")
	require.NoError(t, err)
	encoded = append(encoded, '\n')
	require.NoError(t, os.WriteFile(path, encoded, 0o600))
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func writeBytes(t *testing.T, path string, value []byte, mode os.FileMode) string {
	t.Helper()
	require.NoError(t, os.WriteFile(path, value, mode))
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func readJSON(t *testing.T, path string, destination interface{}) {
	t.Helper()
	value, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(value, destination))
}
