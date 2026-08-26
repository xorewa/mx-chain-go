package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/multiversx/mx-chain-core-go/data/block"
	coreBlake2b "github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	identityverify "github.com/multiversx/mx-chain-go/cmd/internal/drwaprototypeidentityverify"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype/networkidentity"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"golang.org/x/sys/unix"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// REPLACED_BY_PART_B

const (
	planSchema = "drwa.s1.prototype-network-identity-migration-plan.v1"
	planStatus = "READY_OFFLINE_REHEARSAL_NO_LIVE_AUTHORIZATION"
)

type options struct {
	planPath                string
	expectedPlanSHA         string
	identityToolPath        string
	expectedIdentityToolSHA string
	isolationContractPath   string
	expectedContractSHA     string
	journalPath             string
	summaryPath             string
}

type migrationPlanNode struct {
	ID               string `json:"id"`
	Role             string `json:"role"`
	ShardID          string `json:"shard_id"`
	SourceNodeRoot   string `json:"source_node_root"`
	SourceRootDevice uint64 `json:"source_root_device"`
	SourceRootInode  uint64 `json:"source_root_inode"`
	NodeRoot         string `json:"node_root"`
	NodeRootDevice   uint64 `json:"node_root_device"`
	NodeRootInode    uint64 `json:"node_root_inode"`
	TargetDBPath     string `json:"target_db_path"`
}

type migrationPlan struct {
	Schema                   string              `json:"schema"`
	Status                   string              `json:"status"`
	CreatedUTC               string              `json:"created_utc"`
	ChainID                  string              `json:"chain_id"`
	CanonicalEpoch           uint32              `json:"canonical_epoch"`
	CanonicalHash            string              `json:"canonical_metachain_genesis_hash"`
	NetworkDomain            string              `json:"network_domain"`
	BindingPath              string              `json:"binding_path"`
	BindingSHA256            string              `json:"binding_sha256"`
	ExtractionEvidencePath   string              `json:"extraction_evidence_path"`
	ExtractionEvidenceSHA256 string              `json:"extraction_evidence_sha256"`
	TransitionPlanPath       string              `json:"transition_plan_path"`
	TransitionPlanSHA256     string              `json:"transition_plan_sha256"`
	TransitionTracePath      string              `json:"transition_trace_path"`
	TransitionTraceSHA256    string              `json:"transition_trace_sha256"`
	MainConfigSHA256         string              `json:"main_config_sha256"`
	NodesSetupSHA256         string              `json:"nodes_setup_sha256"`
	CheckpointManifestPath   string              `json:"checkpoint_manifest_path"`
	CheckpointManifestSHA256 string              `json:"checkpoint_manifest_sha256"`
	CandidateBinaryPath      string              `json:"candidate_binary_path"`
	CandidateBinarySHA256    string              `json:"candidate_binary_sha256"`
	ValidatorConfigPath      string              `json:"validator_config_path"`
	ValidatorConfigSHA256    string              `json:"validator_config_sha256"`
	ObserverConfigPath       string              `json:"observer_config_path"`
	ObserverConfigSHA256     string              `json:"observer_config_sha256"`
	HeaderPath               string              `json:"header_path"`
	HeaderSHA256             string              `json:"header_sha256"`
	RehearsalRoot            string              `json:"rehearsal_root"`
	Nodes                    []migrationPlanNode `json:"nodes"`
}

type isolationContract struct {
	Schema                  string               `json:"schema"`
	Status                  string               `json:"status"`
	ContainerImageID        string               `json:"container_image_id"`
	ContainerImageDigest    string               `json:"container_image_digest"`
	ContainerPlatform       string               `json:"container_platform"`
	ContainerName           string               `json:"container_name"`
	ContainerHostname       string               `json:"container_hostname"`
	ContainerUserUID        int                  `json:"container_user_uid"`
	ContainerUserGID        int                  `json:"container_user_gid"`
	ContainerPullPolicy     string               `json:"container_pull_policy"`
	ContainerAutoRemove     bool                 `json:"container_auto_remove"`
	ContainerPIDMode        string               `json:"container_pid_mode"`
	ContainerEntrypoint     string               `json:"container_entrypoint"`
	ContainerMountSource    string               `json:"container_mount_source"`
	ContainerMountTarget    string               `json:"container_mount_target"`
	ContainerMountReadWrite bool                 `json:"container_mount_read_write"`
	NetworkMode             string               `json:"network_mode"`
	ReadOnlyContainerRoot   bool                 `json:"read_only_container_root"`
	DroppedCapabilities     string               `json:"dropped_capabilities"`
	NoNewPrivileges         bool                 `json:"no_new_privileges"`
	RehearsalRoot           string               `json:"rehearsal_root"`
	MigrationPlanPath       string               `json:"migration_plan_path"`
	MigrationPlanSHA256     string               `json:"migration_plan_sha256"`
	IdentityToolPath        string               `json:"identity_tool_path"`
	IdentityToolSHA256      string               `json:"identity_tool_sha256"`
	EvidenceBindings        []evidenceBinding    `json:"evidence_bindings"`
	WriterSHA256            string               `json:"writer_sha256"`
	SeccompProfilePath      string               `json:"seccomp_profile_path"`
	SeccompProfileSHA256    string               `json:"seccomp_profile_sha256"`
	SeccompMountReadOnly    bool                 `json:"seccomp_mount_read_only"`
	ReadOnlyInputMounts     []readOnlyInputMount `json:"read_only_input_mounts"`
	IsolationContractPath   string               `json:"isolation_contract_path"`
	JournalPath             string               `json:"journal_path"`
	SummaryPath             string               `json:"summary_path"`
	HostNetworkNamespace    string               `json:"host_network_namespace"`
	AuthoritativeCredit     int                  `json:"authoritative_runtime_credit"`
}

type readOnlyInputMount struct {
	Purpose  string `json:"purpose"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
	Device   uint64 `json:"device"`
	Inode    uint64 `json:"inode"`
}

type evidenceBinding struct {
	NodeID string `json:"node_id"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

type journalEvent struct {
	Schema       string   `json:"schema"`
	Sequence     int      `json:"sequence"`
	TimestampUTC string   `json:"timestamp_utc"`
	Status       string   `json:"status"`
	NodeID       string   `json:"node_id,omitempty"`
	ShardID      string   `json:"shard_id,omitempty"`
	TargetDBPath string   `json:"target_db_path,omitempty"`
	PlanEvidence string   `json:"plan_evidence,omitempty"`
	EvidenceSHA  string   `json:"evidence_sha256,omitempty"`
	EvidenceSize int      `json:"evidence_size,omitempty"`
	EnvelopeSHA  string   `json:"envelope_sha256,omitempty"`
	Completed    []string `json:"completed_nodes,omitempty"`
	Detail       string   `json:"detail,omitempty"`
}

// sealedExecutable is retained only by hostile tests for the rejected executable-verifier design.
// The writer has no production call site that executes an external verifier.
type sealedExecutable struct {
	file           *os.File
	original       *os.File
	sha            string
	script         bool
	originalDevice uint64
	originalInode  uint64
	originalSize   int64
	originalMode   os.FileMode
	snapshotDevice uint64
	snapshotInode  uint64
	snapshotSize   int64
	snapshotMode   os.FileMode
	snapshotSeals  int
}

type outputDirectory struct {
	file *os.File
	path string
}

type nodeWriter func(migrationPlanNode, migrationPlan, []byte, []byte) error

type planBoundaryVerifier func(identityverify.PlanRequest) (identityverify.PlanEvidence, error)

type summary struct {
	Schema                     string   `json:"schema"`
	Status                     string   `json:"status"`
	TimestampUTC               string   `json:"timestamp_utc"`
	PlanPath                   string   `json:"plan_path"`
	PlanSHA256                 string   `json:"plan_sha256"`
	IdentityToolPath           string   `json:"identity_tool_path"`
	IdentityToolSHA256         string   `json:"identity_tool_sha256"`
	IsolationContractPath      string   `json:"isolation_contract_path"`
	IsolationContractSHA256    string   `json:"isolation_contract_sha256"`
	JournalPath                string   `json:"journal_path"`
	JournalSHA256              string   `json:"journal_sha256"`
	CanonicalMetachainHash     string   `json:"canonical_metachain_genesis_hash"`
	NetworkDomain              string   `json:"network_domain"`
	Provenance                 string   `json:"provenance"`
	CompletedNodes             []string `json:"completed_nodes"`
	DurableCloseReopenVerified bool     `json:"durable_close_reopen_verified"`
	AuthoritativeRuntimeCredit int      `json:"authoritative_runtime_credit"`
}

type verifierEvidence struct {
	Schema                 string `json:"schema"`
	Status                 string `json:"status"`
	Mode                   string `json:"mode"`
	TimestampUTC           string `json:"timestamp_utc"`
	ChainID                string `json:"chain_id"`
	CanonicalEpoch         uint32 `json:"canonical_epoch"`
	Provenance             string `json:"provenance"`
	CanonicalHash          string `json:"canonical_metachain_genesis_hash"`
	NetworkDomain          string `json:"network_domain"`
	HeaderSHA256           string `json:"header_sha256"`
	HeaderLength           int    `json:"header_length"`
	IdentitySchemaVersion  byte   `json:"identity_schema_version"`
	StorageKeyHex          string `json:"storage_key_hex"`
	EnvelopeSHA256         string `json:"envelope_sha256"`
	EnvelopeLength         int    `json:"envelope_length"`
	HeaderOutputPath       string `json:"header_output_path"`
	BindingPath            string `json:"binding_path"`
	BindingSHA256          string `json:"binding_sha256"`
	TargetDBPath           string `json:"target_db_path"`
	NodeRoot               string `json:"node_root"`
	ShardID                string `json:"shard_id"`
	TargetAbsentBefore     bool   `json:"target_absent_before"`
	AuthoritativeRunCredit int    `json:"authoritative_runtime_credit"`
}

func main() {
	opts := options{}
	flag.StringVar(&opts.planPath, "plan", "", "exact verified 16-node rehearsal plan")
	flag.StringVar(&opts.expectedPlanSHA, "expected-plan-sha", "", "exact plan SHA-256")
	flag.StringVar(&opts.identityToolPath, "identity-tool", "", "hash-bound read-only identity verifier")
	flag.StringVar(&opts.expectedIdentityToolSHA, "expected-identity-tool-sha", "", "exact verifier SHA-256")
	flag.StringVar(&opts.isolationContractPath, "isolation-contract", "", "hash-bound Docker isolation contract")
	flag.StringVar(&opts.expectedContractSHA, "expected-isolation-contract-sha", "", "exact isolation-contract SHA-256")
	flag.StringVar(&opts.journalPath, "journal", "", "O_EXCL append-only mutation journal")
	flag.StringVar(&opts.summaryPath, "summary", "", "O_EXCL final rehearsal summary")
	flag.Parse()
	if err := run(opts); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(opts options) error {
	return runWithBoundary(opts, os.Getpid(), requireRuntimeIsolation)
}

func runWithBoundary(opts options, processID int, isolationCheck func(isolationContract, migrationPlan) error) (runErr error) {
	return runWithBoundaryAndWriterAndVerifier(
		opts, processID, isolationCheck, writeAndReopen, identityverify.VerifyPlanBoundary,
	)
}

func runWithBoundaryAndWriter(
	opts options,
	processID int,
	isolationCheck func(isolationContract, migrationPlan) error,
	writer nodeWriter,
) (runErr error) {
	return runWithBoundaryAndWriterAndVerifier(
		opts, processID, isolationCheck, writer, identityverify.VerifyPlanBoundary,
	)
}

func runWithBoundaryAndWriterAndVerifier(
	opts options,
	processID int,
	isolationCheck func(isolationContract, migrationPlan) error,
	writer nodeWriter,
	boundaryVerifier planBoundaryVerifier,
) (runErr error) {
	if processID != 1 {
		return errors.New("rehearsal writer must be container PID 1")
	}
	if opts.planPath == "" || opts.identityToolPath == "" || opts.isolationContractPath == "" || opts.journalPath == "" || opts.summaryPath == "" {
		return errors.New("all plan/tool/contract/journal/summary paths are required")
	}
	for name, digest := range map[string]string{
		"expected plan SHA-256":               opts.expectedPlanSHA,
		"expected identity-tool SHA-256":      opts.expectedIdentityToolSHA,
		"expected isolation-contract SHA-256": opts.expectedContractSHA,
	} {
		if _, decodeErr := decodeHex32(digest); decodeErr != nil {
			return fmt.Errorf("%s is required and must be canonical: %w", name, decodeErr)
		}
	}
	planBytes, planSHA, err := readExactRegular(opts.planPath, opts.expectedPlanSHA)
	if err != nil {
		return fmt.Errorf("migration plan: %w", err)
	}
	var plan migrationPlan
	if err = strictDecode(planBytes, &plan); err != nil {
		return fmt.Errorf("decode migration plan: %w", err)
	}
	if err = validatePlan(plan); err != nil {
		return err
	}
	if filepath.Clean(opts.journalPath) == filepath.Clean(opts.summaryPath) {
		return errors.New("journal and summary paths must differ")
	}
	_, toolSHA, err := readExactRegular(opts.identityToolPath, opts.expectedIdentityToolSHA)
	if err != nil {
		return fmt.Errorf("bind identity verifier provenance: %w", err)
	}
	contractBytes, contractSHA, err := readExactRegular(opts.isolationContractPath, opts.expectedContractSHA)
	if err != nil {
		return fmt.Errorf("isolation contract: %w", err)
	}
	var contract isolationContract
	if err = strictDecode(contractBytes, &contract); err != nil {
		return fmt.Errorf("decode isolation contract: %w", err)
	}
	selfSHA, err := hashLoadedExecutable()
	if err != nil {
		return err
	}
	if err = validateIsolationContract(contract, plan, opts, planSHA, toolSHA, selfSHA); err != nil {
		return err
	}
	if err = validateSeccompProfile(contract.SeccompProfilePath, contract.SeccompProfileSHA256); err != nil {
		return err
	}
	if err = isolationCheck(contract, plan); err != nil {
		return fmt.Errorf("runtime isolation boundary: %w", err)
	}

	outputDir, err := openOutputDirectory(plan.RehearsalRoot, opts.journalPath, opts.summaryPath)
	if err != nil {
		return err
	}
	defer outputDir.Close()
	journal, err := outputDir.openExclusive(filepath.Base(opts.journalPath), 0o600)
	if err != nil {
		return fmt.Errorf("reserve journal: %w", err)
	}
	defer journal.Close()
	sequence := 0
	appendEvent := func(event journalEvent) error {
		sequence++
		event.Schema = "drwa.s1.prototype-network-identity-rehearsal-journal.v1"
		event.Sequence = sequence
		event.TimestampUTC = time.Now().UTC().Format(time.RFC3339Nano)
		encoded, marshalErr := json.Marshal(event)
		if marshalErr != nil {
			return marshalErr
		}
		if _, writeErr := journal.Write(append(encoded, '\n')); writeErr != nil {
			return writeErr
		}
		return journal.Sync()
	}
	if err = appendEvent(journalEvent{Status: "ATTEMPT_RESERVED_NO_NODE_WRITTEN"}); err != nil {
		return err
	}
	completed := make([]string, 0, 16)
	failureNode := ""
	failurePhase := "RESERVE_SUMMARY"
	defer func() {
		if runErr != nil {
			_ = appendEvent(journalEvent{
				Status: "ATTEMPT_FAILED_NO_RETRY", NodeID: failureNode,
				Completed: append([]string(nil), completed...), Detail: failurePhase + ": " + runErr.Error(),
			})
		}
	}()
	summaryFile, err := outputDir.openExclusive(filepath.Base(opts.summaryPath), 0o600)
	if err != nil {
		return fmt.Errorf("reserve summary: %w", err)
	}
	defer summaryFile.Close()

	nodes := append([]migrationPlanNode(nil), plan.Nodes...)
	sort.Slice(nodes, func(left, right int) bool { return nodes[left].ID < nodes[right].ID })
	failurePhase = "ALL_TARGETS_ABSENT"
	for _, node := range nodes {
		if _, err = os.Lstat(node.TargetDBPath); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				return fmt.Errorf("target already exists before all-node preflight: %s", node.TargetDBPath)
			}
			return err
		}
	}
	evidenceBindings, err := validateEvidenceBindings(contract, plan)
	if err != nil {
		return err
	}
	for _, node := range nodes {
		failureNode = node.ID
		failurePhase = "MUTATION_BOUNDARY_REVALIDATION"
		binding := evidenceBindings[node.ID]
		evidenceSHA, evidenceSize, verifierErr := validateBoundVerifierEvidence(binding, plan, node)
		if verifierErr != nil {
			err = verifierErr
			return fmt.Errorf("mutation-boundary revalidation %s: %w", node.ID, err)
		}
		current, verifierErr := boundaryVerifier(identityverify.PlanRequest{
			ChainID: plan.ChainID, Epoch: plan.CanonicalEpoch,
			ExpectedCanonicalHash: plan.CanonicalHash, ExpectedDomain: plan.NetworkDomain,
			BindingPath: plan.BindingPath, ExpectedBindingSHA: plan.BindingSHA256,
			HeaderPath: plan.HeaderPath, TargetDBPath: node.TargetDBPath, NodeRoot: node.NodeRoot, ShardID: node.ShardID,
			MigrationPlanPath: opts.planPath, ExpectedMigrationPlanSHA: planSHA,
			ExtractionEvidencePath:        plan.ExtractionEvidencePath,
			ExpectedExtractionEvidenceSHA: plan.ExtractionEvidenceSHA256,
			RehearsalRoot:                 plan.RehearsalRoot,
		})
		if verifierErr != nil {
			return fmt.Errorf("in-process mutation-boundary verification %s: %w", node.ID, verifierErr)
		}
		if verifierErr = compareCurrentAndBoundEvidence(current, plan, node); verifierErr != nil {
			return fmt.Errorf("current/bound verifier divergence %s: %w", node.ID, verifierErr)
		}
		if err = appendEvent(journalEvent{
			Status: "NODE_REVALIDATED_TARGET_ABSENT", NodeID: node.ID, ShardID: node.ShardID,
			TargetDBPath: node.TargetDBPath, PlanEvidence: binding.Path,
			EvidenceSHA: evidenceSHA, EvidenceSize: evidenceSize,
		}); err != nil {
			return err
		}
	}
	failureNode = ""
	failurePhase = "ALL_SIXTEEN_REVALIDATED_JOURNAL"
	if err = appendEvent(journalEvent{Status: "ALL_SIXTEEN_REVALIDATED_BEFORE_FIRST_WRITE"}); err != nil {
		return err
	}

	headerBytes, _, err := readExactRegular(plan.HeaderPath, plan.HeaderSHA256)
	if err != nil {
		return err
	}
	if err = verifyCanonicalHeader(plan, headerBytes); err != nil {
		return err
	}
	identityRecord, err := networkIdentityRecordForPlan(plan, headerBytes)
	if err != nil {
		return err
	}
	envelope, err := networkidentity.Encode(identityRecord)
	if err != nil {
		return err
	}
	envelopeDigest := sha256.Sum256(envelope)
	envelopeSHA := hex.EncodeToString(envelopeDigest[:])
	for _, node := range nodes {
		failureNode = node.ID
		failurePhase = "NODE_WRITE_RESERVATION"
		if err = appendEvent(journalEvent{Status: "NODE_WRITE_RESERVED", NodeID: node.ID, ShardID: node.ShardID, TargetDBPath: node.TargetDBPath, EnvelopeSHA: envelopeSHA}); err != nil {
			return err
		}
		failurePhase = "NODE_SYNCHRONOUS_WRITE_CLOSE_REOPEN"
		if err = writer(node, plan, envelope, headerBytes); err != nil {
			return fmt.Errorf("node %s: %w", node.ID, err)
		}
		completed = append(completed, node.ID)
		if err = appendEvent(journalEvent{Status: "NODE_DURABLE_CLOSE_REOPEN_VERIFIED", NodeID: node.ID, ShardID: node.ShardID, TargetDBPath: node.TargetDBPath, EnvelopeSHA: envelopeSHA}); err != nil {
			return err
		}
	}
	if len(completed) != 16 {
		return fmt.Errorf("completed %d nodes, expected 16", len(completed))
	}
	failureNode = ""
	failurePhase = "FINAL_JOURNAL_AND_SUMMARY"
	if err = appendEvent(journalEvent{Status: "ALL_SIXTEEN_DURABLE_NO_NODE_LAUNCHED"}); err != nil {
		return err
	}
	if err = reconcileJournalEvidenceBindings(opts.journalPath); err != nil {
		return fmt.Errorf("reconcile mutation-boundary evidence bindings: %w", err)
	}
	if err = appendEvent(journalEvent{Status: "ALL_SIXTEEN_EVIDENCE_BINDINGS_RECONCILED"}); err != nil {
		return err
	}
	if err = journal.Sync(); err != nil {
		return err
	}
	journalSHA, err := hashOpenFile(journal)
	if err != nil {
		return err
	}
	result := summary{
		Schema:       "drwa.s1.prototype-network-identity-offline-rehearsal.v1",
		Status:       "ALL_SIXTEEN_EMERGENCY_IDENTITIES_DURABLE_NO_NODE_LAUNCHED_NO_RUNTIME_CREDIT",
		TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano),
		PlanPath:     opts.planPath, PlanSHA256: planSHA,
		IdentityToolPath: opts.identityToolPath, IdentityToolSHA256: toolSHA,
		IsolationContractPath: opts.isolationContractPath, IsolationContractSHA256: contractSHA,
		JournalPath: opts.journalPath, JournalSHA256: journalSHA,
		CanonicalMetachainHash: plan.CanonicalHash, NetworkDomain: plan.NetworkDomain,
		Provenance: networkidentity.EmergencyMigration.String(), CompletedNodes: completed,
		DurableCloseReopenVerified: true, AuthoritativeRuntimeCredit: 0,
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	if _, err = summaryFile.Write(append(encoded, '\n')); err != nil {
		return err
	}
	if err = summaryFile.Sync(); err != nil {
		return err
	}
	if err = summaryFile.Close(); err != nil {
		return err
	}
	return nil
}

func compareCurrentAndBoundEvidence(current identityverify.PlanEvidence, plan migrationPlan, node migrationPlanNode) error {
	headerBytes, _, err := readExactRegular(plan.HeaderPath, plan.HeaderSHA256)
	if err != nil {
		return fmt.Errorf("re-read exact header for verifier comparison: %w", err)
	}
	expectedRecord, err := networkIdentityRecordForPlan(plan, headerBytes)
	if err != nil {
		return err
	}
	expectedEnvelope, err := networkidentity.Encode(expectedRecord)
	if err != nil {
		return fmt.Errorf("encode expected verifier envelope: %w", err)
	}
	expectedEnvelopeSHA := sha256.Sum256(expectedEnvelope)
	if current.Schema != "drwa.s1.prototype-network-identity-migration.v2" ||
		current.Status != "DRY_VALIDATED_16_NODE_PLAN_BOUND_ABSENT_TARGET_NO_NODE_MUTATION" || current.Mode != "plan" ||
		current.ChainID != plan.ChainID || current.CanonicalEpoch != plan.CanonicalEpoch ||
		current.Provenance != "PLANNED_EMERGENCY_MIGRATION_NOT_APPLIED" || current.CanonicalHash != plan.CanonicalHash ||
		current.NetworkDomain != plan.NetworkDomain || current.HeaderSHA256 != plan.HeaderSHA256 || current.HeaderLength <= 0 ||
		current.IdentitySchemaVersion != networkidentity.Version ||
		current.StorageKeyHex != hex.EncodeToString(networkidentity.Key(plan.CanonicalEpoch)) ||
		current.EnvelopeSHA256 != hex.EncodeToString(expectedEnvelopeSHA[:]) || current.EnvelopeLength != len(expectedEnvelope) ||
		current.HeaderOutputPath != plan.HeaderPath || current.BindingPath != plan.BindingPath || current.BindingSHA256 != plan.BindingSHA256 ||
		current.TargetDBPath != node.TargetDBPath || current.NodeRoot != node.NodeRoot || current.ShardID != node.ShardID ||
		!current.TargetAbsentBefore || current.AuthoritativeRunCredit != 0 {
		return errors.New("in-process verifier result differs from exact plan/no-mutation contract")
	}
	return nil
}

func validatePlan(plan migrationPlan) error {
	if plan.Schema != planSchema || plan.Status != planStatus || plan.ChainID == "" || plan.RehearsalRoot == "" || len(plan.Nodes) != 16 {
		return errors.New("migration plan schema/status/identity/count mismatch")
	}
	if _, err := time.Parse(time.RFC3339Nano, plan.CreatedUTC); err != nil {
		return errors.New("migration plan timestamp is not canonical RFC3339")
	}
	if !filepath.IsAbs(plan.RehearsalRoot) {
		return errors.New("rehearsal root must be absolute")
	}
	canonicalRoot, err := canonicalNoSymlinkExisting(plan.RehearsalRoot)
	if err != nil || canonicalRoot != filepath.Clean(plan.RehearsalRoot) {
		return fmt.Errorf("rehearsal root is not canonical/no-symlink: %w", err)
	}
	canonicalHashBytes, err := decodeHex32(plan.CanonicalHash)
	if err != nil {
		return fmt.Errorf("canonical metachain hash: %w", err)
	}
	domainHasher := sha256.New()
	_, _ = domainHasher.Write([]byte("DRWA/NETWORK/v1"))
	_, _ = domainHasher.Write([]byte(plan.ChainID))
	_, _ = domainHasher.Write(canonicalHashBytes)
	if hex.EncodeToString(domainHasher.Sum(nil)) != plan.NetworkDomain {
		return errors.New("network domain does not match canonical metachain hash and chain ID")
	}
	for name, value := range map[string]string{
		"binding": plan.BindingSHA256, "extraction evidence": plan.ExtractionEvidenceSHA256,
		"transition plan": plan.TransitionPlanSHA256, "transition trace": plan.TransitionTraceSHA256,
		"main config": plan.MainConfigSHA256, "nodes setup": plan.NodesSetupSHA256,
		"checkpoint manifest": plan.CheckpointManifestSHA256, "candidate binary": plan.CandidateBinarySHA256,
		"validator config": plan.ValidatorConfigSHA256, "observer config": plan.ObserverConfigSHA256,
		"header": plan.HeaderSHA256,
	} {
		if _, decodeErr := decodeHex32(value); decodeErr != nil {
			return fmt.Errorf("%s SHA-256: %w", name, decodeErr)
		}
	}
	seen := make(map[string]struct{})
	rootIdentities := make(map[string]string)
	sourceIdentities := make(map[string]string)
	allIdentities := make(map[string]string)
	shardCounts := make(map[string]int)
	observerCounts := make(map[string]int)
	validatorCount := 0
	for _, node := range plan.Nodes {
		if !identityverify.IsSafeArtifactComponent(node.ID) || (node.Role != "observer" && node.Role != "validator") || !supportedShard(node.ShardID) ||
			node.SourceRootDevice == 0 || node.SourceRootInode == 0 || node.NodeRootDevice == 0 || node.NodeRootInode == 0 ||
			node.SourceNodeRoot == "" || node.NodeRoot == "" || node.TargetDBPath == "" || !pathWithin(plan.RehearsalRoot, node.NodeRoot) || !pathWithin(node.NodeRoot, node.TargetDBPath) {
			return fmt.Errorf("node %q is outside rehearsal boundary", node.ID)
		}
		if _, duplicate := seen[node.ID]; duplicate {
			return fmt.Errorf("duplicate node %s", node.ID)
		}
		canonicalNodeRoot, canonicalErr := canonicalNoSymlinkExisting(node.NodeRoot)
		if canonicalErr != nil || canonicalNodeRoot != filepath.Clean(node.NodeRoot) {
			return fmt.Errorf("node %s destination root is not canonical/no-symlink: %w", node.ID, canonicalErr)
		}
		canonicalSourceRoot, canonicalErr := canonicalNoSymlinkExisting(node.SourceNodeRoot)
		if canonicalErr != nil || canonicalSourceRoot != filepath.Clean(node.SourceNodeRoot) {
			return fmt.Errorf("node %s source root is not canonical/no-symlink: %w", node.ID, canonicalErr)
		}
		expectedTarget := filepath.Join(node.NodeRoot, "db", plan.ChainID, "Static", "Shard_"+node.ShardID, "PrototypeNetworkIdentityStorageDB")
		if filepath.Clean(node.TargetDBPath) != expectedTarget {
			return fmt.Errorf("node %s target is not the exact identity-store path", node.ID)
		}
		rootIdentity := fmt.Sprintf("%d:%d", node.NodeRootDevice, node.NodeRootInode)
		sourceIdentity := fmt.Sprintf("%d:%d", node.SourceRootDevice, node.SourceRootInode)
		if previous, duplicate := rootIdentities[rootIdentity]; duplicate {
			return fmt.Errorf("destination roots %s and %s alias filesystem identity %s", previous, node.ID, rootIdentity)
		}
		if previous, duplicate := sourceIdentities[sourceIdentity]; duplicate {
			return fmt.Errorf("source roots %s and %s alias filesystem identity %s", previous, node.ID, sourceIdentity)
		}
		if previous, duplicate := allIdentities[rootIdentity]; duplicate {
			return fmt.Errorf("destination root %s aliases %s at filesystem identity %s", node.ID, previous, rootIdentity)
		}
		allIdentities[rootIdentity] = "destination " + node.ID
		if previous, duplicate := allIdentities[sourceIdentity]; duplicate {
			return fmt.Errorf("source root %s aliases %s at filesystem identity %s", node.ID, previous, sourceIdentity)
		}
		allIdentities[sourceIdentity] = "source " + node.ID
		rootIdentities[rootIdentity] = node.ID
		sourceIdentities[sourceIdentity] = node.ID
		shardCounts[node.ShardID]++
		if node.Role == "observer" {
			observerCounts[node.ShardID]++
		} else {
			validatorCount++
		}
		seen[node.ID] = struct{}{}
	}
	for _, shardID := range []string{"0", "1", "2", "metachain"} {
		if shardCounts[shardID] != 4 || observerCounts[shardID] != 1 {
			return fmt.Errorf("shard %s requires four nodes including exactly one observer", shardID)
		}
	}
	if validatorCount != 12 {
		return fmt.Errorf("migration plan requires 12 validators, found %d", validatorCount)
	}
	return nil
}

func validateIsolationContract(contract isolationContract, plan migrationPlan, opts options, planSHA, toolSHA, selfSHA string) error {
	expectedArtifacts := filepath.Join(plan.RehearsalRoot, "artifacts")
	expectedPlan := filepath.Join(expectedArtifacts, "migration-plan.json")
	expectedTool := filepath.Join(expectedArtifacts, "identity-tool")
	expectedEntrypoint := filepath.Join(expectedArtifacts, "identity-rehearsal-writer-candidate")
	expectedContract := filepath.Join(expectedArtifacts, "writer-isolation-contract.json")
	expectedJournal := filepath.Join(expectedArtifacts, "writer-journal.jsonl")
	expectedSummary := filepath.Join(expectedArtifacts, "writer-summary.json")
	if contract.Schema != "drwa.s1.prototype-network-identity-isolation-contract.v1" ||
		contract.Status != "AUDITED_DOCKER_NETWORK_NONE_REHEARSAL_ONLY" ||
		validateContainerImageIdentity(contract.ContainerImageID, contract.ContainerImageDigest) != nil ||
		contract.ContainerPlatform != "linux/amd64" || !identityverify.IsSafeArtifactComponent(contract.ContainerName) ||
		contract.ContainerHostname != contract.ContainerName || contract.ContainerUserUID <= 0 || contract.ContainerUserGID <= 0 ||
		contract.ContainerPullPolicy != "never" || contract.ContainerAutoRemove || contract.ContainerPIDMode != "default-private" ||
		contract.ContainerEntrypoint != expectedEntrypoint || contract.ContainerMountSource != plan.RehearsalRoot ||
		contract.ContainerMountTarget != plan.RehearsalRoot || !contract.ContainerMountReadWrite ||
		contract.NetworkMode != "none" || !contract.ReadOnlyContainerRoot ||
		contract.DroppedCapabilities != "ALL" || !contract.NoNewPrivileges ||
		contract.RehearsalRoot != plan.RehearsalRoot || contract.MigrationPlanPath != expectedPlan || opts.planPath != expectedPlan ||
		contract.MigrationPlanSHA256 != planSHA || contract.IdentityToolPath != expectedTool || opts.identityToolPath != expectedTool ||
		contract.IdentityToolSHA256 != toolSHA || contract.WriterSHA256 != selfSHA || !contract.SeccompMountReadOnly ||
		contract.IsolationContractPath != expectedContract || opts.isolationContractPath != expectedContract ||
		contract.JournalPath != expectedJournal || opts.journalPath != expectedJournal ||
		contract.SummaryPath != expectedSummary || opts.summaryPath != expectedSummary ||
		contract.HostNetworkNamespace == "" || contract.AuthoritativeCredit != 0 {
		return errors.New("isolation contract differs from executable plan or required Docker boundary")
	}
	if _, err := decodeHex32(contract.SeccompProfileSHA256); err != nil || contract.SeccompProfilePath == "" {
		return errors.New("isolation contract seccomp profile identity is invalid")
	}
	if err := validateReadOnlyInputMounts(contract, plan); err != nil {
		return err
	}
	return nil
}

func validateReadOnlyInputMounts(contract isolationContract, plan migrationPlan) error {
	archiveRoot, qualificationRoot, err := deriveRequiredReadOnlyRoots(plan)
	if err != nil {
		return err
	}
	expected := map[string]string{
		"closed-checkpoint-archive": archiveRoot,
		"qualification-lineage":     qualificationRoot,
	}
	if len(contract.ReadOnlyInputMounts) != len(expected) {
		return fmt.Errorf("isolation contract binds %d read-only input mounts, expected %d", len(contract.ReadOnlyInputMounts), len(expected))
	}
	seen := make(map[string]struct{}, len(expected))
	for _, mount := range contract.ReadOnlyInputMounts {
		expectedPath, exists := expected[mount.Purpose]
		if !exists {
			return fmt.Errorf("unknown read-only input mount purpose %q", mount.Purpose)
		}
		if _, duplicate := seen[mount.Purpose]; duplicate {
			return fmt.Errorf("duplicate read-only input mount purpose %q", mount.Purpose)
		}
		canonical, canonicalErr := canonicalNoSymlinkExisting(mount.Source)
		if canonicalErr != nil || canonical != expectedPath || mount.Source != expectedPath || mount.Target != expectedPath || !mount.ReadOnly {
			return fmt.Errorf("read-only input mount %s differs from exact same-path boundary", mount.Purpose)
		}
		info, statErr := os.Stat(canonical)
		if statErr != nil || !info.IsDir() {
			return fmt.Errorf("read-only input mount %s is not a directory", mount.Purpose)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || mount.Device != uint64(stat.Dev) || mount.Inode != stat.Ino || mount.Device == 0 || mount.Inode == 0 {
			return fmt.Errorf("read-only input mount %s filesystem identity mismatch", mount.Purpose)
		}
		seen[mount.Purpose] = struct{}{}
	}
	return nil
}

func deriveRequiredReadOnlyRoots(plan migrationPlan) (string, string, error) {
	if len(plan.Nodes) != 16 {
		return "", "", errors.New("read-only input derivation requires 16 plan nodes")
	}
	archiveRoot := filepath.Dir(filepath.Clean(plan.Nodes[0].SourceNodeRoot))
	for _, node := range plan.Nodes {
		if filepath.Dir(filepath.Clean(node.SourceNodeRoot)) != archiveRoot {
			return "", "", errors.New("all source node roots must be direct children of one closed archive root")
		}
	}
	qualificationRoot, err := deriveQualificationRoot(plan)
	if err != nil {
		return "", "", err
	}
	artifactsRoot := filepath.Join(plan.RehearsalRoot, "artifacts")
	for name, path := range map[string]string{
		"extraction evidence": plan.ExtractionEvidencePath,
		"checkpoint manifest": plan.CheckpointManifestPath,
		"candidate binary":    plan.CandidateBinaryPath,
		"validator config":    plan.ValidatorConfigPath,
		"observer config":     plan.ObserverConfigPath,
		"canonical header":    plan.HeaderPath,
	} {
		if filepath.Dir(filepath.Clean(path)) != artifactsRoot {
			return "", "", fmt.Errorf("%s is not a direct rehearsal artifacts child", name)
		}
	}
	for _, root := range []string{archiveRoot, qualificationRoot} {
		if !filepath.IsAbs(root) || root == string(os.PathSeparator) || pathsOverlap(root, plan.RehearsalRoot) {
			return "", "", errors.New("read-only input root is broad or overlaps the rehearsal root")
		}
	}
	if pathsOverlap(archiveRoot, qualificationRoot) {
		return "", "", errors.New("read-only input roots overlap")
	}
	return archiveRoot, qualificationRoot, nil
}

func deriveQualificationRoot(plan migrationPlan) (string, error) {
	bindingPath := filepath.Clean(plan.BindingPath)
	transitionPlanPath := filepath.Clean(plan.TransitionPlanPath)
	transitionTracePath := filepath.Clean(plan.TransitionTracePath)
	for _, path := range []string{bindingPath, transitionPlanPath, transitionTracePath} {
		if !filepath.IsAbs(path) {
			return "", errors.New("qualification lineage path is not absolute")
		}
	}

	bindingDirectory := filepath.Dir(bindingPath)
	qualificationRoot := filepath.Dir(filepath.Dir(bindingDirectory))
	if filepath.Base(qualificationRoot) != "qualification" ||
		bindingDirectory != filepath.Join(qualificationRoot, "runtime", "S1") ||
		filepath.Dir(transitionPlanPath) != filepath.Join(qualificationRoot, "traces") ||
		filepath.Dir(transitionTracePath) != filepath.Join(qualificationRoot, "traces") {
		return "", errors.New("qualification lineage paths do not match the exact qualification/runtime/S1 and qualification/traces topology")
	}
	return qualificationRoot, nil
}

func pathsOverlap(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	return left == right || pathWithin(left, right) || pathWithin(right, left)
}

func validateContainerImageIdentity(imageID, imageDigest string) error {
	const prefix = "sha256:"
	if !strings.HasPrefix(imageID, prefix) {
		return errors.New("container image ID is not a canonical SHA-256 identity")
	}
	digest := strings.TrimPrefix(imageID, prefix)
	if _, err := decodeHex32(digest); err != nil {
		return err
	}
	separator := strings.LastIndex(imageDigest, "@sha256:")
	if separator <= 0 || imageDigest[separator+len("@sha256:"):] != digest {
		return errors.New("container image repository digest differs from image ID")
	}
	return nil
}

func validateSeccompProfile(path, expectedSHA string) error {
	value, _, err := readExactRegular(path, expectedSHA)
	if err != nil {
		return fmt.Errorf("read writer seccomp profile: %w", err)
	}
	var profile struct {
		DefaultAction string   `json:"defaultAction"`
		Architectures []string `json:"architectures"`
		Syscalls      []struct {
			Names    []string `json:"names"`
			Action   string   `json:"action"`
			ErrnoRet int      `json:"errnoRet"`
		} `json:"syscalls"`
	}
	if err = strictDecode(value, &profile); err != nil {
		return fmt.Errorf("decode writer seccomp profile: %w", err)
	}
	if profile.DefaultAction != "SCMP_ACT_ALLOW" ||
		len(profile.Architectures) != 3 || profile.Architectures[0] != "SCMP_ARCH_X86_64" ||
		profile.Architectures[1] != "SCMP_ARCH_X86" || profile.Architectures[2] != "SCMP_ARCH_X32" ||
		len(profile.Syscalls) != 1 || len(profile.Syscalls[0].Names) != 2 ||
		profile.Syscalls[0].Names[0] != "bind" || profile.Syscalls[0].Names[1] != "connect" ||
		profile.Syscalls[0].Action != "SCMP_ACT_ERRNO" || profile.Syscalls[0].ErrnoRet != 1 {
		return errors.New("writer seccomp profile differs from the exact bind/connect-denial policy")
	}
	return nil
}

func validateEvidenceBindings(contract isolationContract, plan migrationPlan) (map[string]evidenceBinding, error) {
	if len(contract.EvidenceBindings) != 16 {
		return nil, fmt.Errorf("isolation contract binds %d verifier records, expected 16", len(contract.EvidenceBindings))
	}
	planNodes := make(map[string]migrationPlanNode, len(plan.Nodes))
	for _, node := range plan.Nodes {
		planNodes[node.ID] = node
	}
	result := make(map[string]evidenceBinding, 16)
	for _, binding := range contract.EvidenceBindings {
		if _, exists := result[binding.NodeID]; exists {
			return nil, fmt.Errorf("duplicate verifier evidence binding for %s", binding.NodeID)
		}
		if _, exists := planNodes[binding.NodeID]; !exists || binding.Size <= 0 {
			return nil, fmt.Errorf("verifier evidence binding has unknown node or invalid size: %s", binding.NodeID)
		}
		if _, err := decodeHex32(binding.SHA256); err != nil {
			return nil, fmt.Errorf("verifier evidence binding %s SHA-256: %w", binding.NodeID, err)
		}
		if filepath.Dir(filepath.Clean(binding.Path)) != filepath.Join(plan.RehearsalRoot, "artifacts") {
			return nil, fmt.Errorf("verifier evidence binding %s is not a direct artifacts child", binding.NodeID)
		}
		result[binding.NodeID] = binding
	}
	return result, nil
}

func validateBoundVerifierEvidence(binding evidenceBinding, plan migrationPlan, node migrationPlanNode) (string, int, error) {
	evidenceBytes, evidenceSHA, err := readExactRegular(binding.Path, binding.SHA256)
	if err != nil {
		return "", 0, fmt.Errorf("read bound verifier evidence: %w", err)
	}
	if len(evidenceBytes) != binding.Size {
		return "", 0, errors.New("bound verifier evidence size changed")
	}
	var result verifierEvidence
	if err = strictDecode(evidenceBytes, &result); err != nil {
		return "", 0, fmt.Errorf("decode bound verifier evidence: %w", err)
	}
	headerBytes, _, err := readExactRegular(plan.HeaderPath, plan.HeaderSHA256)
	if err != nil {
		return "", 0, fmt.Errorf("read exact canonical header for evidence binding: %w", err)
	}
	record, err := networkIdentityRecordForPlan(plan, headerBytes)
	if err != nil {
		return "", 0, fmt.Errorf("construct exact identity record for evidence binding: %w", err)
	}
	envelope, err := networkidentity.Encode(record)
	if err != nil {
		return "", 0, fmt.Errorf("encode exact identity envelope for evidence binding: %w", err)
	}
	envelopeDigest := sha256.Sum256(envelope)
	if binding.NodeID != node.ID || result.Schema != "drwa.s1.prototype-network-identity-migration.v2" ||
		result.Status != "DRY_VALIDATED_16_NODE_PLAN_BOUND_ABSENT_TARGET_NO_NODE_MUTATION" ||
		result.Mode != "plan" || result.ChainID != plan.ChainID || result.CanonicalEpoch != plan.CanonicalEpoch ||
		result.Provenance != "PLANNED_EMERGENCY_MIGRATION_NOT_APPLIED" || result.CanonicalHash != plan.CanonicalHash ||
		result.NetworkDomain != plan.NetworkDomain || result.HeaderSHA256 != plan.HeaderSHA256 || result.HeaderLength <= 0 ||
		result.IdentitySchemaVersion != networkidentity.Version || result.StorageKeyHex != hex.EncodeToString(networkidentity.Key(plan.CanonicalEpoch)) ||
		result.EnvelopeSHA256 != hex.EncodeToString(envelopeDigest[:]) || result.EnvelopeLength != len(envelope) ||
		result.HeaderOutputPath != plan.HeaderPath || result.BindingPath != plan.BindingPath || result.BindingSHA256 != plan.BindingSHA256 ||
		result.TargetDBPath != node.TargetDBPath || result.NodeRoot != node.NodeRoot || result.ShardID != node.ShardID ||
		!result.TargetAbsentBefore || result.AuthoritativeRunCredit != 0 {
		return "", 0, errors.New("bound verifier evidence differs from exact plan or no-mutation contract")
	}
	if _, err = time.Parse(time.RFC3339Nano, result.TimestampUTC); err != nil {
		return "", 0, errors.New("bound verifier evidence timestamp is invalid")
	}
	return evidenceSHA, len(evidenceBytes), nil
}

func reconcileJournalEvidenceBindings(journalPath string) error {
	value, _, err := readExactRegular(journalPath, "")
	if err != nil {
		return err
	}
	lines := bytes.Split(bytes.TrimSpace(value), []byte{'\n'})
	bound := 0
	for index, line := range lines {
		var event journalEvent
		if err = strictDecode(line, &event); err != nil {
			return fmt.Errorf("journal line %d: %w", index+1, err)
		}
		if event.Schema != "drwa.s1.prototype-network-identity-rehearsal-journal.v1" || event.Sequence != index+1 {
			return fmt.Errorf("journal line %d schema/sequence mismatch", index+1)
		}
		if event.Status != "NODE_REVALIDATED_TARGET_ABSENT" {
			continue
		}
		if _, digestErr := decodeHex32(event.EvidenceSHA); event.PlanEvidence == "" || event.EvidenceSize <= 0 || digestErr != nil {
			return fmt.Errorf("journal line %d evidence binding is incomplete", index+1)
		}
		evidence, observedSHA, readErr := readExactRegular(event.PlanEvidence, event.EvidenceSHA)
		if readErr != nil {
			return fmt.Errorf("journal line %d evidence: %w", index+1, readErr)
		}
		if len(evidence) != event.EvidenceSize || observedSHA != event.EvidenceSHA {
			return fmt.Errorf("journal line %d evidence size/hash mismatch", index+1)
		}
		bound++
	}
	if bound != 16 {
		return fmt.Errorf("journal binds %d mutation-boundary records, expected 16", bound)
	}
	return nil
}

func openVerifiedExecutable(path, expectedSHA string) (*sealedExecutable, error) {
	canonical, err := canonicalNoSymlinkExisting(path)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(canonical, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	original := os.NewFile(uintptr(fd), canonical)
	if original == nil {
		_ = unix.Close(fd)
		return nil, errors.New("create retained executable handle")
	}
	fail := func(reason error) (*sealedExecutable, error) {
		_ = original.Close()
		return nil, reason
	}
	info, err := original.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return fail(errors.New("identity verifier is not an executable regular file"))
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fail(errors.New("identity verifier filesystem identity is unavailable"))
	}
	value, err := io.ReadAll(original)
	if err != nil {
		return fail(err)
	}
	digest := sha256.Sum256(value)
	digestHex := hex.EncodeToString(digest[:])
	if expectedSHA != "" && digestHex != expectedSHA {
		return fail(fmt.Errorf("identity verifier SHA-256 %s does not match expected %s", digestHex, expectedSHA))
	}
	if _, err = original.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	snapshotWriteFD, err := unix.MemfdCreate(
		"drwa-s1-identity-verifier",
		unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING|unix.MFD_EXEC,
	)
	if err != nil {
		return fail(fmt.Errorf("create sealable executable verifier snapshot: %w", err))
	}
	snapshotWriter := os.NewFile(uintptr(snapshotWriteFD), "anonymous-verifier-snapshot-writer")
	if snapshotWriter == nil {
		_ = unix.Close(snapshotWriteFD)
		return fail(errors.New("create anonymous verifier snapshot writer"))
	}
	if _, err = snapshotWriter.Write(value); err != nil {
		_ = snapshotWriter.Close()
		return fail(err)
	}
	if err = snapshotWriter.Sync(); err != nil {
		_ = snapshotWriter.Close()
		return fail(err)
	}
	if err = snapshotWriter.Chmod(0o500); err != nil {
		_ = snapshotWriter.Close()
		return fail(err)
	}
	const requiredSeals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if _, err = unix.FcntlInt(snapshotWriter.Fd(), unix.F_ADD_SEALS, requiredSeals); err != nil {
		_ = snapshotWriter.Close()
		return fail(fmt.Errorf("seal executable verifier snapshot: %w", err))
	}
	observedSeals, err := unix.FcntlInt(snapshotWriter.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || observedSeals&requiredSeals != requiredSeals {
		_ = snapshotWriter.Close()
		return fail(errors.New("executable verifier snapshot seals are incomplete"))
	}
	snapshot := snapshotWriter
	snapshotInfo, err := snapshot.Stat()
	if err != nil {
		_ = snapshot.Close()
		return fail(err)
	}
	snapshotStat, ok := snapshotInfo.Sys().(*syscall.Stat_t)
	if !ok || snapshotInfo.Size() != int64(len(value)) || snapshotInfo.Mode().Perm() != 0o500 {
		_ = snapshot.Close()
		return fail(errors.New("anonymous verifier snapshot identity/mode mismatch"))
	}
	return &sealedExecutable{
		file: snapshot, original: original, sha: digestHex, script: bytes.HasPrefix(value, []byte("#!")),
		originalDevice: uint64(stat.Dev), originalInode: stat.Ino, originalSize: info.Size(), originalMode: info.Mode(),
		snapshotDevice: uint64(snapshotStat.Dev), snapshotInode: snapshotStat.Ino,
		snapshotSize: snapshotInfo.Size(), snapshotMode: snapshotInfo.Mode(), snapshotSeals: observedSeals,
	}, nil
}

func (executable *sealedExecutable) Close() error {
	snapshotErr := executable.file.Close()
	originalErr := executable.original.Close()
	if snapshotErr != nil {
		return snapshotErr
	}
	return originalErr
}

func (executable *sealedExecutable) verifyUnchanged() error {
	info, err := executable.original.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != executable.originalDevice || stat.Ino != executable.originalInode || info.Size() != executable.originalSize || info.Mode() != executable.originalMode {
		return errors.New("retained identity verifier filesystem identity changed")
	}
	if _, err = executable.original.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hasher := sha256.New()
	if _, err = io.Copy(hasher, executable.original); err != nil {
		return err
	}
	if hex.EncodeToString(hasher.Sum(nil)) != executable.sha {
		return errors.New("retained identity verifier bytes changed")
	}
	if _, err = executable.original.Seek(0, io.SeekStart); err != nil {
		return err
	}
	snapshotInfo, err := executable.file.Stat()
	if err != nil {
		return err
	}
	snapshotStat, ok := snapshotInfo.Sys().(*syscall.Stat_t)
	if !ok || uint64(snapshotStat.Dev) != executable.snapshotDevice || snapshotStat.Ino != executable.snapshotInode ||
		snapshotInfo.Size() != executable.snapshotSize || snapshotInfo.Mode() != executable.snapshotMode {
		return errors.New("anonymous identity verifier snapshot changed")
	}
	observedSeals, err := unix.FcntlInt(executable.file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || observedSeals != executable.snapshotSeals ||
		observedSeals&(unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL) !=
			unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL {
		return errors.New("anonymous identity verifier snapshot seals changed")
	}
	if _, err = executable.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	snapshotHasher := sha256.New()
	if _, err = io.Copy(snapshotHasher, executable.file); err != nil {
		return err
	}
	if hex.EncodeToString(snapshotHasher.Sum(nil)) != executable.sha {
		return errors.New("anonymous identity verifier snapshot bytes changed")
	}
	_, err = executable.file.Seek(0, io.SeekStart)
	return err
}

func hashLoadedExecutable() (string, error) {
	file, err := os.Open("/proc/self/exe")
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("loaded executable is not a regular file")
	}
	hasher := sha256.New()
	if _, err = io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func verifyCanonicalHeader(plan migrationPlan, headerBytes []byte) error {
	marshalizer := &marshal.GogoProtoMarshalizer{}
	metaHeader := &block.MetaBlock{}
	if err := marshalizer.Unmarshal(metaHeader, headerBytes); err != nil {
		return fmt.Errorf("unmarshal canonical MetaBlock: %w", err)
	}
	remarshalled, err := marshalizer.Marshal(metaHeader)
	if err != nil {
		return fmt.Errorf("remarshal canonical MetaBlock: %w", err)
	}
	if !bytes.Equal(remarshalled, headerBytes) {
		return errors.New("canonical MetaBlock has noncanonical byte encoding")
	}
	if !bytes.Equal(metaHeader.GetChainID(), []byte(plan.ChainID)) || metaHeader.GetEpoch() != plan.CanonicalEpoch {
		return errors.New("canonical MetaBlock chain ID or epoch differs from migration plan")
	}
	if len(metaHeader.GetRootHash()) == 0 || len(metaHeader.GetValidatorStatsRootHash()) == 0 {
		return errors.New("canonical MetaBlock state or validator-statistics root is unavailable")
	}
	canonicalHashBytes := coreBlake2b.NewBlake2b().Compute(string(headerBytes))
	if len(canonicalHashBytes) != sha256.Size || hex.EncodeToString(canonicalHashBytes) != plan.CanonicalHash {
		return errors.New("canonical MetaBlock hash differs from migration plan")
	}
	var canonicalHash [sha256.Size]byte
	copy(canonicalHash[:], canonicalHashBytes)
	domain, err := drwaprototype.DeriveNetworkDomain([]byte(plan.ChainID), canonicalHash)
	if err != nil || hex.EncodeToString(domain[:]) != plan.NetworkDomain {
		return errors.New("canonical MetaBlock network domain differs from migration plan")
	}
	return nil
}

func writeAndReopen(node migrationPlanNode, plan migrationPlan, envelope, expectedHeader []byte) error {
	return writeAndReopenWithBoundaryHooks(node, plan, envelope, expectedHeader, nil, nil, nil)
}

func writeAndReopenWithHooks(
	node migrationPlanNode,
	plan migrationPlan,
	envelope []byte,
	expectedHeader []byte,
	beforeOpen func() error,
	afterPut func(),
) error {
	return writeAndReopenWithBoundaryHooks(node, plan, envelope, expectedHeader, nil, beforeOpen, afterPut)
}

func writeAndReopenWithBoundaryHooks(
	node migrationPlanNode,
	plan migrationPlan,
	envelope []byte,
	expectedHeader []byte,
	beforeParentOpen func() error,
	beforeTargetOpen func() error,
	afterPut func(),
) error {
	canonicalRoot, err := canonicalNoSymlinkExisting(node.NodeRoot)
	if err != nil || canonicalRoot != node.NodeRoot {
		return fmt.Errorf("node root is not canonical/no-symlink at write boundary: %w", err)
	}
	rootFD, err := unix.Open(node.NodeRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	rootHandle := os.NewFile(uintptr(rootFD), node.NodeRoot)
	if rootHandle == nil {
		_ = unix.Close(rootFD)
		return errors.New("create node-root handle")
	}
	defer rootHandle.Close()
	rootInfo, err := rootHandle.Stat()
	if err != nil {
		return err
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || uint64(rootStat.Dev) != node.NodeRootDevice || rootStat.Ino != node.NodeRootInode {
		return errors.New("node root filesystem identity changed at write boundary")
	}
	if _, err = os.Lstat(node.TargetDBPath); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return errors.New("target exists at write boundary")
		}
		return err
	}
	parent := filepath.Dir(node.TargetDBPath)
	if beforeParentOpen != nil {
		if err = beforeParentOpen(); err != nil {
			return err
		}
	}
	parentHandle, parentFD, err := openShardParentFromHeldRoot(rootFD, plan.ChainID, node.ShardID, parent)
	if err != nil {
		return err
	}
	defer parentHandle.Close()
	parentInfo, err := parentHandle.Stat()
	if err != nil {
		return err
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("target parent filesystem identity unavailable")
	}
	targetName := filepath.Base(node.TargetDBPath)
	var before unix.Stat_t
	if statErr := unix.Fstatat(parentFD, targetName, &before, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(statErr, syscall.ENOENT) {
		if statErr == nil {
			return errors.New("target appeared through retained parent before LevelDB creation")
		}
		return statErr
	}
	targetFDPath := fmt.Sprintf("/proc/self/fd/%d/%s", parentFD, targetName)
	if beforeTargetOpen != nil {
		if err = beforeTargetOpen(); err != nil {
			return err
		}
	}
	var atOpen unix.Stat_t
	if statErr := unix.Fstatat(parentFD, targetName, &atOpen, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(statErr, syscall.ENOENT) {
		if statErr == nil {
			return errors.New("target appeared at the LevelDB open boundary")
		}
		return statErr
	}
	db, err := leveldb.OpenFile(targetFDPath, exclusiveDBOptions())
	if err != nil {
		return err
	}
	key := networkidentity.Key(plan.CanonicalEpoch)
	if err = db.Put(key, envelope, synchronousWriteOptions()); err != nil {
		_ = db.Close()
		return err
	}
	if afterPut != nil {
		afterPut()
	}
	if err = db.Close(); err != nil {
		return err
	}
	if err = parentHandle.Sync(); err != nil {
		return err
	}
	var created unix.Stat_t
	if err = unix.Fstatat(parentFD, targetName, &created, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if created.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("created target is not a directory")
	}
	currentParent, currentParentFD, err := openCurrentParentMatching(parent, parentStat)
	if err != nil {
		return err
	}
	defer currentParent.Close()
	var currentTarget unix.Stat_t
	if err = unix.Fstatat(currentParentFD, targetName, &currentTarget, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if currentTarget.Dev != created.Dev || currentTarget.Ino != created.Ino || currentTarget.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("exact planned target path does not resolve to the created database")
	}
	currentTargetFDPath := fmt.Sprintf("/proc/self/fd/%d/%s", currentParentFD, targetName)
	reopened, err := leveldb.OpenFile(currentTargetFDPath, &opt.Options{ReadOnly: true, ErrorIfMissing: true})
	if err != nil {
		return err
	}
	stored, getErr := reopened.Get(key, nil)
	closeErr := reopened.Close()
	if getErr != nil {
		return getErr
	}
	if closeErr != nil {
		return closeErr
	}
	if !bytes.Equal(stored, envelope) {
		return errors.New("reopened envelope differs from synchronous write")
	}
	record, err := networkidentity.Decode(stored, []byte(plan.ChainID))
	if err != nil || record.SchemaVersion != networkidentity.Version || record.Epoch != plan.CanonicalEpoch ||
		record.Provenance != networkidentity.EmergencyMigration || !bytes.Equal(record.HeaderBytes, expectedHeader) ||
		hex.EncodeToString(record.CanonicalHash[:]) != plan.CanonicalHash ||
		hex.EncodeToString(record.NetworkDomain[:]) != plan.NetworkDomain {
		return errors.New("reopened envelope semantic validation failed")
	}
	if err = verifyCanonicalHeader(plan, record.HeaderBytes); err != nil {
		return fmt.Errorf("reopened canonical header validation: %w", err)
	}
	var finalIdentity unix.Stat_t
	if err = unix.Fstatat(currentParentFD, targetName, &finalIdentity, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if finalIdentity.Dev != created.Dev || finalIdentity.Ino != created.Ino || finalIdentity.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("target filesystem identity changed across close and reopen")
	}
	if err = verifyCurrentPathIdentity(parent, parentStat, targetName, &created); err != nil {
		return err
	}
	if err = verifyExactNodeRootIdentity(node); err != nil {
		return err
	}
	return nil
}

func openShardParentFromHeldRoot(rootFD int, chainID, shardID, expectedPath string) (*os.File, int, error) {
	if chainID == "" || filepath.Base(chainID) != chainID || shardID == "" || filepath.Base(shardID) != shardID {
		return nil, -1, errors.New("chain or shard path component is invalid")
	}
	currentFD, err := unix.Openat(rootFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, -1, err
	}
	for _, component := range []string{"db", chainID, "Static", "Shard_" + shardID} {
		nextFD, openErr := unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(currentFD)
		if openErr != nil {
			return nil, -1, openErr
		}
		currentFD = nextFD
	}
	handle := os.NewFile(uintptr(currentFD), expectedPath)
	if handle == nil {
		_ = unix.Close(currentFD)
		return nil, -1, errors.New("create held shard-parent handle")
	}
	return handle, currentFD, nil
}

func verifyExactNodeRootIdentity(node migrationPlanNode) error {
	canonical, err := canonicalNoSymlinkExisting(node.NodeRoot)
	if err != nil || canonical != node.NodeRoot {
		return fmt.Errorf("exact node root no longer resolves canonically: %w", err)
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != node.NodeRootDevice || stat.Ino != node.NodeRootInode {
		return errors.New("exact node-root filesystem identity changed")
	}
	return nil
}

func openCurrentParentMatching(parent string, expected *syscall.Stat_t) (*os.File, int, error) {
	canonical, err := canonicalNoSymlinkExisting(parent)
	if err != nil || canonical != parent {
		return nil, -1, fmt.Errorf("exact target parent no longer resolves canonically: %w", err)
	}
	fd, err := unix.Open(canonical, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, -1, err
	}
	handle := os.NewFile(uintptr(fd), canonical)
	if handle == nil {
		_ = unix.Close(fd)
		return nil, -1, errors.New("create current target parent handle")
	}
	info, err := handle.Stat()
	if err != nil {
		_ = handle.Close()
		return nil, -1, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != uint64(expected.Dev) || stat.Ino != expected.Ino || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = handle.Close()
		return nil, -1, errors.New("exact target parent filesystem identity changed")
	}
	return handle, fd, nil
}

func verifyCurrentPathIdentity(parent string, expectedParent *syscall.Stat_t, targetName string, expectedTarget *unix.Stat_t) error {
	handle, fd, err := openCurrentParentMatching(parent, expectedParent)
	if err != nil {
		return err
	}
	defer handle.Close()
	var target unix.Stat_t
	if err = unix.Fstatat(fd, targetName, &target, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if target.Dev != expectedTarget.Dev || target.Ino != expectedTarget.Ino || target.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("exact planned target identity changed after durable reopen")
	}
	return nil
}

func exclusiveDBOptions() *opt.Options {
	return &opt.Options{ErrorIfExist: true}
}

func synchronousWriteOptions() *opt.WriteOptions {
	return &opt.WriteOptions{Sync: true}
}

func requireRuntimeIsolation(contract isolationContract, plan migrationPlan) error {
	if os.Geteuid() != contract.ContainerUserUID || os.Getegid() != contract.ContainerUserGID {
		return errors.New("writer effective user differs from the exact container contract")
	}
	hostname, err := os.Hostname()
	if err != nil || hostname != contract.ContainerHostname {
		return errors.New("writer hostname differs from the exact container contract")
	}
	executablePath, err := os.Executable()
	if err != nil || filepath.Clean(executablePath) != contract.ContainerEntrypoint {
		return errors.New("writer entrypoint differs from the exact container contract")
	}
	statusBytes, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	status := parseColonFields(string(statusBytes))
	if err = validateIsolationStatus(status); err != nil {
		return err
	}
	selfPIDNamespace, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		return err
	}
	initPIDNamespace, err := os.Readlink("/proc/1/ns/pid")
	if err != nil || selfPIDNamespace != initPIDNamespace {
		return errors.New("writer is not PID 1 in its PID namespace")
	}
	networkNamespace, err := os.Readlink("/proc/self/ns/net")
	if err != nil || networkNamespace == "" || networkNamespace == contract.HostNetworkNamespace {
		return errors.New("writer network namespace is absent or equals the recorded host namespace")
	}
	interfaces, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return err
	}
	if len(interfaces) != 1 || interfaces[0].Name() != "lo" {
		return errors.New("isolated writer requires exactly the loopback interface")
	}
	if err = requireNoNonLoopbackRoute(); err != nil {
		return err
	}
	if err = requireNoNonLoopbackIPv6Route(); err != nil {
		return err
	}
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	if err = validateIsolationMounts(string(mounts), contract); err != nil {
		return err
	}
	if err = requireNetworkSyscallsDenied(); err != nil {
		return err
	}
	return nil
}

func validateIsolationMounts(mounts string, contract isolationContract) error {
	rootMode, rootFound := mountMode(mounts, "/")
	rehearsalMode, rehearsalFound := mountMode(mounts, contract.RehearsalRoot)
	seccompMode, seccompFound := mountMode(mounts, contract.SeccompProfilePath)
	if !rootFound || rootMode != "ro" || !rehearsalFound || rehearsalMode != "rw" ||
		!seccompFound || seccompMode != "ro" {
		return errors.New("container root must be read-only, exact rehearsal root read-write, and exact seccomp profile read-only")
	}
	for _, input := range contract.ReadOnlyInputMounts {
		mode, found := mountMode(mounts, input.Target)
		if !found || mode != "ro" {
			return fmt.Errorf("read-only input mount %s is missing or writable", input.Purpose)
		}
	}
	return nil
}

func validateIsolationStatus(status map[string]string) error {
	if status["NoNewPrivs"] != "1" || status["Seccomp"] != "2" {
		return errors.New("NoNewPrivs and seccomp-filter mode are required")
	}
	for _, field := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		if status[field] != "0000000000000000" {
			return fmt.Errorf("%s must be exactly zero for dropped-capabilities ALL", field)
		}
	}
	return nil
}

func requireNoNonLoopbackRoute() error {
	value, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(string(value)), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] != "lo" {
			return fmt.Errorf("non-loopback network route present on %s", fields[0])
		}
	}
	return nil
}

func requireNoNonLoopbackIPv6Route() error {
	value, err := os.ReadFile("/proc/net/ipv6_route")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(value)), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[len(fields)-1] != "lo" {
			return fmt.Errorf("non-loopback IPv6 route present on %s", fields[len(fields)-1])
		}
	}
	return nil
}

func requireNetworkSyscallsDenied() error {
	connectFD, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("create connect-denial probe socket: %w", err)
	}
	connectErr := unix.Connect(connectFD, &unix.SockaddrInet4{Port: 9, Addr: [4]byte{127, 0, 0, 1}})
	_ = unix.Close(connectFD)
	if !errors.Is(connectErr, syscall.EPERM) {
		return fmt.Errorf("connect syscall is not seccomp-denied with EPERM: %v", connectErr)
	}
	bindFD, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("create bind-denial probe socket: %w", err)
	}
	bindErr := unix.Bind(bindFD, &unix.SockaddrInet4{Port: 0, Addr: [4]byte{127, 0, 0, 1}})
	_ = unix.Close(bindFD)
	if !errors.Is(bindErr, syscall.EPERM) {
		return fmt.Errorf("bind syscall is not seccomp-denied with EPERM: %v", bindErr)
	}
	return nil
}

func parseColonFields(value string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(value, "\n") {
		key, field, found := strings.Cut(line, ":")
		if found {
			result[strings.TrimSpace(key)] = strings.TrimSpace(field)
		}
	}
	return result
}

func mountMode(mountInfo, expectedPath string) (string, bool) {
	for _, line := range strings.Split(strings.TrimSpace(mountInfo), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		mountPath := strings.ReplaceAll(strings.ReplaceAll(fields[4], `\040`, " "), `\134`, `\`)
		if mountPath != expectedPath {
			continue
		}
		for _, option := range strings.Split(fields[5], ",") {
			if option == "ro" || option == "rw" {
				return option, true
			}
		}
	}
	return "", false
}

func readExactRegular(path, expectedSHA string) ([]byte, string, error) {
	canonical, err := canonicalNoSymlinkExisting(path)
	if err != nil {
		return nil, "", err
	}
	if canonical != filepath.Clean(path) {
		return nil, "", errors.New("input path is not canonical/no-symlink")
	}
	fd, err := unix.Open(canonical, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, "", err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, "", errors.New("create file handle")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, "", errors.New("input is not a regular file")
	}
	value, err := io.ReadAll(file)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(value)
	digestHex := hex.EncodeToString(digest[:])
	if expectedSHA != "" && digestHex != expectedSHA {
		return nil, "", fmt.Errorf("SHA-256 %s does not match expected %s", digestHex, expectedSHA)
	}
	return value, digestHex, nil
}

func canonicalNoSymlinkExisting(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	cleaned := filepath.Clean(absolute)
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return "", err
	}
	if resolved != cleaned {
		return "", errors.New("path contains a symbolic-link component")
	}
	return cleaned, nil
}

func decodeHex32(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return nil, errors.New("expected exactly 32 lowercase hexadecimal bytes")
	}
	if hex.EncodeToString(decoded) != value {
		return nil, errors.New("hexadecimal identity is not canonical lowercase")
	}
	return decoded, nil
}

func networkIdentityRecordForPlan(plan migrationPlan, headerBytes []byte) (networkidentity.Record, error) {
	canonicalHashBytes, err := decodeHex32(plan.CanonicalHash)
	if err != nil {
		return networkidentity.Record{}, fmt.Errorf("canonical hash: %w", err)
	}
	networkDomainBytes, err := decodeHex32(plan.NetworkDomain)
	if err != nil {
		return networkidentity.Record{}, fmt.Errorf("network domain: %w", err)
	}
	canonicalHash := [32]byte{}
	copy(canonicalHash[:], canonicalHashBytes)
	networkDomain := [32]byte{}
	copy(networkDomain[:], networkDomainBytes)

	return networkidentity.Record{
		SchemaVersion: networkidentity.Version,
		Epoch:         plan.CanonicalEpoch,
		Provenance:    networkidentity.EmergencyMigration,
		ChainID:       []byte(plan.ChainID),
		CanonicalHash: canonicalHash,
		NetworkDomain: networkDomain,
		HeaderBytes:   headerBytes,
	}, nil
}

func supportedShard(shardID string) bool {
	return shardID == "0" || shardID == "1" || shardID == "2" || shardID == "metachain"
}

func openOutputDirectory(rehearsalRoot, journalPath, summaryPath string) (*outputDirectory, error) {
	root, err := canonicalNoSymlinkExisting(rehearsalRoot)
	if err != nil {
		return nil, err
	}
	expected := filepath.Join(root, "artifacts")
	if filepath.Dir(filepath.Clean(journalPath)) != expected || filepath.Dir(filepath.Clean(summaryPath)) != expected ||
		filepath.Base(journalPath) == "." || filepath.Base(summaryPath) == "." {
		return nil, errors.New("journal and summary must be direct children of the rehearsal artifacts directory")
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootFD)
	artifactsFD, err := unix.Openat(rootFD, "artifacts", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(artifactsFD), expected)
	if file == nil {
		_ = unix.Close(artifactsFD)
		return nil, errors.New("create artifacts directory handle")
	}
	resolved, err := canonicalNoSymlinkExisting(expected)
	if err != nil || resolved != expected {
		_ = file.Close()
		return nil, errors.New("artifacts directory is not canonical/no-symlink")
	}
	return &outputDirectory{file: file, path: expected}, nil
}

func (directory *outputDirectory) openExclusive(name string, mode os.FileMode) (*os.File, error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return nil, errors.New("output name must be one path component")
	}
	fd, err := unix.Openat(int(directory.file.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(mode.Perm()))
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(directory.path, name))
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("create output handle")
	}
	if err = directory.file.Sync(); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func (directory *outputDirectory) Close() error {
	return directory.file.Close()
}

func hashOpenFile(file *os.File) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}

func strictDecode(value []byte, destination interface{}) error {
	if err := rejectDuplicateJSONKeys(value); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

func rejectDuplicateJSONKeys(value []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, tokenErr := decoder.Token()
			if tokenErr != nil {
				return tokenErr
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := keys[key]; duplicate {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			keys[key] = struct{}{}
			if err = consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim('}') {
			return errors.New("invalid JSON object close")
		}
	case '[':
		for decoder.More() {
			if err = consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim(']') {
			return errors.New("invalid JSON array close")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}
