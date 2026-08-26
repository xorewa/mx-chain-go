package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/multiversx/mx-chain-core-go/data/block"
	coreBlake2b "github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype/networkidentity"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"golang.org/x/sys/unix"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// REPLACED_BY_PART_B

const (
	contractSchema = "drwa.s1.prototype-network-identity-orchestration-contract.v1"
	contractStatus = "READY_INDEPENDENTLY_AUDITED_ISOLATED_REHEARSAL_NO_LIVE_AUTHORIZATION"
	planSchema     = "drwa.s1.prototype-network-identity-migration-plan.v1"
	metaShard      = uint32(4294967295)
)

type options struct {
	mode                string
	contractPath        string
	expectedContractSHA string
	containerName       string
	preflightOutput     string
}

type boundArtifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type containerRuntimeContract struct {
	ImageID         string        `json:"image_id"`
	ImageRepoDigest string        `json:"image_repo_digest"`
	Platform        string        `json:"platform"`
	Name            string        `json:"name"`
	Hostname        string        `json:"hostname"`
	UID             int           `json:"uid"`
	GID             int           `json:"gid"`
	NetworkMode     string        `json:"network_mode"`
	PIDMode         string        `json:"pid_mode"`
	RestartPolicy   string        `json:"restart_policy"`
	PullPolicy      string        `json:"pull_policy"`
	ReadOnlyRootFS  bool          `json:"read_only_rootfs"`
	AutoRemove      bool          `json:"auto_remove"`
	Orchestrator    boundArtifact `json:"orchestrator"`
	Environment     []string      `json:"environment"`
}

type orchestrationContract struct {
	Schema                     string                   `json:"schema"`
	Status                     string                   `json:"status"`
	CreatedUTC                 string                   `json:"created_utc"`
	RehearsalRoot              string                   `json:"rehearsal_root"`
	HostNetworkNamespace       string                   `json:"host_network_namespace"`
	MigrationPlan              boundArtifact            `json:"migration_plan"`
	WriterSummary              boundArtifact            `json:"writer_summary"`
	WriterJournal              boundArtifact            `json:"writer_journal"`
	WriterIsolationContract    boundArtifact            `json:"writer_isolation_contract"`
	WriterBinary               boundArtifact            `json:"writer_binary"`
	WriterIdentityTool         boundArtifact            `json:"writer_identity_tool"`
	WriterStoppedPreflight     boundArtifact            `json:"writer_stopped_preflight"`
	WriterContainerEvents      boundArtifact            `json:"writer_container_events"`
	WriterPostRunState         boundArtifact            `json:"writer_post_run_state"`
	WriterLogsEvidence         boundArtifact            `json:"writer_logs_evidence"`
	NodeBinary                 boundArtifact            `json:"node_binary"`
	NodeBase                   string                   `json:"node_base"`
	NodeBaseFiles              []boundArtifact          `json:"node_base_files"`
	SeedBinary                 boundArtifact            `json:"seed_binary"`
	SeedRoot                   string                   `json:"seed_root"`
	SeedFiles                  []boundArtifact          `json:"seed_files"`
	TraceLoader                boundArtifact            `json:"trace_loader"`
	TraceBinary                boundArtifact            `json:"trace_binary"`
	TraceLibraryDirectory      string                   `json:"trace_library_directory"`
	TraceLibraries             []boundArtifact          `json:"trace_libraries"`
	RuntimeLibraryDirectory    string                   `json:"runtime_library_directory"`
	RuntimeLibraries           []boundArtifact          `json:"runtime_libraries"`
	ChildEnvironment           []string                 `json:"child_environment"`
	SeccompProfile             boundArtifact            `json:"seccomp_profile"`
	ReadOnlyMounts             []string                 `json:"read_only_mounts"`
	ExpectedGenesisTimestamp   uint64                   `json:"expected_genesis_timestamp"`
	CanonicalMetachainHash     string                   `json:"canonical_metachain_genesis_hash"`
	NetworkDomain              string                   `json:"network_domain"`
	IdentityProvenance         string                   `json:"identity_provenance"`
	CrashNodeID                string                   `json:"crash_node_id"`
	HealthTimeoutSeconds       uint64                   `json:"health_timeout_seconds"`
	ShutdownTimeoutSeconds     uint64                   `json:"shutdown_timeout_seconds"`
	EvidencePath               string                   `json:"evidence_path"`
	JournalPath                string                   `json:"journal_path"`
	AuthoritativeRuntimeCredit int                      `json:"authoritative_runtime_credit"`
	ContainerRuntime           containerRuntimeContract `json:"container_runtime"`
	ContainerPreflightPath     string                   `json:"container_preflight_path"`
}

type containerPreflightEvidence struct {
	Schema                 string   `json:"schema"`
	Status                 string   `json:"status"`
	TimestampUTC           string   `json:"timestamp_utc"`
	ContractPath           string   `json:"contract_path"`
	ContractSHA256         string   `json:"contract_sha256"`
	ContainerName          string   `json:"container_name"`
	ContainerID            string   `json:"container_id"`
	ContainerInspectSHA256 string   `json:"container_inspect_sha256"`
	ImageInspectSHA256     string   `json:"image_inspect_sha256"`
	ContainerInspectPath   string   `json:"container_inspect_path"`
	ImageInspectPath       string   `json:"image_inspect_path"`
	ImageID                string   `json:"image_id"`
	ImageRepoDigest        string   `json:"image_repo_digest"`
	Platform               string   `json:"platform"`
	ExactBinds             []string `json:"exact_binds"`
	SeccompProfilePath     string   `json:"seccomp_profile_path"`
	SeccompProfileSHA256   string   `json:"seccomp_profile_sha256"`
	AuthoritativeCredit    int      `json:"authoritative_runtime_credit"`
}

type dockerContainerInspection struct {
	ID           string `json:"Id"`
	Name         string `json:"Name"`
	Platform     string `json:"Platform"`
	Image        string `json:"Image"`
	RestartCount int    `json:"RestartCount"`
	State        struct {
		Status  string `json:"Status"`
		Running bool   `json:"Running"`
		PID     int    `json:"Pid"`
	} `json:"State"`
	Config struct {
		Hostname    string          `json:"Hostname"`
		User        string          `json:"User"`
		Entrypoint  []string        `json:"Entrypoint"`
		Cmd         []string        `json:"Cmd"`
		Healthcheck json.RawMessage `json:"Healthcheck,omitempty"`
	} `json:"Config"`
	HostConfig struct {
		Binds             []string          `json:"Binds"`
		NetworkMode       string            `json:"NetworkMode"`
		PIDMode           string            `json:"PidMode"`
		AutoRemove        bool              `json:"AutoRemove"`
		ReadonlyRootfs    bool              `json:"ReadonlyRootfs"`
		Privileged        bool              `json:"Privileged"`
		PublishAllPorts   bool              `json:"PublishAllPorts"`
		CapAdd            []string          `json:"CapAdd"`
		CapDrop           []string          `json:"CapDrop"`
		SecurityOpt       []string          `json:"SecurityOpt"`
		Devices           []json.RawMessage `json:"Devices"`
		DeviceRequests    []json.RawMessage `json:"DeviceRequests"`
		DeviceCgroupRules []string          `json:"DeviceCgroupRules"`
		IPCMode           string            `json:"IpcMode"`
		UTSMode           string            `json:"UTSMode"`
		UsernsMode        string            `json:"UsernsMode"`
		CgroupnsMode      string            `json:"CgroupnsMode"`
		Runtime           string            `json:"Runtime"`
		Init              *bool             `json:"Init"`
		RestartPolicy     struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
		PortBindings map[string]interface{} `json:"PortBindings"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type        string `json:"Type"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		Mode        string `json:"Mode"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
}

type dockerImageInspection struct {
	ID           string   `json:"Id"`
	RepoDigests  []string `json:"RepoDigests"`
	Architecture string   `json:"Architecture"`
	OS           string   `json:"Os"`
}

type runtimeSelfSnapshot struct {
	UID, GID int
	Hostname string
	SelfSHA  string
	Args     []string
	Env      []string
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

type writerSummary struct {
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

type nodeSpec struct {
	ID             string
	Role           string
	ShardID        uint32
	REST           uint16
	Args           []string
	Work           string
	WorkRootDevice uint64
	WorkRootInode  uint64
}

type sealedFile struct {
	file   *os.File
	path   string
	sha    string
	device uint64
	inode  uint64
	size   int64
	mode   os.FileMode
}

type runningProcess struct {
	ID          string
	cmd         *exec.Cmd
	groupID     int
	targetPID   int
	targetPIDFD int
	done        chan error
	stdout      *os.File
	tracePrefix string
	cleanStop   bool
	crashed     bool
}

type endpointObservation struct {
	ID      string `json:"id"`
	REST    uint16 `json:"rest"`
	ShardID uint32 `json:"shard_id"`
	Epoch   uint64 `json:"epoch"`
	Round   uint64 `json:"round"`
	Nonce   uint64 `json:"nonce"`
	ChainID string `json:"chain_id"`
}

type blockObservation struct {
	Hash          string `json:"hash"`
	StateRootHash string `json:"state_root_hash"`
	Timestamp     uint64 `json:"timestamp"`
	Nonce         uint64 `json:"nonce"`
	ShardID       uint32 `json:"shard_id"`
}

type healthSnapshot struct {
	Endpoints map[string]endpointObservation `json:"endpoints"`
	Anchors   map[string]blockObservation    `json:"anchors"`
}

type journalEvent struct {
	Schema       string   `json:"schema"`
	Sequence     int      `json:"sequence"`
	TimestampUTC string   `json:"timestamp_utc"`
	Status       string   `json:"status"`
	Completed    []string `json:"completed_steps,omitempty"`
	Detail       string   `json:"detail,omitempty"`
}

type rehearsalEvidence struct {
	Schema                     string              `json:"schema"`
	Status                     string              `json:"status"`
	TimestampUTC               string              `json:"timestamp_utc"`
	ContractPath               string              `json:"contract_path"`
	ContractSHA256             string              `json:"contract_sha256"`
	MigrationPlanSHA256        string              `json:"migration_plan_sha256"`
	WriterSummarySHA256        string              `json:"writer_summary_sha256"`
	WriterJournalSHA256        string              `json:"writer_journal_sha256"`
	WriterIsolationContractSHA string              `json:"writer_isolation_contract_sha256"`
	WriterBinarySHA256         string              `json:"writer_binary_sha256"`
	WriterIdentityToolSHA256   string              `json:"writer_identity_tool_sha256"`
	WriterStoppedPreflightSHA  string              `json:"writer_stopped_preflight_sha256"`
	WriterContainerEventsSHA   string              `json:"writer_container_events_sha256"`
	WriterPostRunStateSHA      string              `json:"writer_post_run_state_sha256"`
	WriterLogsEvidenceSHA      string              `json:"writer_logs_evidence_sha256"`
	ContainerPreflightSHA256   string              `json:"container_preflight_sha256"`
	NodeBinarySHA256           string              `json:"node_binary_sha256"`
	OrchestratorBinarySHA256   string              `json:"orchestrator_binary_sha256"`
	ContainerImageID           string              `json:"container_image_id"`
	ContainerImageRepoDigest   string              `json:"container_image_repo_digest"`
	ContainerPlatform          string              `json:"container_platform"`
	ContainerName              string              `json:"container_name"`
	ContainerUID               int                 `json:"container_uid"`
	ContainerGID               int                 `json:"container_gid"`
	SeccompProfileSHA256       string              `json:"seccomp_profile_sha256"`
	RuntimeLibraryFiles        map[string]string   `json:"runtime_library_files_sha256"`
	ChildEnvironment           []string            `json:"child_environment"`
	CanonicalMetachainHash     string              `json:"canonical_metachain_genesis_hash"`
	NetworkDomain              string              `json:"network_domain"`
	IdentityProvenance         string              `json:"identity_provenance"`
	FirstStart                 healthSnapshot      `json:"first_start"`
	SecondStart                healthSnapshot      `json:"second_start"`
	PostCrashRestart           healthSnapshot      `json:"post_crash_restart"`
	CleanShutdowns             map[string][]string `json:"clean_shutdowns"`
	CrashNodeID                string              `json:"crash_node_id"`
	TraceFiles                 map[string]string   `json:"trace_files_sha256"`
	LogFiles                   map[string]string   `json:"log_files_sha256"`
	EveryIdentityLogMatched    bool                `json:"every_identity_log_matched"`
	AllConnectBindLoopbackOnly bool                `json:"all_connect_bind_loopback_only"`
	NoStateRootDrift           bool                `json:"no_state_root_drift"`
	AuthoritativeRuntimeCredit int                 `json:"authoritative_runtime_credit"`
}

func main() {
	opts := options{}
	flag.StringVar(&opts.mode, "mode", "orchestrate", "orchestrate or inspect-preflight")
	flag.StringVar(&opts.contractPath, "contract", "", "exact independently audited orchestration contract")
	flag.StringVar(&opts.expectedContractSHA, "expected-contract-sha", "", "exact contract SHA-256")
	flag.StringVar(&opts.containerName, "container-name", "", "exact stopped container name for inspect-preflight")
	flag.StringVar(&opts.preflightOutput, "preflight-output", "", "exclusive stopped-container preflight evidence path")
	flag.Parse()
	var err error
	switch opts.mode {
	case "orchestrate":
		err = run(opts)
	case "inspect-preflight":
		err = runContainerPreflight(opts)
	default:
		err = errors.New("unknown mode")
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(opts options) error {
	if os.Getpid() != 1 {
		return errors.New("isolated rehearsal orchestrator must be container PID 1")
	}
	if opts.contractPath == "" {
		return errors.New("contract path is required")
	}
	if err := validateDigest(opts.expectedContractSHA); err != nil {
		return fmt.Errorf("expected contract SHA-256 is required: %w", err)
	}
	contractBytes, observedContractSHA, err := readBoundFile(opts.contractPath, opts.expectedContractSHA)
	if err != nil {
		return err
	}
	var contract orchestrationContract
	if err = strictDecode(contractBytes, &contract); err != nil {
		return fmt.Errorf("decode orchestration contract: %w", err)
	}
	if err = validateContract(contract); err != nil {
		return err
	}
	if err = verifyRuntimeSelf(contract, opts.contractPath, observedContractSHA); err != nil {
		return fmt.Errorf("runtime self binding: %w", err)
	}
	containerPreflightSHA, err := verifyContainerPreflightEvidence(contract, opts.contractPath, observedContractSHA)
	if err != nil {
		return fmt.Errorf("stopped-container preflight binding: %w", err)
	}
	if err = requireRuntimeIsolation(contract); err != nil {
		return fmt.Errorf("runtime isolation: %w", err)
	}
	return executeRehearsal(contract, opts.contractPath, observedContractSHA, containerPreflightSHA)
}

func validateContract(contract orchestrationContract) error {
	if contract.Schema != contractSchema || contract.Status != contractStatus ||
		contract.AuthoritativeRuntimeCredit != 0 || contract.RehearsalRoot == "" ||
		contract.HostNetworkNamespace == "" || contract.IdentityProvenance != networkidentity.EmergencyMigration.String() {
		return errors.New("orchestration contract schema/status/boundary mismatch")
	}
	created, err := time.Parse(time.RFC3339Nano, contract.CreatedUTC)
	if err != nil || created.Location() != time.UTC || created.Format(time.RFC3339Nano) != contract.CreatedUTC {
		return errors.New("orchestration contract timestamp is not canonical UTC")
	}
	if contract.HealthTimeoutSeconds < 30 || contract.HealthTimeoutSeconds > 600 ||
		contract.ShutdownTimeoutSeconds < 10 || contract.ShutdownTimeoutSeconds > 120 {
		return errors.New("orchestration timeouts are outside bounded range")
	}
	if err := validateDigest(contract.CanonicalMetachainHash); err != nil {
		return fmt.Errorf("canonical metachain hash: %w", err)
	}
	if err := validateDigest(contract.NetworkDomain); err != nil {
		return fmt.Errorf("network domain: %w", err)
	}
	for name, artifact := range map[string]boundArtifact{
		"migration plan": contract.MigrationPlan, "writer summary": contract.WriterSummary,
		"writer journal": contract.WriterJournal, "writer isolation contract": contract.WriterIsolationContract,
		"writer binary": contract.WriterBinary, "writer identity tool": contract.WriterIdentityTool,
		"writer stopped preflight": contract.WriterStoppedPreflight, "writer container events": contract.WriterContainerEvents,
		"writer post-run state": contract.WriterPostRunState, "writer logs evidence": contract.WriterLogsEvidence,
		"node binary": contract.NodeBinary,
		"seed binary": contract.SeedBinary, "trace loader": contract.TraceLoader, "trace binary": contract.TraceBinary,
		"seccomp profile":     contract.SeccompProfile,
		"orchestrator binary": contract.ContainerRuntime.Orchestrator,
	} {
		if artifact.Path == "" || !pathWithin(contract.RehearsalRoot, artifact.Path) {
			return fmt.Errorf("%s path is empty or outside rehearsal root", name)
		}
		if err := validateDigest(artifact.SHA256); err != nil {
			return fmt.Errorf("%s SHA-256: %w", name, err)
		}
	}
	if err := validateContainerRuntimeContract(contract); err != nil {
		return err
	}
	if !pathWithin(contract.RehearsalRoot, contract.EvidencePath) ||
		!pathWithin(contract.RehearsalRoot, contract.JournalPath) ||
		filepath.Dir(contract.EvidencePath) != filepath.Join(contract.RehearsalRoot, "artifacts") ||
		filepath.Dir(contract.JournalPath) != filepath.Join(contract.RehearsalRoot, "artifacts") ||
		filepath.Clean(contract.EvidencePath) == filepath.Clean(contract.JournalPath) {
		return errors.New("evidence and journal must be distinct direct rehearsal-artifact children")
	}
	if !pathWithin(contract.RehearsalRoot, contract.ContainerPreflightPath) ||
		filepath.Dir(contract.ContainerPreflightPath) != filepath.Join(contract.RehearsalRoot, "artifacts") ||
		contract.ContainerPreflightPath == contract.EvidencePath || contract.ContainerPreflightPath == contract.JournalPath {
		return errors.New("container preflight must be a distinct direct rehearsal-artifact child")
	}
	if !pathWithin(contract.RehearsalRoot, contract.NodeBase) || !pathWithin(contract.RehearsalRoot, contract.SeedRoot) ||
		contract.TraceLibraryDirectory == "" || len(contract.TraceLibraries) == 0 ||
		contract.RuntimeLibraryDirectory == "" || len(contract.RuntimeLibraries) == 0 || len(contract.ReadOnlyMounts) == 0 {
		return errors.New("node/seed/trace boundary is incomplete")
	}
	if err := validateChildEnvironment(contract); err != nil {
		return err
	}
	if err := validateReadOnlyMountSet(contract); err != nil {
		return err
	}
	collections := []struct {
		root      string
		artifacts []boundArtifact
	}{
		{root: contract.NodeBase, artifacts: contract.NodeBaseFiles},
		{root: contract.SeedRoot, artifacts: contract.SeedFiles},
		{root: contract.TraceLibraryDirectory, artifacts: contract.TraceLibraries},
		{root: contract.RuntimeLibraryDirectory, artifacts: contract.RuntimeLibraries},
	}
	for _, collection := range collections {
		if !pathWithin(contract.RehearsalRoot, collection.root) {
			return fmt.Errorf("bound artifact root escapes rehearsal root: %s", collection.root)
		}
		if len(collection.artifacts) == 0 {
			return errors.New("a bound artifact collection is empty")
		}
		seen := make(map[string]struct{})
		for _, artifact := range collection.artifacts {
			if artifact.Path == "" || !pathWithin(collection.root, artifact.Path) {
				return errors.New("bound artifact path is empty")
			}
			if err := validateDigest(artifact.SHA256); err != nil {
				return err
			}
			if _, duplicate := seen[artifact.Path]; duplicate {
				return fmt.Errorf("duplicate bound artifact %s", artifact.Path)
			}
			seen[artifact.Path] = struct{}{}
		}
	}
	return nil
}

func validateReadOnlyMountSet(contract orchestrationContract) error {
	expected := map[string]struct{}{
		filepath.Clean(contract.NodeBase):                           {},
		filepath.Clean(contract.SeedRoot):                           {},
		filepath.Clean(contract.TraceLibraryDirectory):              {},
		filepath.Clean(contract.RuntimeLibraryDirectory):            {},
		filepath.Clean(contract.SeccompProfile.Path):                {},
		filepath.Clean(contract.ContainerRuntime.Orchestrator.Path): {},
	}
	if len(expected) != 6 || len(contract.ReadOnlyMounts) != len(expected) {
		return errors.New("read-only mount set must contain exactly node base, seed root, trace libraries, runtime libraries, seccomp profile, and orchestrator binary")
	}
	seen := make(map[string]struct{}, len(expected))
	for _, path := range contract.ReadOnlyMounts {
		cleaned := filepath.Clean(path)
		if _, exists := expected[cleaned]; !exists || cleaned != path {
			return fmt.Errorf("unexpected read-only mount %s", path)
		}
		if _, duplicate := seen[cleaned]; duplicate {
			return fmt.Errorf("duplicate read-only mount %s", path)
		}
		seen[cleaned] = struct{}{}
	}
	return nil
}

func validateChildEnvironment(contract orchestrationContract) error {
	expected := []string{
		"HOME=" + filepath.Join(contract.RehearsalRoot, "runtime", "home"),
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"LD_LIBRARY_PATH=" + contract.RuntimeLibraryDirectory,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"TMPDIR=" + filepath.Join(contract.RehearsalRoot, "runtime", "tmp"),
	}
	sort.Strings(expected)
	observed := append([]string(nil), contract.ChildEnvironment...)
	sort.Strings(observed)
	if len(observed) != len(expected) || strings.Join(observed, "\x00") != strings.Join(expected, "\x00") {
		return errors.New("child environment is not the exact bounded execution environment")
	}
	for _, directory := range []string{filepath.Join(contract.RehearsalRoot, "runtime", "home"), filepath.Join(contract.RehearsalRoot, "runtime", "tmp")} {
		canonical, err := canonicalNoSymlinkExisting(directory)
		if err != nil || canonical != directory {
			return fmt.Errorf("child runtime directory is not canonical/no-symlink: %s", directory)
		}
		entries, readErr := os.ReadDir(directory)
		if readErr != nil || len(entries) != 0 {
			return fmt.Errorf("child runtime directory is not an exact empty prestate: %s", directory)
		}
	}
	return nil
}

func validateContainerRuntimeContract(contract orchestrationContract) error {
	runtime := contract.ContainerRuntime
	if runtime.Platform != "linux/amd64" || runtime.UID != 1001 || runtime.GID != 1001 ||
		runtime.NetworkMode != "none" || runtime.PIDMode != "private" || runtime.RestartPolicy != "no" ||
		runtime.PullPolicy != "never" || !runtime.ReadOnlyRootFS || runtime.AutoRemove ||
		runtime.Name == "" || runtime.Hostname != runtime.Name {
		return errors.New("container runtime substrate differs from the exact isolated profile")
	}
	if !strings.HasPrefix(runtime.ImageID, "sha256:") || validateDigest(strings.TrimPrefix(runtime.ImageID, "sha256:")) != nil {
		return errors.New("container image ID is not an exact sha256 identity")
	}
	repository, digest, found := strings.Cut(runtime.ImageRepoDigest, "@")
	if !found || repository == "" || !strings.HasPrefix(digest, "sha256:") || validateDigest(strings.TrimPrefix(digest, "sha256:")) != nil {
		return errors.New("container image repo digest is not an immutable repository reference")
	}
	if runtime.Orchestrator.Path == "" || !pathWithin(contract.RehearsalRoot, runtime.Orchestrator.Path) {
		return errors.New("orchestrator binary is outside rehearsal root")
	}
	expectedEnvironment := append([]string(nil), contract.ChildEnvironment...)
	observedEnvironment := append([]string(nil), runtime.Environment...)
	sort.Strings(expectedEnvironment)
	sort.Strings(observedEnvironment)
	if len(expectedEnvironment) != len(observedEnvironment) || strings.Join(expectedEnvironment, "\x00") != strings.Join(observedEnvironment, "\x00") {
		return errors.New("container PID-1 environment differs from the bounded child environment")
	}
	return nil
}

func expectedContainerBinds(contract orchestrationContract) []string {
	result := []string{contract.RehearsalRoot + ":" + contract.RehearsalRoot + ":rw"}
	for _, path := range contract.ReadOnlyMounts {
		result = append(result, path+":"+path+":ro")
	}
	sort.Strings(result)
	return result
}

func expectedContainerCommand(contract orchestrationContract, contractPath, contractSHA string) []string {
	result := []string{"-i"}
	result = append(result, contract.ContainerRuntime.Environment...)
	return append(result, expectedRuntimeArgs(contract, contractPath, contractSHA)...)
}

func expectedRuntimeArgs(contract orchestrationContract, contractPath, contractSHA string) []string {
	return []string{
		contract.ContainerRuntime.Orchestrator.Path,
		"--mode", "orchestrate",
		"--contract", contractPath,
		"--expected-contract-sha", contractSHA,
	}
}

func runContainerPreflight(opts options) error {
	if os.Getpid() == 1 {
		return errors.New("stopped-container preflight must run on the host, not as container PID 1")
	}
	if opts.containerName == "" || opts.preflightOutput == "" || opts.contractPath == "" {
		return errors.New("preflight requires contract, container name, and output path")
	}
	if err := validateDigest(opts.expectedContractSHA); err != nil {
		return fmt.Errorf("preflight expected contract SHA-256 is required: %w", err)
	}
	contractBytes, contractSHA, err := readBoundFile(opts.contractPath, opts.expectedContractSHA)
	if err != nil {
		return err
	}
	var contract orchestrationContract
	if err = strictDecode(contractBytes, &contract); err != nil {
		return err
	}
	if err = validateContract(contract); err != nil {
		return err
	}
	selfSHA, err := currentExecutableSHA()
	if err != nil {
		return err
	}
	if err = validateHostPreflightSelfIdentity(os.Args[0], selfSHA, contract); err != nil {
		return err
	}
	if opts.containerName != contract.ContainerRuntime.Name || opts.preflightOutput != contract.ContainerPreflightPath {
		return errors.New("preflight invocation differs from orchestration contract")
	}
	inspectBytes, err := exec.Command("/usr/local/bin/docker", "inspect", "--type", "container", opts.containerName).Output()
	if err != nil {
		return fmt.Errorf("inspect stopped container: %w", err)
	}
	var containers []dockerContainerInspection
	if err = decodeExternalJSON(inspectBytes, &containers); err != nil || len(containers) != 1 {
		return errors.New("docker container inspection is not exactly one strict object")
	}
	imageBytes, err := exec.Command("/usr/local/bin/docker", "image", "inspect", contract.ContainerRuntime.ImageID).Output()
	if err != nil {
		return fmt.Errorf("inspect exact image: %w", err)
	}
	var images []dockerImageInspection
	if err = decodeExternalJSON(imageBytes, &images); err != nil || len(images) != 1 {
		return errors.New("docker image inspection is not exactly one strict object")
	}
	if err = validateStoppedContainerInspection(containers[0], images[0], contract, opts.contractPath, contractSHA); err != nil {
		return err
	}
	inspectDigest := sha256.Sum256(inspectBytes)
	imageDigest := sha256.Sum256(imageBytes)
	containerInspectPath, imageInspectPath := derivedRawInspectPaths(opts.preflightOutput)
	if err = writeExclusiveBytes(contract.RehearsalRoot, containerInspectPath, inspectBytes); err != nil {
		return err
	}
	if err = writeExclusiveBytes(contract.RehearsalRoot, imageInspectPath, imageBytes); err != nil {
		return err
	}
	evidence := containerPreflightEvidence{
		Schema:       "drwa.s1.prototype-network-identity-stopped-container-preflight.v1",
		Status:       "EXACT_STOPPED_CONTAINER_SUBSTRATE_VERIFIED_NO_PROCESS_NO_RUNTIME_CREDIT",
		TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano), ContractPath: opts.contractPath, ContractSHA256: contractSHA,
		ContainerName: opts.containerName, ContainerID: containers[0].ID,
		ContainerInspectSHA256: hex.EncodeToString(inspectDigest[:]), ImageInspectSHA256: hex.EncodeToString(imageDigest[:]),
		ContainerInspectPath: containerInspectPath, ImageInspectPath: imageInspectPath,
		ImageID: contract.ContainerRuntime.ImageID, ImageRepoDigest: contract.ContainerRuntime.ImageRepoDigest,
		Platform: contract.ContainerRuntime.Platform, ExactBinds: expectedContainerBinds(contract),
		SeccompProfilePath: contract.SeccompProfile.Path, SeccompProfileSHA256: contract.SeccompProfile.SHA256,
	}
	return writeExclusiveJSON(contract.RehearsalRoot, opts.preflightOutput, evidence)
}

func decodeExternalJSON(value []byte, destination interface{}) error {
	if err := rejectDuplicateJSONKeys(value); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("external JSON contains trailing value")
	}
	return nil
}

func validateStoppedContainerInspection(container dockerContainerInspection, image dockerImageInspection, contract orchestrationContract, contractPath, contractSHA string) error {
	runtime := contract.ContainerRuntime
	expectedCommand := expectedContainerCommand(contract, contractPath, contractSHA)
	if container.ID == "" || container.Name != "/"+runtime.Name || container.Image != runtime.ImageID ||
		container.Platform != "linux" || container.RestartCount != 0 || container.State.Status != "created" ||
		container.State.Running || container.State.PID != 0 || container.Config.Hostname != runtime.Hostname ||
		container.Config.User != fmt.Sprintf("%d:%d", runtime.UID, runtime.GID) || len(container.Config.Healthcheck) != 0 ||
		strings.Join(container.Config.Entrypoint, "\x00") != "/usr/bin/env" ||
		strings.Join(container.Config.Cmd, "\x00") != strings.Join(expectedCommand, "\x00") {
		return errors.New("stopped container identity/state/entrypoint differs from exact contract")
	}
	if container.HostConfig.NetworkMode != runtime.NetworkMode || (container.HostConfig.PIDMode != "" && container.HostConfig.PIDMode != runtime.PIDMode) ||
		container.HostConfig.AutoRemove != runtime.AutoRemove || container.HostConfig.ReadonlyRootfs != runtime.ReadOnlyRootFS ||
		container.HostConfig.Privileged || container.HostConfig.PublishAllPorts || len(container.HostConfig.PortBindings) != 0 ||
		container.HostConfig.RestartPolicy.Name != runtime.RestartPolicy || len(container.HostConfig.CapDrop) != 1 || container.HostConfig.CapDrop[0] != "ALL" ||
		len(container.HostConfig.CapAdd) != 0 || len(container.HostConfig.Devices) != 0 || len(container.HostConfig.DeviceRequests) != 0 ||
		len(container.HostConfig.DeviceCgroupRules) != 0 || container.HostConfig.IPCMode != "private" ||
		container.HostConfig.UTSMode != "" || container.HostConfig.UsernsMode != "" ||
		container.HostConfig.CgroupnsMode != "private" || container.HostConfig.Runtime != "runc" {
		return errors.New("stopped container host-isolation configuration differs")
	}
	if container.HostConfig.Init != nil && *container.HostConfig.Init {
		return errors.New("stopped container init process must be absent")
	}
	security := append([]string(nil), container.HostConfig.SecurityOpt...)
	sort.Strings(security)
	seccompBytes, _, seccompErr := readBoundFile(contract.SeccompProfile.Path, contract.SeccompProfile.SHA256)
	if seccompErr != nil {
		return fmt.Errorf("read exact seccomp profile for stopped inspection: %w", seccompErr)
	}
	var compactSeccomp bytes.Buffer
	if seccompErr = json.Compact(&compactSeccomp, seccompBytes); seccompErr != nil {
		return fmt.Errorf("compact exact seccomp profile: %w", seccompErr)
	}
	expectedSecurity := []string{"no-new-privileges", "seccomp=" + compactSeccomp.String()}
	sort.Strings(expectedSecurity)
	if strings.Join(security, "\x00") != strings.Join(expectedSecurity, "\x00") {
		return errors.New("stopped container security options do not bind the exact seccomp profile")
	}
	binds := append([]string(nil), container.HostConfig.Binds...)
	sort.Strings(binds)
	if strings.Join(binds, "\x00") != strings.Join(expectedContainerBinds(contract), "\x00") || len(container.Mounts) != len(binds) {
		return errors.New("stopped container user-mount cardinality differs")
	}
	observedMounts := make([]string, 0, len(container.Mounts))
	for _, mount := range container.Mounts {
		mode := "ro"
		if mount.RW {
			mode = "rw"
		}
		if mount.Type != "bind" || mount.Mode != mode {
			return errors.New("stopped container mount type/mode differs")
		}
		observedMounts = append(observedMounts, mount.Source+":"+mount.Destination+":"+mode)
	}
	sort.Strings(observedMounts)
	if strings.Join(observedMounts, "\x00") != strings.Join(expectedContainerBinds(contract), "\x00") {
		return errors.New("stopped container resolved mounts differ")
	}
	if image.ID != runtime.ImageID || image.OS+"/"+image.Architecture != runtime.Platform {
		return errors.New("container image ID/platform differs")
	}
	foundDigest := false
	for _, digest := range image.RepoDigests {
		if digest == runtime.ImageRepoDigest {
			foundDigest = true
		}
	}
	if !foundDigest {
		return errors.New("container image repo digest differs")
	}
	return nil
}

func verifyContainerPreflightEvidence(contract orchestrationContract, contractPath, contractSHA string) (string, error) {
	value, evidenceSHA, err := readBoundFile(contract.ContainerPreflightPath, "")
	if err != nil {
		return "", err
	}
	var evidence containerPreflightEvidence
	if err = strictDecode(value, &evidence); err != nil {
		return "", err
	}
	parsed, parseErr := time.Parse(time.RFC3339Nano, evidence.TimestampUTC)
	expectedContainerInspectPath, expectedImageInspectPath := derivedRawInspectPaths(contract.ContainerPreflightPath)
	if parseErr != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != evidence.TimestampUTC ||
		evidence.Schema != "drwa.s1.prototype-network-identity-stopped-container-preflight.v1" ||
		evidence.Status != "EXACT_STOPPED_CONTAINER_SUBSTRATE_VERIFIED_NO_PROCESS_NO_RUNTIME_CREDIT" ||
		evidence.ContractPath != contractPath || evidence.ContractSHA256 != contractSHA ||
		evidence.ContainerName != contract.ContainerRuntime.Name || validateDigest(evidence.ContainerID) != nil ||
		evidence.ImageID != contract.ContainerRuntime.ImageID || evidence.ImageRepoDigest != contract.ContainerRuntime.ImageRepoDigest ||
		evidence.Platform != contract.ContainerRuntime.Platform || evidence.SeccompProfilePath != contract.SeccompProfile.Path ||
		evidence.SeccompProfileSHA256 != contract.SeccompProfile.SHA256 || evidence.AuthoritativeCredit != 0 ||
		evidence.ContainerInspectPath != expectedContainerInspectPath || evidence.ImageInspectPath != expectedImageInspectPath ||
		validateDigest(evidence.ContainerInspectSHA256) != nil || validateDigest(evidence.ImageInspectSHA256) != nil {
		return "", errors.New("stopped-container preflight evidence differs from exact contract")
	}
	expectedBinds := expectedContainerBinds(contract)
	observedBinds := append([]string(nil), evidence.ExactBinds...)
	sort.Strings(observedBinds)
	if strings.Join(observedBinds, "\x00") != strings.Join(expectedBinds, "\x00") {
		return "", errors.New("stopped-container preflight bind set differs")
	}
	containerRaw, _, err := readBoundFile(evidence.ContainerInspectPath, evidence.ContainerInspectSHA256)
	if err != nil {
		return "", fmt.Errorf("raw container inspection: %w", err)
	}
	imageRaw, _, err := readBoundFile(evidence.ImageInspectPath, evidence.ImageInspectSHA256)
	if err != nil {
		return "", fmt.Errorf("raw image inspection: %w", err)
	}
	var containers []dockerContainerInspection
	var images []dockerImageInspection
	if err = decodeExternalJSON(containerRaw, &containers); err != nil || len(containers) != 1 {
		return "", errors.New("retained raw container inspection is not exactly one valid object")
	}
	if err = decodeExternalJSON(imageRaw, &images); err != nil || len(images) != 1 {
		return "", errors.New("retained raw image inspection is not exactly one valid object")
	}
	if containers[0].ID != evidence.ContainerID {
		return "", errors.New("retained raw container ID differs from preflight summary")
	}
	if err = validateStoppedContainerInspection(containers[0], images[0], contract, contractPath, contractSHA); err != nil {
		return "", fmt.Errorf("retained raw stopped-container semantics: %w", err)
	}
	return evidenceSHA, nil
}

func derivedRawInspectPaths(preflightPath string) (string, string) {
	base := strings.TrimSuffix(preflightPath, filepath.Ext(preflightPath))
	return base + ".container-inspect.raw.json", base + ".image-inspect.raw.json"
}

func verifyRuntimeSelf(contract orchestrationContract, contractPath, observedContractSHA string) error {
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	selfSHA, err := currentExecutableSHA()
	if err != nil {
		return err
	}
	return validateRuntimeSelfSnapshot(runtimeSelfSnapshot{
		UID: os.Getuid(), GID: os.Getgid(), Hostname: hostname, SelfSHA: selfSHA,
		Args: append([]string(nil), os.Args...), Env: os.Environ(),
	}, contract, contractPath, observedContractSHA)
}

func currentExecutableSHA() (string, error) {
	selfFile, err := os.Open("/proc/self/exe")
	if err != nil {
		return "", err
	}
	defer selfFile.Close()
	hasher := sha256.New()
	if _, err = io.Copy(hasher, selfFile); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func validateHostPreflightSelfIdentity(argv0, selfSHA string, contract orchestrationContract) error {
	if argv0 != contract.ContainerRuntime.Orchestrator.Path || selfSHA != contract.ContainerRuntime.Orchestrator.SHA256 {
		return errors.New("host preflight executable differs from exact orchestrator binary")
	}
	return nil
}

func validateRuntimeSelfSnapshot(snapshot runtimeSelfSnapshot, contract orchestrationContract, contractPath, observedContractSHA string) error {
	if snapshot.UID != contract.ContainerRuntime.UID || snapshot.GID != contract.ContainerRuntime.GID {
		return errors.New("runtime uid/gid differs from container contract")
	}
	if snapshot.Hostname != contract.ContainerRuntime.Hostname {
		return errors.New("runtime hostname differs from container contract")
	}
	if snapshot.SelfSHA != contract.ContainerRuntime.Orchestrator.SHA256 {
		return errors.New("runtime orchestrator self identity differs")
	}
	expectedArgs := expectedRuntimeArgs(contract, contractPath, observedContractSHA)
	if len(snapshot.Args) != len(expectedArgs) || strings.Join(snapshot.Args, "\x00") != strings.Join(expectedArgs, "\x00") {
		return errors.New("runtime argv differs from exact orchestrator invocation")
	}
	expectedEnv := append([]string(nil), contract.ContainerRuntime.Environment...)
	observedEnv := append([]string(nil), snapshot.Env...)
	sort.Strings(expectedEnv)
	sort.Strings(observedEnv)
	if len(expectedEnv) != len(observedEnv) || strings.Join(expectedEnv, "\x00") != strings.Join(observedEnv, "\x00") {
		return errors.New("runtime environment differs from exact container contract")
	}
	return nil
}

func executeRehearsal(contract orchestrationContract, contractPath, contractSHA, containerPreflightSHA string) (runErr error) {
	planBytes, planSHA, err := readBoundFile(contract.MigrationPlan.Path, contract.MigrationPlan.SHA256)
	if err != nil {
		return fmt.Errorf("migration plan: %w", err)
	}
	var plan migrationPlan
	if err = strictDecode(planBytes, &plan); err != nil {
		return err
	}
	if err = validatePlanAgainstContract(plan, contract); err != nil {
		return err
	}
	summaryBytes, summarySHA, err := readBoundFile(contract.WriterSummary.Path, contract.WriterSummary.SHA256)
	if err != nil {
		return fmt.Errorf("writer summary: %w", err)
	}
	var writer writerSummary
	if err = strictDecode(summaryBytes, &writer); err != nil {
		return err
	}
	_, journalSHA, err := readBoundFile(contract.WriterJournal.Path, contract.WriterJournal.SHA256)
	if err != nil {
		return fmt.Errorf("writer journal: %w", err)
	}
	if err = verifyWriterArtifactBindings(contract); err != nil {
		return err
	}
	if err = validateWriterEvidence(writer, plan, contract, planSHA, journalSHA); err != nil {
		return err
	}

	nodeBinary, err := openSealedFile(contract.NodeBinary)
	if err != nil {
		return fmt.Errorf("node binary: %w", err)
	}
	defer nodeBinary.Close()
	seedBinary, err := openSealedFile(contract.SeedBinary)
	if err != nil {
		return fmt.Errorf("seed binary: %w", err)
	}
	defer seedBinary.Close()
	traceLoader, err := openSealedFile(contract.TraceLoader)
	if err != nil {
		return fmt.Errorf("trace loader: %w", err)
	}
	defer traceLoader.Close()
	traceBinary, err := openSealedFile(contract.TraceBinary)
	if err != nil {
		return fmt.Errorf("trace binary: %w", err)
	}
	defer traceBinary.Close()
	if err = verifyArtifactCollections(contract); err != nil {
		return err
	}
	if err = verifySeccompProfile(contract.SeccompProfile); err != nil {
		return err
	}
	if err = verifyEveryStoredIdentity(plan); err != nil {
		return err
	}

	journal, err := openExclusiveOutput(contract.RehearsalRoot, contract.JournalPath)
	if err != nil {
		return fmt.Errorf("reserve orchestration journal: %w", err)
	}
	defer journal.Close()
	sequence := 0
	completed := make([]string, 0, 8)
	appendEvent := func(status, detail string) error {
		sequence++
		event := journalEvent{
			Schema: "drwa.s1.prototype-network-identity-orchestration-journal.v1", Sequence: sequence,
			TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano), Status: status,
			Completed: append([]string(nil), completed...), Detail: detail,
		}
		encoded, marshalErr := json.Marshal(event)
		if marshalErr != nil {
			return marshalErr
		}
		if _, writeErr := journal.Write(append(encoded, '\n')); writeErr != nil {
			return writeErr
		}
		return journal.Sync()
	}
	if err = appendEvent("ATTEMPT_RESERVED_NO_PROCESS_LAUNCHED", ""); err != nil {
		return err
	}
	var deferredCleanupErr error
	defer func() {
		if runErr != nil {
			status := "ATTEMPT_FAILED_ALL_STARTED_PROCESSES_STOPPED_NO_LIVE_CREDIT"
			if deferredCleanupErr != nil {
				status = "ATTEMPT_FAILED_PROCESS_CLEANUP_INCOMPLETE_NO_LIVE_CREDIT"
			}
			_ = appendEvent(status, runErr.Error())
		}
	}()
	if _, statErr := os.Lstat(contract.EvidencePath); !errors.Is(statErr, os.ErrNotExist) {
		if statErr == nil {
			return errors.New("orchestration evidence path already exists")
		}
		return statErr
	}

	specs, err := deriveNodeSpecs(plan, contract)
	if err != nil {
		return err
	}
	traceDir := filepath.Join(contract.RehearsalRoot, "artifacts", "network-traces")
	logDir := filepath.Join(contract.RehearsalRoot, "artifacts", "node-logs")
	if err = createExactEmptyDirectory(traceDir); err != nil {
		return err
	}
	if err = createExactEmptyDirectory(logDir); err != nil {
		return err
	}

	launcher := processLauncher{
		contract: contract, nodeBinary: nodeBinary, seedBinary: seedBinary,
		traceLoader: traceLoader, traceBinary: traceBinary, traceDir: traceDir, logDir: logDir,
	}
	var allProcesses []*runningProcess
	defer func() {
		_, cleanupErr := stopProcesses(allProcesses, time.Duration(contract.ShutdownTimeoutSeconds)*time.Second, false)
		if cleanupErr != nil {
			deferredCleanupErr = cleanupErr
			if runErr == nil {
				runErr = fmt.Errorf("deferred process cleanup: %w", cleanupErr)
			} else {
				runErr = fmt.Errorf("%v; deferred process cleanup: %w", runErr, cleanupErr)
			}
		}
	}()
	seed, err := launcher.startSeed()
	if err != nil {
		return err
	}
	allProcesses = append(allProcesses, seed)
	completed = append(completed, "SEED_LAUNCHED")
	if err = appendEvent("SEED_LAUNCHED", ""); err != nil {
		return err
	}

	first, err := launcher.startNodes(specs, "first")
	allProcesses = append(allProcesses, first...)
	if err != nil {
		return err
	}
	firstSnapshot, err := waitForAdvancingHealth(specs, plan.ChainID, contract.ExpectedGenesisTimestamp, nil, time.Duration(contract.HealthTimeoutSeconds)*time.Second)
	if err != nil {
		return err
	}
	if err = verifyIdentityLogs(first, contract); err != nil {
		return err
	}
	completed = append(completed, "FIRST_START_HEALTH_AND_IDENTITY")
	if err = appendEvent("FIRST_START_HEALTH_AND_IDENTITY_VERIFIED", ""); err != nil {
		return err
	}
	firstStopped, err := stopProcesses(first, time.Duration(contract.ShutdownTimeoutSeconds)*time.Second, true)
	if err != nil {
		return err
	}
	completed = append(completed, "FIRST_CLEAN_SHUTDOWN")
	if err = appendEvent("FIRST_CLEAN_SHUTDOWN_VERIFIED", ""); err != nil {
		return err
	}

	second, err := launcher.startNodes(specs, "second")
	allProcesses = append(allProcesses, second...)
	if err != nil {
		return err
	}
	secondSnapshot, err := waitForAdvancingHealth(specs, plan.ChainID, contract.ExpectedGenesisTimestamp, firstSnapshot.Anchors, time.Duration(contract.HealthTimeoutSeconds)*time.Second)
	if err != nil {
		return err
	}
	if err = verifyIdentityLogs(second, contract); err != nil {
		return err
	}
	if err = equalAnchors(firstSnapshot.Anchors, secondSnapshot.Anchors); err != nil {
		return err
	}
	completed = append(completed, "SECOND_START_HEALTH_IDENTITY_NO_DRIFT")
	if err = appendEvent("SECOND_START_HEALTH_IDENTITY_NO_DRIFT_VERIFIED", ""); err != nil {
		return err
	}

	crashed, survivors, err := splitCrashProcess(second, contract.CrashNodeID)
	if err != nil {
		return err
	}
	if err = killProcess(crashed, time.Duration(contract.ShutdownTimeoutSeconds)*time.Second); err != nil {
		return err
	}
	restarted, err := launcher.startNode(specByID(specs, contract.CrashNodeID), "post-crash")
	if err != nil {
		return err
	}
	allProcesses = append(allProcesses, restarted)
	postCrashSnapshot, err := waitForAdvancingHealth(specs, plan.ChainID, contract.ExpectedGenesisTimestamp, firstSnapshot.Anchors, time.Duration(contract.HealthTimeoutSeconds)*time.Second)
	if err != nil {
		return err
	}
	if err = verifyIdentityLogs([]*runningProcess{restarted}, contract); err != nil {
		return err
	}
	if err = equalAnchors(firstSnapshot.Anchors, postCrashSnapshot.Anchors); err != nil {
		return err
	}
	completed = append(completed, "CRASH_RESTART_HEALTH_IDENTITY_NO_DRIFT")
	if err = appendEvent("CRASH_RESTART_HEALTH_IDENTITY_NO_DRIFT_VERIFIED", ""); err != nil {
		return err
	}
	secondActive := append(survivors, restarted)
	secondStopped, err := stopProcesses(secondActive, time.Duration(contract.ShutdownTimeoutSeconds)*time.Second, true)
	if err != nil {
		return err
	}
	seedStopped, err := stopProcesses([]*runningProcess{seed}, time.Duration(contract.ShutdownTimeoutSeconds)*time.Second, true)
	if err != nil {
		return err
	}
	if len(seedStopped) != 1 || seedStopped[0] != "seed" {
		return errors.New("seed clean-shutdown evidence is incomplete")
	}
	completed = append(completed, "ALL_PROCESSES_BOUNDED_STOP")
	if err = appendEvent("ALL_PROCESSES_BOUNDED_STOP_VERIFIED", ""); err != nil {
		return err
	}

	for _, executable := range []*sealedFile{nodeBinary, seedBinary, traceLoader, traceBinary} {
		if err = executable.verifyUnchanged(); err != nil {
			return err
		}
	}
	if err = verifyArtifactCollections(contract); err != nil {
		return err
	}
	if err = verifySeccompProfile(contract.SeccompProfile); err != nil {
		return err
	}
	traceHashes, err := verifyAndHashTraces(traceDir, expectedTracePrefixes(specs, contract.CrashNodeID))
	if err != nil {
		return err
	}
	logHashes, err := hashRegularFiles(logDir)
	if err != nil {
		return err
	}
	completed = append(completed, "NETWORK_TRACE_LOOPBACK_ONLY")
	if err = appendEvent("NETWORK_TRACE_LOOPBACK_ONLY_VERIFIED", ""); err != nil {
		return err
	}

	evidence := rehearsalEvidence{
		Schema:       "drwa.s1.prototype-network-identity-isolated-rehearsal.v1",
		Status:       "ISOLATED_SIXTEEN_NODE_START_RESTART_CRASH_RECOVERY_VERIFIED_NO_LIVE_OR_RUNTIME_CREDIT",
		TimestampUTC: time.Now().UTC().Format(time.RFC3339Nano), ContractPath: contractPath, ContractSHA256: contractSHA,
		MigrationPlanSHA256: planSHA, WriterSummarySHA256: summarySHA, WriterJournalSHA256: journalSHA,
		WriterIsolationContractSHA: contract.WriterIsolationContract.SHA256,
		WriterBinarySHA256:         contract.WriterBinary.SHA256,
		WriterIdentityToolSHA256:   contract.WriterIdentityTool.SHA256,
		WriterStoppedPreflightSHA:  contract.WriterStoppedPreflight.SHA256,
		WriterContainerEventsSHA:   contract.WriterContainerEvents.SHA256,
		WriterPostRunStateSHA:      contract.WriterPostRunState.SHA256,
		WriterLogsEvidenceSHA:      contract.WriterLogsEvidence.SHA256,
		ContainerPreflightSHA256:   containerPreflightSHA,
		NodeBinarySHA256:           nodeBinary.sha, CanonicalMetachainHash: plan.CanonicalHash, NetworkDomain: plan.NetworkDomain,
		OrchestratorBinarySHA256: contract.ContainerRuntime.Orchestrator.SHA256,
		ContainerImageID:         contract.ContainerRuntime.ImageID, ContainerImageRepoDigest: contract.ContainerRuntime.ImageRepoDigest,
		ContainerPlatform: contract.ContainerRuntime.Platform, ContainerName: contract.ContainerRuntime.Name,
		ContainerUID: contract.ContainerRuntime.UID, ContainerGID: contract.ContainerRuntime.GID,
		SeccompProfileSHA256: contract.SeccompProfile.SHA256,
		RuntimeLibraryFiles:  artifactHashMap(contract.RuntimeLibraries), ChildEnvironment: append([]string(nil), contract.ChildEnvironment...),
		IdentityProvenance: contract.IdentityProvenance, FirstStart: firstSnapshot, SecondStart: secondSnapshot,
		PostCrashRestart: postCrashSnapshot, CleanShutdowns: map[string][]string{"first": firstStopped, "second": secondStopped, "final": seedStopped},
		CrashNodeID: contract.CrashNodeID, TraceFiles: traceHashes, LogFiles: logHashes,
		EveryIdentityLogMatched: true, AllConnectBindLoopbackOnly: true, NoStateRootDrift: true,
		AuthoritativeRuntimeCredit: 0,
	}
	if err = writeExclusiveJSON(contract.RehearsalRoot, contract.EvidencePath, evidence); err != nil {
		return err
	}
	completed = append(completed, "FINAL_EVIDENCE")
	return appendEvent("REHEARSAL_COMPLETE_NO_LIVE_OR_RUNTIME_CREDIT", "")
}

func verifyWriterArtifactBindings(contract orchestrationContract) error {
	for name, artifact := range map[string]boundArtifact{
		"writer isolation contract": contract.WriterIsolationContract,
		"writer binary":             contract.WriterBinary,
		"writer identity tool":      contract.WriterIdentityTool,
		"writer stopped preflight":  contract.WriterStoppedPreflight,
		"writer container events":   contract.WriterContainerEvents,
		"writer post-run state":     contract.WriterPostRunState,
		"writer logs evidence":      contract.WriterLogsEvidence,
	} {
		if _, _, err := readBoundFile(artifact.Path, artifact.SHA256); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

type processLauncher struct {
	contract                                         orchestrationContract
	nodeBinary, seedBinary, traceLoader, traceBinary *sealedFile
	traceDir, logDir                                 string
	startNodeOverride                                func(nodeSpec, string) (*runningProcess, error)
}

func (launcher processLauncher) startSeed() (*runningProcess, error) {
	return launcher.start("seed", launcher.seedBinary, nil, launcher.contract.SeedRoot, "seed")
}

func (launcher processLauncher) startNodes(specs []nodeSpec, phase string) ([]*runningProcess, error) {
	result := make([]*runningProcess, 0, len(specs))
	for _, spec := range specs {
		var process *runningProcess
		var err error
		if launcher.startNodeOverride != nil {
			process, err = launcher.startNodeOverride(spec, phase)
		} else {
			process, err = launcher.startNode(spec, phase)
		}
		if err != nil {
			return result, err
		}
		result = append(result, process)
	}
	return result, nil
}

func (launcher processLauncher) startNode(spec nodeSpec, phase string) (*runningProcess, error) {
	if err := validateExactDirectoryIdentity(spec.Work, spec.WorkRootDevice, spec.WorkRootInode); err != nil {
		return nil, fmt.Errorf("node %s work root changed before %s launch: %w", spec.ID, phase, err)
	}
	return launcher.start(spec.ID, launcher.nodeBinary, spec.Args, launcher.contract.NodeBase, phase)
}

func (launcher processLauncher) start(id string, executable *sealedFile, args []string, cwd, phase string) (*runningProcess, error) {
	for _, sealed := range []*sealedFile{launcher.traceLoader, launcher.traceBinary, executable} {
		if err := sealed.verifyUnchanged(); err != nil {
			return nil, err
		}
	}
	prefix := filepath.Join(launcher.traceDir, phase+"-"+id)
	stdoutPath := filepath.Join(launcher.logDir, phase+"-"+id+".log")
	stdout, err := os.OpenFile(stdoutPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	traceArgs := []string{
		"--library-path", launcher.contract.TraceLibraryDirectory, "/proc/self/fd/4",
		"-ff", "-qq", "-s", "256", "-e", "trace=connect,bind", "-o", prefix, "/proc/self/fd/5",
	}
	traceArgs = append(traceArgs, args...)
	command := exec.Command("/proc/self/fd/3", traceArgs...)
	command.ExtraFiles = []*os.File{launcher.traceLoader.file, launcher.traceBinary.file, executable.file}
	command.Dir = cwd
	command.Env = append([]string(nil), launcher.contract.ChildEnvironment...)
	command.Stdin = nil
	command.Stdout = stdout
	command.Stderr = stdout
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err = command.Start(); err != nil {
		_ = stdout.Close()
		return nil, err
	}
	process := &runningProcess{
		ID: id, cmd: command, groupID: command.Process.Pid, done: make(chan error, 1),
		stdout: stdout, tracePrefix: prefix, targetPIDFD: -1,
	}
	go func() {
		waitErr := command.Wait()
		_ = stdout.Sync()
		_ = stdout.Close()
		process.done <- waitErr
	}()
	targetPID, targetPIDFD, alreadyReaped, err := waitForTracedTarget(command.Process.Pid, executable, process.done, 5*time.Second)
	if err != nil {
		var cleanupErr error
		if !alreadyReaped {
			cleanupErr = terminateUnboundProcess(process, 5*time.Second)
		}
		return nil, errors.Join(fmt.Errorf("bind exact traced child %s: %w", id, err), cleanupErr)
	}
	process.targetPID = targetPID
	process.targetPIDFD = targetPIDFD
	return process, nil
}

func terminateUnboundProcess(process *runningProcess, timeout time.Duration) error {
	if process == nil || process.groupID <= 0 {
		return errors.New("unbound process has no valid process group")
	}
	killErr := syscall.Kill(-process.groupID, syscall.SIGKILL)
	if killErr != nil && !errors.Is(killErr, syscall.ESRCH) {
		return fmt.Errorf("kill unbound process group: %w", killErr)
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-process.done:
		process.crashed = true
		return nil
	case <-timer.C:
		return errors.New("unbound process group was not reaped within bounded timeout")
	}
}

func waitForTracedTarget(tracerPID int, executable *sealedFile, done <-chan error, timeout time.Duration) (int, int, bool, error) {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	childrenPath := fmt.Sprintf("/proc/%d/task/%d/children", tracerPID, tracerPID)
	for {
		select {
		case waitErr := <-done:
			return 0, -1, true, fmt.Errorf("tracer exited before target binding: %v", waitErr)
		case <-deadline.C:
			return 0, -1, false, errors.New("bounded timeout waiting for exact traced child")
		case <-ticker.C:
			childrenBytes, err := os.ReadFile(childrenPath)
			if err != nil {
				continue
			}
			fields := strings.Fields(string(childrenBytes))
			if len(fields) == 0 {
				continue
			}
			if len(fields) != 1 {
				return 0, -1, false, fmt.Errorf("tracer has %d direct children, expected one", len(fields))
			}
			pid, err := strconv.Atoi(fields[0])
			if err != nil || pid <= 0 {
				return 0, -1, false, errors.New("traced child PID is invalid")
			}
			info, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
			if err != nil {
				continue
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || uint64(stat.Dev) != executable.device || stat.Ino != executable.inode {
				continue
			}
			pidFD, err := unix.PidfdOpen(pid, 0)
			if err != nil {
				return 0, -1, false, fmt.Errorf("open traced-child pidfd: %w", err)
			}
			return pid, pidFD, false, nil
		}
	}
}

func validatePlanAgainstContract(plan migrationPlan, contract orchestrationContract) error {
	if plan.Schema != planSchema || plan.Status != "READY_OFFLINE_REHEARSAL_NO_LIVE_AUTHORIZATION" ||
		plan.ChainID == "" || plan.CanonicalHash != contract.CanonicalMetachainHash ||
		plan.NetworkDomain != contract.NetworkDomain || plan.RehearsalRoot != contract.RehearsalRoot || len(plan.Nodes) != 16 {
		return errors.New("migration plan differs from orchestration contract")
	}
	if err := validateDigest(plan.CanonicalHash); err != nil {
		return err
	}
	if err := validateDigest(plan.NetworkDomain); err != nil {
		return err
	}
	created, err := time.Parse(time.RFC3339Nano, plan.CreatedUTC)
	if err != nil || created.Location() != time.UTC || created.Format(time.RFC3339Nano) != plan.CreatedUTC {
		return errors.New("migration plan timestamp is not canonical UTC")
	}
	if plan.CandidateBinaryPath != contract.NodeBinary.Path || plan.CandidateBinarySHA256 != contract.NodeBinary.SHA256 {
		return errors.New("migration-plan node binary differs from the orchestration contract")
	}
	for _, config := range []struct {
		name, path, expectedSHA, planSourcePath, nodeBasePath string
	}{
		{name: "validator config", path: plan.ValidatorConfigPath, expectedSHA: plan.ValidatorConfigSHA256, planSourcePath: filepath.Join(contract.RehearsalRoot, "artifacts", "config_validator.toml"), nodeBasePath: filepath.Join(contract.NodeBase, "config", "config_validator.toml")},
		{name: "observer config", path: plan.ObserverConfigPath, expectedSHA: plan.ObserverConfigSHA256, planSourcePath: filepath.Join(contract.RehearsalRoot, "artifacts", "config_observer.toml"), nodeBasePath: filepath.Join(contract.NodeBase, "config", "config_observer.toml")},
	} {
		if filepath.Clean(config.path) != filepath.Clean(config.planSourcePath) {
			return fmt.Errorf("migration-plan %s path differs from the exact staged source path", config.name)
		}
		_, observedSHA, readErr := readBoundFile(config.path, config.expectedSHA)
		boundSHA, exists := boundArtifactSHA(contract.NodeBaseFiles, config.nodeBasePath)
		if readErr != nil || !exists || observedSHA != boundSHA {
			return fmt.Errorf("migration-plan %s differs from the exact node-base bytes", config.name)
		}
	}
	boundNodesSetupSHA, exists := boundArtifactSHA(contract.NodeBaseFiles, filepath.Join(contract.NodeBase, "config", "nodesSetup.json"))
	if !exists || boundNodesSetupSHA != plan.NodesSetupSHA256 {
		return errors.New("migration-plan nodes setup differs from the exact node-base bytes")
	}
	seen := make(map[string]struct{})
	crashFound := false
	for _, node := range plan.Nodes {
		if _, exists := seen[node.ID]; exists || !pathWithin(plan.RehearsalRoot, node.NodeRoot) ||
			!pathWithin(node.NodeRoot, node.TargetDBPath) || (node.Role != "observer" && node.Role != "validator") ||
			node.SourceRootDevice == 0 || node.SourceRootInode == 0 || node.NodeRootDevice == 0 || node.NodeRootInode == 0 {
			return fmt.Errorf("invalid or duplicate plan node %s", node.ID)
		}
		expectedRoot := filepath.Join(plan.RehearsalRoot, "work", node.ID)
		if filepath.Clean(node.NodeRoot) != expectedRoot {
			return fmt.Errorf("plan node %s root is not the exact rehearsal work root", node.ID)
		}
		expectedTarget := filepath.Join(expectedRoot, "db", plan.ChainID, "Static", "Shard_"+node.ShardID, "PrototypeNetworkIdentityStorageDB")
		if filepath.Clean(node.TargetDBPath) != expectedTarget {
			return fmt.Errorf("plan node %s target is not the exact identity-store path", node.ID)
		}
		if err := validateExactDirectoryIdentity(node.NodeRoot, node.NodeRootDevice, node.NodeRootInode); err != nil {
			return fmt.Errorf("plan node %s root: %w", node.ID, err)
		}
		canonicalTarget, canonicalErr := canonicalNoSymlinkExisting(node.TargetDBPath)
		if canonicalErr != nil || canonicalTarget != filepath.Clean(node.TargetDBPath) {
			return fmt.Errorf("plan node %s target is not canonical/no-symlink: %w", node.ID, canonicalErr)
		}
		seen[node.ID] = struct{}{}
		if node.ID == contract.CrashNodeID {
			crashFound = node.Role == "validator"
		}
	}
	if !crashFound {
		return errors.New("crash node is not an exact validator plan node")
	}
	if _, err := deriveNodeSpecs(plan, contract); err != nil {
		return fmt.Errorf("exact 16-node topology: %w", err)
	}
	return nil
}

func boundArtifactSHA(artifacts []boundArtifact, expectedPath string) (string, bool) {
	for _, artifact := range artifacts {
		if artifact.Path == expectedPath {
			return artifact.SHA256, true
		}
	}
	return "", false
}

func artifactHashMap(artifacts []boundArtifact) map[string]string {
	result := make(map[string]string, len(artifacts))
	for _, artifact := range artifacts {
		result[artifact.Path] = artifact.SHA256
	}
	return result
}

func validateExactDirectoryIdentity(path string, expectedDevice, expectedInode uint64) error {
	canonical, err := canonicalNoSymlinkExisting(path)
	if err != nil || canonical != filepath.Clean(path) {
		return fmt.Errorf("path is not canonical/no-symlink: %w", err)
	}
	info, err := os.Stat(canonical)
	if err != nil || info == nil || !info.IsDir() {
		return errors.New("path is not an existing directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || expectedDevice == 0 || expectedInode == 0 || uint64(stat.Dev) != expectedDevice || stat.Ino != expectedInode {
		return errors.New("filesystem identity changed")
	}
	return nil
}

func validateWriterEvidence(writer writerSummary, plan migrationPlan, contract orchestrationContract, planSHA, journalSHA string) error {
	if writer.Schema != "drwa.s1.prototype-network-identity-offline-rehearsal.v1" ||
		writer.Status != "ALL_SIXTEEN_EMERGENCY_IDENTITIES_DURABLE_NO_NODE_LAUNCHED_NO_RUNTIME_CREDIT" ||
		writer.PlanPath != contract.MigrationPlan.Path || writer.PlanSHA256 != planSHA ||
		writer.IdentityToolPath != contract.WriterIdentityTool.Path || writer.IdentityToolSHA256 != contract.WriterIdentityTool.SHA256 ||
		writer.IsolationContractPath != contract.WriterIsolationContract.Path || writer.IsolationContractSHA256 != contract.WriterIsolationContract.SHA256 ||
		writer.JournalPath != contract.WriterJournal.Path || writer.JournalSHA256 != journalSHA ||
		writer.CanonicalMetachainHash != plan.CanonicalHash || writer.NetworkDomain != plan.NetworkDomain ||
		writer.Provenance != networkidentity.EmergencyMigration.String() ||
		!writer.DurableCloseReopenVerified || writer.AuthoritativeRuntimeCredit != 0 || len(writer.CompletedNodes) != 16 {
		return errors.New("writer evidence does not close the exact offline mutation boundary")
	}
	parsedTimestamp, err := time.Parse(time.RFC3339Nano, writer.TimestampUTC)
	if err != nil || parsedTimestamp.Location() != time.UTC || parsedTimestamp.Format(time.RFC3339Nano) != writer.TimestampUTC {
		return errors.New("writer evidence timestamp is invalid")
	}
	expected := make([]string, 0, len(plan.Nodes))
	for _, node := range plan.Nodes {
		expected = append(expected, node.ID)
	}
	sort.Strings(expected)
	observed := append([]string(nil), writer.CompletedNodes...)
	sort.Strings(observed)
	if strings.Join(expected, "\x00") != strings.Join(observed, "\x00") {
		return errors.New("writer completed-node set differs from migration plan")
	}
	return nil
}

func deriveNodeSpecs(plan migrationPlan, contract orchestrationContract) ([]nodeSpec, error) {
	byID := make(map[string]migrationPlanNode, len(plan.Nodes))
	for _, node := range plan.Nodes {
		byID[node.ID] = node
	}
	result := make([]nodeSpec, 0, 16)
	observerShards := []uint32{0, 1, 2, metaShard}
	for index, shard := range observerShards {
		id := fmt.Sprintf("observer%d", index)
		node, ok := byID[id]
		if !ok || node.Role != "observer" || parseShard(node.ShardID) != shard {
			return nil, fmt.Errorf("observer topology mismatch for %s", id)
		}
		destination := strconv.FormatUint(uint64(shard), 10)
		if shard == metaShard {
			destination = "metachain"
		}
		work := filepath.Join(contract.RehearsalRoot, "work", id)
		if node.NodeRoot != work {
			return nil, fmt.Errorf("node root mismatch for %s", id)
		}
		result = append(result, nodeSpec{
			ID: id, Role: "observer", ShardID: shard, REST: uint16(10000 + index), Work: work,
			WorkRootDevice: node.NodeRootDevice, WorkRootInode: node.NodeRootInode,
			Args: []string{
				"-port", strconv.Itoa(21100 + index), "--profile-mode", "-log-save", "-log-level", "*:INFO",
				"--log-logger-name", "--log-correlation", "--use-health-service", "-rest-api-interface",
				fmt.Sprintf("localhost:%d", 10000+index), "-destination-shard-as-observer", destination,
				"-validator-key-pem-file", "./config/validatorKey.pem", "-sk-index", strconv.Itoa(15 - index),
				"-working-directory", work, "-config", "./config/config_observer.toml", "-operation-mode", "db-lookup-extension",
			},
		})
	}
	validatorShards := []uint32{metaShard, metaShard, metaShard, 0, 0, 0, 1, 1, 1, 2, 2, 2}
	for index, shard := range validatorShards {
		id := fmt.Sprintf("validator%d", index)
		node, ok := byID[id]
		if !ok || node.Role != "validator" || parseShard(node.ShardID) != shard {
			return nil, fmt.Errorf("validator topology mismatch for %s", id)
		}
		work := filepath.Join(contract.RehearsalRoot, "work", id)
		if node.NodeRoot != work {
			return nil, fmt.Errorf("node root mismatch for %s", id)
		}
		result = append(result, nodeSpec{
			ID: id, Role: "validator", ShardID: shard, REST: uint16(9500 + index), Work: work,
			WorkRootDevice: node.NodeRootDevice, WorkRootInode: node.NodeRootInode,
			Args: []string{
				"-port", strconv.Itoa(21500 + index), "--profile-mode", "-log-save", "-log-level", "*:INFO",
				"--log-logger-name", "--log-correlation", "--use-health-service", "-rest-api-interface",
				fmt.Sprintf("localhost:%d", 9500+index), "-sk-index", strconv.Itoa(index), "-working-directory", work,
				"-config", "./config/config_validator.toml",
			},
		})
	}
	return result, nil
}

func verifyEveryStoredIdentity(plan migrationPlan) error {
	for _, node := range plan.Nodes {
		if err := validateExactDirectoryIdentity(node.NodeRoot, node.NodeRootDevice, node.NodeRootInode); err != nil {
			return fmt.Errorf("revalidate identity DB root %s: %w", node.ID, err)
		}
		canonicalTarget, err := canonicalNoSymlinkExisting(node.TargetDBPath)
		if err != nil || canonicalTarget != filepath.Clean(node.TargetDBPath) {
			return fmt.Errorf("revalidate identity DB target %s: %w", node.ID, err)
		}
		db, err := leveldb.OpenFile(node.TargetDBPath, &opt.Options{ReadOnly: true, ErrorIfMissing: true})
		if err != nil {
			return fmt.Errorf("open identity DB %s: %w", node.ID, err)
		}
		expectedKey := networkidentity.Key(plan.CanonicalEpoch)
		stored, getErr := db.Get(expectedKey, nil)
		iterator := db.NewIterator(nil, nil)
		logicalEntries := 0
		exactEntry := false
		for iterator.Next() {
			logicalEntries++
			if bytes.Equal(iterator.Key(), expectedKey) && bytes.Equal(iterator.Value(), stored) {
				exactEntry = true
			}
		}
		iteratorErr := iterator.Error()
		iterator.Release()
		closeErr := db.Close()
		if getErr != nil {
			return fmt.Errorf("read identity DB %s: %w", node.ID, getErr)
		}
		if iteratorErr != nil || logicalEntries != 1 || !exactEntry {
			return fmt.Errorf("identity DB %s does not contain exactly the expected logical entry", node.ID)
		}
		if closeErr != nil {
			return closeErr
		}
		record, decodeErr := networkidentity.Decode(stored, []byte(plan.ChainID))
		if decodeErr != nil || record.SchemaVersion != networkidentity.Version ||
			record.Epoch != plan.CanonicalEpoch || record.Provenance != networkidentity.EmergencyMigration ||
			hex.EncodeToString(record.CanonicalHash[:]) != plan.CanonicalHash ||
			hex.EncodeToString(record.NetworkDomain[:]) != plan.NetworkDomain {
			return fmt.Errorf("identity DB %s envelope mismatch", node.ID)
		}
		canonicalHash, domain, deriveErr := deriveCanonicalIdentity(plan, record.HeaderBytes)
		if deriveErr != nil || hex.EncodeToString(canonicalHash[:]) != plan.CanonicalHash || hex.EncodeToString(domain[:]) != plan.NetworkDomain {
			return fmt.Errorf("identity DB %s canonical identity mismatch", node.ID)
		}
	}
	return nil
}

func deriveCanonicalIdentity(plan migrationPlan, headerBytes []byte) ([sha256.Size]byte, [sha256.Size]byte, error) {
	var empty [sha256.Size]byte
	marshalizer := &marshal.GogoProtoMarshalizer{}
	header := &block.MetaBlock{}
	if err := marshalizer.Unmarshal(header, headerBytes); err != nil {
		return empty, empty, err
	}
	remarshalled, err := marshalizer.Marshal(header)
	if err != nil || !bytes.Equal(remarshalled, headerBytes) ||
		!bytes.Equal(header.GetChainID(), []byte(plan.ChainID)) || header.GetEpoch() != plan.CanonicalEpoch ||
		len(header.GetRootHash()) == 0 || len(header.GetValidatorStatsRootHash()) == 0 {
		return empty, empty, errors.New("stored canonical MetaBlock semantic mismatch")
	}
	hashBytes := coreBlake2b.NewBlake2b().Compute(string(headerBytes))
	if len(hashBytes) != sha256.Size {
		return empty, empty, errors.New("canonical MetaBlock hash length mismatch")
	}
	var canonicalHash [sha256.Size]byte
	copy(canonicalHash[:], hashBytes)
	domain, err := drwaprototype.DeriveNetworkDomain([]byte(plan.ChainID), canonicalHash)
	if err != nil {
		return empty, empty, err
	}
	return canonicalHash, domain, nil
}

func verifyArtifactCollections(contract orchestrationContract) error {
	for _, collection := range []struct {
		root      string
		artifacts []boundArtifact
	}{
		{root: contract.NodeBase, artifacts: contract.NodeBaseFiles},
		{root: contract.SeedRoot, artifacts: contract.SeedFiles},
		{root: contract.TraceLibraryDirectory, artifacts: contract.TraceLibraries},
		{root: contract.RuntimeLibraryDirectory, artifacts: contract.RuntimeLibraries},
	} {
		if err := verifyExactRegularTree(collection.root, collection.artifacts); err != nil {
			return err
		}
	}
	return nil
}

func verifySeccompProfile(artifact boundArtifact) error {
	value, _, err := readBoundFile(artifact.Path, artifact.SHA256)
	if err != nil {
		return fmt.Errorf("seccomp profile: %w", err)
	}
	var profile struct {
		DefaultAction   string `json:"defaultAction"`
		DefaultErrnoRet int    `json:"defaultErrnoRet"`
		ArchMap         []struct {
			Architecture     string   `json:"architecture"`
			SubArchitectures []string `json:"subArchitectures"`
		} `json:"archMap"`
		Syscalls []json.RawMessage `json:"syscalls"`
	}
	if err = strictDecode(value, &profile); err != nil {
		return fmt.Errorf("decode seccomp profile: %w", err)
	}
	if profile.DefaultAction != "SCMP_ACT_ALLOW" || profile.DefaultErrnoRet != 1 || len(profile.ArchMap) != 1 ||
		profile.ArchMap[0].Architecture != "SCMP_ARCH_X86_64" || len(profile.ArchMap[0].SubArchitectures) != 2 ||
		profile.ArchMap[0].SubArchitectures[0] != "SCMP_ARCH_X86" || profile.ArchMap[0].SubArchitectures[1] != "SCMP_ARCH_X32" ||
		len(profile.Syscalls) != 0 {
		return errors.New("seccomp profile differs from the closed child-tracing policy")
	}
	return nil
}

func verifyExactRegularTree(root string, expected []boundArtifact) error {
	canonicalRoot, err := canonicalNoSymlinkExisting(root)
	if err != nil || canonicalRoot != filepath.Clean(root) {
		return fmt.Errorf("artifact root is not canonical/no-symlink: %s", root)
	}
	allowedDirectories := map[string]struct{}{canonicalRoot: {}}
	for _, artifact := range expected {
		artifactPath := filepath.Clean(artifact.Path)
		if !pathWithin(canonicalRoot, artifactPath) {
			return fmt.Errorf("bound artifact escapes exact tree: %s", artifact.Path)
		}
		for directory := filepath.Dir(artifactPath); directory != canonicalRoot; directory = filepath.Dir(directory) {
			if !pathWithin(canonicalRoot, directory) {
				return fmt.Errorf("bound artifact parent escapes exact tree: %s", artifact.Path)
			}
			allowedDirectories[directory] = struct{}{}
		}
	}
	observed := make(map[string]string)
	err = filepath.WalkDir(canonicalRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if _, allowed := allowedDirectories[path]; !allowed {
				return fmt.Errorf("artifact tree contains unbound directory: %s", path)
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return fmt.Errorf("artifact tree contains non-regular entry: %s", path)
		}
		_, digest, readErr := readBoundFile(path, "")
		if readErr != nil {
			return readErr
		}
		observed[path] = digest
		return nil
	})
	if err != nil {
		return err
	}
	if len(observed) != len(expected) {
		return fmt.Errorf("artifact tree %s contains %d regular files, contract binds %d", root, len(observed), len(expected))
	}
	for _, artifact := range expected {
		digest, exists := observed[artifact.Path]
		if !exists || digest != artifact.SHA256 {
			return fmt.Errorf("artifact tree identity mismatch: %s", artifact.Path)
		}
	}
	return nil
}

func waitForAdvancingHealth(
	specs []nodeSpec,
	chainID string,
	genesisTimestamp uint64,
	requiredAnchors map[string]blockObservation,
	timeout time.Duration,
) (healthSnapshot, error) {
	deadline := time.Now().Add(timeout)
	var first map[string]uint64
	var lastErr error
	for time.Now().Before(deadline) {
		snapshot, err := observeHealth(specs, chainID, genesisTimestamp, requiredAnchors)
		if err == nil {
			observerNonces := make(map[string]uint64)
			for _, spec := range specs {
				if spec.Role == "observer" {
					observerNonces[shardName(spec.ShardID)] = snapshot.Endpoints[spec.ID].Nonce
				}
			}
			if first == nil {
				first = observerNonces
			} else {
				advanced := true
				for shard, nonce := range first {
					if observerNonces[shard] < nonce+2 {
						advanced = false
					}
				}
				if advanced {
					return snapshot, nil
				}
			}
			lastErr = errors.New("waiting for every observer chain to advance two blocks")
		} else {
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	return healthSnapshot{}, fmt.Errorf("bounded health timeout: %w", lastErr)
}

func observeHealth(specs []nodeSpec, chainID string, genesisTimestamp uint64, requiredAnchors map[string]blockObservation) (healthSnapshot, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	result := healthSnapshot{Endpoints: make(map[string]endpointObservation), Anchors: make(map[string]blockObservation)}
	for _, spec := range specs {
		status, err := fetchStatus(client, spec)
		if err != nil {
			return healthSnapshot{}, err
		}
		if status.ChainID != chainID || status.ShardID != spec.ShardID {
			return healthSnapshot{}, fmt.Errorf("endpoint identity mismatch for %s", spec.ID)
		}
		result.Endpoints[spec.ID] = status
	}
	for _, spec := range specs[:4] {
		shard := shardName(spec.ShardID)
		nonce := uint64(0)
		if required, exists := requiredAnchors[shard]; exists {
			nonce = required.Nonce
		} else {
			nonce = result.Endpoints[spec.ID].Nonce
		}
		block, err := fetchBlock(client, spec.REST, nonce)
		if err != nil {
			return healthSnapshot{}, err
		}
		if block.ShardID != spec.ShardID || block.Nonce != nonce {
			return healthSnapshot{}, fmt.Errorf("anchor identity mismatch for shard %s", shard)
		}
		genesis, err := fetchBlock(client, spec.REST, 0)
		if err != nil || genesis.Timestamp != genesisTimestamp || genesis.Nonce != 0 || genesis.ShardID != spec.ShardID {
			return healthSnapshot{}, fmt.Errorf("genesis binding mismatch for shard %s", shard)
		}
		result.Anchors[shard] = block
	}
	return result, nil
}

func fetchStatus(client *http.Client, spec nodeSpec) (endpointObservation, error) {
	var response struct {
		Code string `json:"code"`
		Data struct {
			Metrics map[string]interface{} `json:"metrics"`
		} `json:"data"`
	}
	if err := getJSON(client, fmt.Sprintf("http://127.0.0.1:%d/node/status", spec.REST), &response); err != nil {
		return endpointObservation{}, err
	}
	if response.Code != "successful" {
		return endpointObservation{}, errors.New("node status response is not successful")
	}
	shard, err := numericValue(response.Data.Metrics["erd_shard_id"])
	if err != nil {
		return endpointObservation{}, err
	}
	shardID, err := uint32Value("status shard", shard)
	if err != nil {
		return endpointObservation{}, err
	}
	epoch, err := numericValue(response.Data.Metrics["erd_epoch_number"])
	if err != nil {
		return endpointObservation{}, err
	}
	round, err := numericValue(response.Data.Metrics["erd_current_round"])
	if err != nil {
		return endpointObservation{}, err
	}
	nonce, err := numericValue(response.Data.Metrics["erd_nonce"])
	if err != nil {
		return endpointObservation{}, err
	}
	chain, ok := response.Data.Metrics["erd_chain_id"].(string)
	if !ok {
		return endpointObservation{}, errors.New("chain ID metric is not a string")
	}
	return endpointObservation{ID: spec.ID, REST: spec.REST, ShardID: shardID, Epoch: epoch, Round: round, Nonce: nonce, ChainID: chain}, nil
}

func fetchBlock(client *http.Client, port uint16, nonce uint64) (blockObservation, error) {
	var response struct {
		Code string `json:"code"`
		Data struct {
			Block struct {
				Hash          string      `json:"hash"`
				StateRootHash string      `json:"stateRootHash"`
				Timestamp     interface{} `json:"timestamp"`
				Nonce         interface{} `json:"nonce"`
				Shard         interface{} `json:"shard"`
			} `json:"block"`
		} `json:"data"`
	}
	if err := getJSON(client, fmt.Sprintf("http://127.0.0.1:%d/block/by-nonce/%d", port, nonce), &response); err != nil {
		return blockObservation{}, err
	}
	if response.Code != "successful" || response.Data.Block.Hash == "" || response.Data.Block.StateRootHash == "" {
		return blockObservation{}, errors.New("block response is incomplete")
	}
	timestamp, err := numericValue(response.Data.Block.Timestamp)
	if err != nil {
		return blockObservation{}, err
	}
	observedNonce, err := numericValue(response.Data.Block.Nonce)
	if err != nil {
		return blockObservation{}, err
	}
	shard, err := numericValue(response.Data.Block.Shard)
	if err != nil {
		return blockObservation{}, err
	}
	shardID, err := uint32Value("block shard", shard)
	if err != nil {
		return blockObservation{}, err
	}
	return blockObservation{
		Hash: response.Data.Block.Hash, StateRootHash: response.Data.Block.StateRootHash,
		Timestamp: timestamp, Nonce: observedNonce, ShardID: shardID,
	}, nil
}

func getJSON(client *http.Client, url string, destination interface{}) error {
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP status %d", response.StatusCode)
	}
	const maximumResponseBytes = 4 * 1024 * 1024
	value, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	if err != nil {
		return err
	}
	if len(value) > maximumResponseBytes {
		return errors.New("JSON response exceeds size limit")
	}
	if err = rejectDuplicateJSONKeys(value); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	if err = decoder.Decode(destination); err != nil {
		return err
	}
	var trailing interface{}
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

func verifyIdentityLogs(processes []*runningProcess, contract orchestrationContract) error {
	for _, process := range processes {
		value, err := os.ReadFile(filepath.Join(filepath.Dir(process.tracePrefix), "..", "node-logs", filepath.Base(process.tracePrefix)+".log"))
		if err != nil {
			return err
		}
		text := string(value)
		if !strings.Contains(text, "canonicalMetachainGenesisHash = "+contract.CanonicalMetachainHash) ||
			!strings.Contains(text, "networkDomain = "+contract.NetworkDomain) ||
			!strings.Contains(text, "identitySource = "+contract.IdentityProvenance) {
			return fmt.Errorf("node %s did not emit the exact emergency identity tuple", process.ID)
		}
	}
	return nil
}

func equalAnchors(expected, observed map[string]blockObservation) error {
	if len(expected) != 4 || len(observed) != 4 {
		return errors.New("four anchor observations are required")
	}
	for shard, value := range expected {
		other, exists := observed[shard]
		if !exists || other != value {
			return fmt.Errorf("block/state-root anchor drift on shard %s", shard)
		}
	}
	return nil
}

func splitCrashProcess(processes []*runningProcess, id string) (*runningProcess, []*runningProcess, error) {
	var crashed *runningProcess
	survivors := make([]*runningProcess, 0, len(processes)-1)
	for _, process := range processes {
		if process.ID == id {
			if crashed != nil {
				return nil, nil, errors.New("duplicate crash-node process")
			}
			crashed = process
		} else {
			survivors = append(survivors, process)
		}
	}
	if crashed == nil || len(survivors) != 15 {
		return nil, nil, errors.New("exact crash-node process was not found")
	}
	return crashed, survivors, nil
}

func specByID(specs []nodeSpec, id string) nodeSpec {
	for _, spec := range specs {
		if spec.ID == id {
			return spec
		}
	}
	return nodeSpec{}
}

func stopProcesses(processes []*runningProcess, timeout time.Duration, requireClean bool) ([]string, error) {
	return stopProcessesWithSignal(processes, timeout, requireClean, func(process *runningProcess) error {
		return unix.PidfdSendSignal(process.targetPIDFD, unix.SIGTERM, nil, 0)
	})
}

func stopProcessesWithSignal(
	processes []*runningProcess,
	timeout time.Duration,
	requireClean bool,
	signalProcess func(*runningProcess) error,
) ([]string, error) {
	active := make([]*runningProcess, 0, len(processes))
	failures := make([]error, 0)
	for _, process := range processes {
		if process == nil || process.cleanStop || process.crashed {
			continue
		}
		select {
		case waitErr := <-process.done:
			closeProcessPIDFD(process)
			failures = append(failures, fmt.Errorf("process %s exited before bounded stop: %v", process.ID, waitErr))
			continue
		default:
		}
		if process.targetPID <= 0 || process.targetPIDFD < 0 {
			failures = append(failures, fmt.Errorf("process %s has no bound traced-child pidfd", process.ID))
			continue
		}
		if err := signalProcess(process); err != nil && !errors.Is(err, syscall.ESRCH) {
			failures = append(failures, fmt.Errorf("signal process %s: %w", process.ID, err))
			continue
		}
		active = append(active, process)
	}
	deadline := time.Now().Add(timeout)
	stopped := make([]string, 0, len(active))
	for _, process := range active {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			select {
			case waitErr := <-process.done:
				closeProcessPIDFD(process)
				if requireClean && waitErr != nil {
					failures = append(failures, fmt.Errorf("process %s did not stop cleanly: %w", process.ID, waitErr))
				} else {
					process.cleanStop = true
					stopped = append(stopped, process.ID)
				}
			default:
				failures = append(failures, fmt.Errorf("bounded SIGTERM timeout with no SIGKILL fallback: %s", process.ID))
			}
			continue
		}
		timer := time.NewTimer(remaining)
		select {
		case waitErr := <-process.done:
			if !timer.Stop() {
				<-timer.C
			}
			closeProcessPIDFD(process)
			if requireClean && waitErr != nil {
				failures = append(failures, fmt.Errorf("process %s did not stop cleanly: %w", process.ID, waitErr))
				continue
			}
			process.cleanStop = true
			stopped = append(stopped, process.ID)
		case <-timer.C:
			failures = append(failures, fmt.Errorf("bounded SIGTERM timeout with no SIGKILL fallback: %s", process.ID))
		}
	}
	sort.Strings(stopped)
	return stopped, errors.Join(failures...)
}

func killProcess(process *runningProcess, timeout time.Duration) error {
	if process == nil {
		return errors.New("nil crash process")
	}
	if process.targetPID <= 0 || process.targetPIDFD < 0 {
		return errors.New("crash process has no bound traced-child pidfd")
	}
	if err := unix.PidfdSendSignal(process.targetPIDFD, unix.SIGKILL, nil, 0); err != nil {
		return err
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-process.done:
		closeProcessPIDFD(process)
		process.crashed = true
		return nil
	case <-timer.C:
		return errors.New("crash process did not exit within bounded timeout")
	}
}

func closeProcessPIDFD(process *runningProcess) {
	if process != nil && process.targetPIDFD >= 0 {
		_ = unix.Close(process.targetPIDFD)
		process.targetPIDFD = -1
	}
}

var (
	inetAddressPattern  = regexp.MustCompile(`inet_addr\("([^"]+)"\)`)
	inet6AddressPattern = regexp.MustCompile(`inet_pton\(AF_INET6, "([^"]+)"`)
)

func expectedTracePrefixes(specs []nodeSpec, crashNodeID string) []string {
	result := []string{"seed-seed"}
	for _, phase := range []string{"first", "second"} {
		for _, spec := range specs {
			result = append(result, phase+"-"+spec.ID)
		}
	}
	result = append(result, "post-crash-"+crashNodeID)
	sort.Strings(result)
	return result
}

func verifyAndHashTraces(root string, expectedPrefixes []string) (map[string]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("no connect/bind trace files exist")
	}
	if len(expectedPrefixes) == 0 {
		return nil, errors.New("expected trace-prefix set is empty")
	}
	expected := make(map[string]bool, len(expectedPrefixes))
	for _, prefix := range expectedPrefixes {
		if prefix == "" || strings.Contains(prefix, ".") {
			return nil, fmt.Errorf("invalid expected trace prefix %q", prefix)
		}
		if _, duplicate := expected[prefix]; duplicate {
			return nil, fmt.Errorf("duplicate expected trace prefix %s", prefix)
		}
		expected[prefix] = false
	}
	result := make(map[string]string)
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return nil, fmt.Errorf("trace entry is not a regular file: %s", entry.Name())
		}
		separator := strings.LastIndexByte(entry.Name(), '.')
		if separator <= 0 {
			return nil, fmt.Errorf("trace filename lacks numeric PID suffix: %s", entry.Name())
		}
		prefix, pidText := entry.Name()[:separator], entry.Name()[separator+1:]
		pid, parseErr := strconv.Atoi(pidText)
		if parseErr != nil || pid <= 0 {
			return nil, fmt.Errorf("trace filename has invalid PID suffix: %s", entry.Name())
		}
		if _, exists := expected[prefix]; !exists {
			return nil, fmt.Errorf("unexpected trace prefix %s", prefix)
		}
		path := filepath.Join(root, entry.Name())
		value, digest, readErr := readBoundFile(path, "")
		if readErr != nil {
			return nil, readErr
		}
		result[entry.Name()] = digest
		scanner := bufio.NewScanner(bytes.NewReader(value))
		scanner.Buffer(make([]byte, 4096), 1024*1024)
		observedNetworkCall := false
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.Contains(line, "connect(") && !strings.Contains(line, "bind(") && !strings.Contains(line, "connect resumed>") && !strings.Contains(line, "bind resumed>") {
				continue
			}
			observedNetworkCall = true
			if err = validateTracedNetworkLine(line); err != nil {
				return nil, fmt.Errorf("trace %s: %w", entry.Name(), err)
			}
		}
		if err = scanner.Err(); err != nil {
			return nil, err
		}
		if observedNetworkCall {
			expected[prefix] = true
		}
	}
	for prefix, observed := range expected {
		if !observed {
			return nil, fmt.Errorf("expected trace prefix %s has no intercepted parseable connect/bind syscall", prefix)
		}
	}
	return result, nil
}

func validateTracedNetworkLine(line string) error {
	if strings.Contains(line, "<unfinished ...>") || strings.Contains(line, "resumed>") {
		return errors.New("split trace line cannot independently prove its sockaddr")
	}
	if strings.Contains(line, "sa_family=AF_UNIX") || strings.Contains(line, "addr=NULL") || strings.Contains(line, " NULL,") {
		return nil
	}
	if strings.Contains(line, "sa_family=AF_INET6") {
		matches := inet6AddressPattern.FindStringSubmatch(line)
		if len(matches) != 2 || (matches[1] != "::" && matches[1] != "::1") {
			return errors.New("IPv6 connect/bind is not wildcard or loopback")
		}
		if strings.Contains(line, "connect(") && matches[1] != "::1" {
			return errors.New("IPv6 connect is not loopback")
		}
		return nil
	}
	if strings.Contains(line, "sa_family=AF_INET") {
		matches := inetAddressPattern.FindStringSubmatch(line)
		if len(matches) != 2 {
			return errors.New("IPv4 connect/bind address is not parseable")
		}
		address := matches[1]
		if strings.Contains(line, "connect(") {
			if !strings.HasPrefix(address, "127.") {
				return fmt.Errorf("IPv4 connect escaped loopback: %s", address)
			}
		} else if address != "0.0.0.0" && !strings.HasPrefix(address, "127.") {
			return fmt.Errorf("IPv4 bind is not wildcard or loopback: %s", address)
		}
		return nil
	}
	return errors.New("connect/bind address family is unrecognized")
}

func requireRuntimeIsolation(contract orchestrationContract) error {
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
		return errors.New("orchestrator is not PID 1 in its PID namespace")
	}

	networkNamespace, err := os.Readlink("/proc/self/ns/net")
	if err != nil || networkNamespace == "" || networkNamespace == contract.HostNetworkNamespace {
		return errors.New("network namespace is absent or equals host namespace")
	}
	interfaces, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return err
	}
	if len(interfaces) != 1 || interfaces[0].Name() != "lo" {
		return errors.New("isolated orchestration requires exactly loopback")
	}
	if err = requireNoNonLoopbackRoutes(); err != nil {
		return err
	}
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	return validateRuntimeMounts(string(mounts), contract)
}

func validateRuntimeMounts(mountInfo string, contract orchestrationContract) error {
	rootMode, found := mountMode(mountInfo, "/")
	if !found || rootMode != "ro" {
		return errors.New("container root is not read-only")
	}
	rehearsalMode, found := mountMode(mountInfo, contract.RehearsalRoot)
	if !found || rehearsalMode != "rw" {
		return errors.New("rehearsal root is not an exact read-write mount")
	}
	for _, path := range contract.ReadOnlyMounts {
		mode, exact := mountMode(mountInfo, path)
		if !exact || mode != "ro" {
			return fmt.Errorf("required exact read-only mount missing: %s", path)
		}
	}
	allowedUnderRehearsal := map[string]struct{}{filepath.Clean(contract.RehearsalRoot): {}}
	for _, path := range contract.ReadOnlyMounts {
		allowedUnderRehearsal[filepath.Clean(path)] = struct{}{}
	}
	for _, line := range strings.Split(strings.TrimSpace(mountInfo), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		mountPath := strings.ReplaceAll(strings.ReplaceAll(fields[4], `\040`, " "), `\134`, `\`)
		if mountPath != contract.RehearsalRoot && !pathWithin(contract.RehearsalRoot, mountPath) {
			continue
		}
		if _, allowed := allowedUnderRehearsal[filepath.Clean(mountPath)]; !allowed {
			return fmt.Errorf("unexpected nested rehearsal mount: %s", mountPath)
		}
	}
	return nil
}

func validateIsolationStatus(status map[string]string) error {
	if status["NoNewPrivs"] != "1" || status["Seccomp"] != "2" || status["Seccomp_filters"] != "1" {
		return errors.New("NoNewPrivs and exactly one seccomp filter are required")
	}
	for _, capabilityField := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		if status[capabilityField] != "0000000000000000" {
			return fmt.Errorf("%s must be zero", capabilityField)
		}
	}
	return nil
}

func requireNoNonLoopbackRoutes() error {
	value, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(string(value)), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] != "lo" {
			return fmt.Errorf("non-loopback IPv4 route present on %s", fields[0])
		}
	}
	value, err = os.ReadFile("/proc/net/ipv6_route")
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

func openSealedFile(artifact boundArtifact) (*sealedFile, error) {
	canonical, err := canonicalNoSymlinkExisting(artifact.Path)
	if err != nil || canonical != filepath.Clean(artifact.Path) {
		return nil, errors.New("sealed executable path is not canonical/no-symlink")
	}
	fd, err := unix.Open(canonical, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), canonical)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("create sealed executable handle")
	}
	fail := func(value error) (*sealedFile, error) {
		_ = file.Close()
		return nil, value
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return fail(errors.New("sealed executable is not an executable regular file"))
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fail(errors.New("sealed executable filesystem identity unavailable"))
	}
	hasher := sha256.New()
	if _, err = io.Copy(hasher, file); err != nil {
		return fail(err)
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	if digest != artifact.SHA256 {
		return fail(fmt.Errorf("sealed executable SHA-256 mismatch: %s", artifact.Path))
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	return &sealedFile{
		file: file, path: canonical, sha: digest, device: uint64(stat.Dev), inode: stat.Ino,
		size: info.Size(), mode: info.Mode(),
	}, nil
}

func (sealed *sealedFile) verifyUnchanged() error {
	info, err := sealed.file.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != sealed.device || stat.Ino != sealed.inode || info.Size() != sealed.size || info.Mode() != sealed.mode {
		return fmt.Errorf("sealed executable identity changed: %s", sealed.path)
	}
	if _, err = sealed.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hasher := sha256.New()
	if _, err = io.Copy(hasher, sealed.file); err != nil {
		return err
	}
	if hex.EncodeToString(hasher.Sum(nil)) != sealed.sha {
		return fmt.Errorf("sealed executable bytes changed: %s", sealed.path)
	}
	_, err = sealed.file.Seek(0, io.SeekStart)
	return err
}

func (sealed *sealedFile) Close() error {
	return sealed.file.Close()
}

func readBoundFile(path, expectedSHA string) ([]byte, string, error) {
	canonical, err := canonicalNoSymlinkExisting(path)
	if err != nil || canonical != filepath.Clean(path) {
		return nil, "", errors.New("bound file path is not canonical/no-symlink")
	}
	fd, err := unix.Open(canonical, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, "", err
	}
	file := os.NewFile(uintptr(fd), canonical)
	if file == nil {
		_ = unix.Close(fd)
		return nil, "", errors.New("create bound file handle")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, "", errors.New("bound input is not a regular file")
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

func hashRegularFiles(root string) (map[string]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	result := make(map[string]string)
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return nil, fmt.Errorf("non-regular evidence file: %s", entry.Name())
		}
		_, digest, readErr := readBoundFile(filepath.Join(root, entry.Name()), "")
		if readErr != nil {
			return nil, readErr
		}
		result[entry.Name()] = digest
	}
	return result, nil
}

func openExclusiveOutput(root, path string) (*os.File, error) {
	expectedDir := filepath.Join(root, "artifacts")
	if filepath.Dir(filepath.Clean(path)) != expectedDir {
		return nil, errors.New("output is not a direct artifacts child")
	}
	directoryFD, err := unix.Open(expectedDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(directoryFD), expectedDir)
	if directory == nil {
		_ = unix.Close(directoryFD)
		return nil, errors.New("create artifacts directory handle")
	}
	defer directory.Close()
	name := filepath.Base(path)
	fd, err := unix.Openat(directoryFD, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("create exclusive output")
	}
	if err = directory.Sync(); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func writeExclusiveJSON(root, path string, value interface{}) error {
	file, err := openExclusiveOutput(root, path)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err == nil {
		_, err = file.Write(append(encoded, '\n'))
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func writeExclusiveBytes(root, path string, value []byte) error {
	file, err := openExclusiveOutput(root, path)
	if err != nil {
		return err
	}
	if _, err = file.Write(value); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func createExactEmptyDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
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

func strictDecode(value []byte, destination interface{}) error {
	if err := rejectDuplicateJSONKeys(value); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
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
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, tokenErr := decoder.Token()
				if tokenErr != nil {
					return tokenErr
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object key is not a string")
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("duplicate JSON object key %q", key)
				}
				seen[key] = struct{}{}
				if err = walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err = walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func numericValue(value interface{}) (uint64, error) {
	switch typed := value.(type) {
	case json.Number:
		return strconv.ParseUint(string(typed), 10, 64)
	case string:
		return strconv.ParseUint(typed, 10, 64)
	case float64:
		if typed < 0 || typed != float64(uint64(typed)) {
			return 0, errors.New("numeric value is not an unsigned integer")
		}
		return uint64(typed), nil
	default:
		return 0, errors.New("numeric value has unsupported type")
	}
}

func uint32Value(name string, value uint64) (uint32, error) {
	if value > uint64(^uint32(0)) {
		return 0, fmt.Errorf("%s exceeds uint32 range", name)
	}
	return uint32(value), nil
}

func validateDigest(value string) error {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
		return errors.New("expected exactly 32 canonical lowercase hexadecimal bytes")
	}
	return nil
}

func parseShard(value string) uint32 {
	if value == "metachain" {
		return metaShard
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return ^uint32(0) - 1
	}
	return uint32(parsed)
}

func shardName(value uint32) string {
	if value == metaShard {
		return "metachain"
	}
	return strconv.FormatUint(uint64(value), 10)
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
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
