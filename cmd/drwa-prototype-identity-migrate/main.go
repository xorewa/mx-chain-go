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
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/multiversx/mx-chain-core-go/data/block"
	coreBlake2b "github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	identityverify "github.com/multiversx/mx-chain-go/cmd/internal/drwaprototypeidentityverify"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype/networkidentity"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// REPLACED_BY_PART_B

type options struct {
	mode                          string
	chainID                       string
	epoch                         uint
	expectedCanonicalHash         string
	expectedDomain                string
	bindingPath                   string
	expectedBindingSHA            string
	transitionPlanPath            string
	expectedPlanSHA               string
	transitionTracePath           string
	expectedTraceSHA              string
	headerPath                    string
	headerOutputPath              string
	targetDBPath                  string
	nodeRoot                      string
	shardID                       string
	evidencePath                  string
	migrationPlanPath             string
	expectedMigrationPlanSHA      string
	extractionEvidencePath        string
	expectedExtractionEvidenceSHA string
	rehearsalRoot                 string
	checkpointOutputPath          string
	shard0ObserverMetaDB          string
	shard1ObserverMetaDB          string
	shard2ObserverMetaDB          string
	metachainObserverMetaDB       string
}

type verifiedIdentity struct {
	HeaderBytes   []byte
	CanonicalHash [32]byte
	NetworkDomain [32]byte
}

type migrationEvidence struct {
	Schema                     string                        `json:"schema"`
	Status                     string                        `json:"status"`
	Mode                       string                        `json:"mode"`
	TimestampUTC               string                        `json:"timestamp_utc"`
	ChainID                    string                        `json:"chain_id"`
	CanonicalEpoch             uint32                        `json:"canonical_epoch"`
	Provenance                 string                        `json:"provenance"`
	CanonicalHash              string                        `json:"canonical_metachain_genesis_hash"`
	NetworkDomain              string                        `json:"network_domain"`
	HeaderSHA256               string                        `json:"header_sha256"`
	HeaderLength               int                           `json:"header_length"`
	IdentitySchemaVersion      byte                          `json:"identity_schema_version"`
	StorageKeyHex              string                        `json:"storage_key_hex"`
	EnvelopeSHA256             string                        `json:"envelope_sha256"`
	EnvelopeLength             int                           `json:"envelope_length"`
	HeaderOutputPath           string                        `json:"header_output_path,omitempty"`
	BindingPath                string                        `json:"binding_path,omitempty"`
	BindingSHA256              string                        `json:"binding_sha256,omitempty"`
	ObserverMetaDBs            []string                      `json:"observer_meta_dbs,omitempty"`
	TransitionPlanPath         string                        `json:"transition_plan_path,omitempty"`
	TransitionPlanSHA256       string                        `json:"transition_plan_sha256,omitempty"`
	TransitionTracePath        string                        `json:"transition_trace_path,omitempty"`
	TransitionTraceSHA256      string                        `json:"transition_trace_sha256,omitempty"`
	ArchivedNodePath           string                        `json:"archived_node_path,omitempty"`
	ArchivedWorkPath           string                        `json:"archived_work_path,omitempty"`
	MainConfigSHA256           string                        `json:"main_config_sha256,omitempty"`
	NodesSetupSHA256           string                        `json:"nodes_setup_sha256,omitempty"`
	PrecursorSHA256            string                        `json:"precursor_sha256,omitempty"`
	PrecursorBlake2b           string                        `json:"precursor_blake2b,omitempty"`
	ObserverRootIdentities     []string                      `json:"observer_root_identities,omitempty"`
	ObserverObservations       []observerObservationEvidence `json:"observer_observations,omitempty"`
	TargetDBPath               string                        `json:"target_db_path,omitempty"`
	NodeRoot                   string                        `json:"node_root,omitempty"`
	ShardID                    string                        `json:"shard_id,omitempty"`
	TargetAbsentBefore         *bool                         `json:"target_absent_before,omitempty"`
	DurableCloseReopenVerified *bool                         `json:"durable_close_reopen_verified,omitempty"`
	AuthoritativeRuntimeCredit int                           `json:"authoritative_runtime_credit"`
}

type observerObservationEvidence struct {
	Role                string   `json:"role"`
	CanonicalRoot       string   `json:"canonical_root"`
	RootDevice          uint64   `json:"root_device"`
	RootInode           uint64   `json:"root_inode"`
	NumericPartitions   []int    `json:"numeric_partitions"`
	PartitionIdentities []string `json:"partition_identities"`
	PrecursorMatchCount int      `json:"precursor_match_count"`
	PrecursorSHA256     string   `json:"precursor_sha256"`
	PrecursorBlake2b    string   `json:"precursor_blake2b"`
	FinalMatchCount     int      `json:"final_match_count"`
	FinalSHA256         string   `json:"final_sha256,omitempty"`
	FinalBlake2b        string   `json:"final_blake2b,omitempty"`
}

func main() {
	opts := parseFlags()
	if err := run(opts); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseFlags() options {
	opts := options{}
	flag.StringVar(&opts.mode, "mode", "plan", "extract, checkpoint, or plan; all database-write modes are disabled in this binary")
	flag.StringVar(&opts.chainID, "chain-id", "", "exact chain ID")
	flag.UintVar(&opts.epoch, "epoch", 0, "canonical genesis epoch")
	flag.StringVar(&opts.expectedCanonicalHash, "expected-canonical-hash", "", "32-byte lowercase hex hash")
	flag.StringVar(&opts.expectedDomain, "expected-domain", "", "32-byte lowercase hex domain")
	flag.StringVar(&opts.bindingPath, "binding", "", "active generation binding JSON")
	flag.StringVar(&opts.expectedBindingSHA, "expected-binding-sha", "", "exact binding file SHA-256")
	flag.StringVar(&opts.transitionPlanPath, "transition-plan", "", "standalone transition plan JSON")
	flag.StringVar(&opts.expectedPlanSHA, "expected-transition-plan-sha", "", "exact transition plan SHA-256")
	flag.StringVar(&opts.transitionTracePath, "transition-trace", "", "canonical executed-transition trace JSON")
	flag.StringVar(&opts.expectedTraceSHA, "expected-transition-trace-sha", "", "exact executed-transition trace SHA-256")
	flag.StringVar(&opts.headerPath, "header", "", "exact marshalled MetaBlock artifact")
	flag.StringVar(&opts.headerOutputPath, "header-output", "", "O_EXCL output for extract mode")
	flag.StringVar(&opts.targetDBPath, "target-db", "", "dedicated static identity LevelDB path")
	flag.StringVar(&opts.nodeRoot, "node-root", "", "exact stopped node working directory")
	flag.StringVar(&opts.shardID, "shard-id", "", "exact node shard: 0, 1, 2, or metachain")
	flag.StringVar(&opts.evidencePath, "evidence", "", "O_EXCL evidence JSON path")
	flag.StringVar(&opts.migrationPlanPath, "migration-plan", "", "exact 16-node migration plan JSON")
	flag.StringVar(&opts.expectedMigrationPlanSHA, "expected-migration-plan-sha", "", "exact migration plan SHA-256")
	flag.StringVar(&opts.extractionEvidencePath, "extraction-evidence", "", "exact extraction evidence JSON")
	flag.StringVar(&opts.expectedExtractionEvidenceSHA, "expected-extraction-evidence-sha", "", "exact extraction evidence SHA-256")
	flag.StringVar(&opts.rehearsalRoot, "rehearsal-root", "", "canonical mechanically isolated rehearsal root")
	flag.StringVar(&opts.checkpointOutputPath, "checkpoint-output", "", "O_EXCL checkpoint-copy manifest output")
	flag.StringVar(&opts.shard0ObserverMetaDB, "shard-0-observer-meta-db", "", "closed shard-0 observer epoch MetaBlock root")
	flag.StringVar(&opts.shard1ObserverMetaDB, "shard-1-observer-meta-db", "", "closed shard-1 observer epoch MetaBlock root")
	flag.StringVar(&opts.shard2ObserverMetaDB, "shard-2-observer-meta-db", "", "closed shard-2 observer epoch MetaBlock root")
	flag.StringVar(&opts.metachainObserverMetaDB, "metachain-observer-meta-db", "", "closed metachain observer epoch MetaBlock root")
	flag.Parse()
	return opts
}

func run(opts options) error {
	if opts.chainID == "" {
		return errors.New("chain-id is required")
	}
	if opts.epoch > uint(^uint32(0)) {
		return fmt.Errorf("epoch %d exceeds uint32", opts.epoch)
	}
	expectedHash, err := decode32("expected-canonical-hash", opts.expectedCanonicalHash)
	if err != nil {
		return err
	}
	expectedDomain, err := decode32("expected-domain", opts.expectedDomain)
	if err != nil {
		return err
	}

	switch opts.mode {
	case "extract":
		return runExtract(opts, uint32(opts.epoch), expectedHash, expectedDomain)
	case "checkpoint":
		return runCheckpoint(opts, uint32(opts.epoch), expectedHash, expectedDomain)
	case "plan":
		return runNode(opts, uint32(opts.epoch), expectedHash, expectedDomain)
	case "rehearse", "migrate", "migrate-disabled":
		return errors.New("live migration is mechanically disabled until a separately audited one-time authorization wrapper is installed")
	default:
		return fmt.Errorf("unsupported mode %q", opts.mode)
	}
}

func runExtract(opts options, epoch uint32, expectedHash, expectedDomain [32]byte) error {
	return runExtractAmended(opts, epoch, expectedHash, expectedDomain)
}

func runNode(opts options, epoch uint32, expectedHash, expectedDomain [32]byte) error {
	return identityverify.RunPlanAndWriteEvidence(identityverify.PlanRequest{
		ChainID: opts.chainID, Epoch: epoch,
		ExpectedCanonicalHash: hex.EncodeToString(expectedHash[:]), ExpectedDomain: hex.EncodeToString(expectedDomain[:]),
		BindingPath: opts.bindingPath, ExpectedBindingSHA: opts.expectedBindingSHA,
		HeaderPath: opts.headerPath, TargetDBPath: opts.targetDBPath, NodeRoot: opts.nodeRoot, ShardID: opts.shardID,
		MigrationPlanPath: opts.migrationPlanPath, ExpectedMigrationPlanSHA: opts.expectedMigrationPlanSHA,
		ExtractionEvidencePath:        opts.extractionEvidencePath,
		ExpectedExtractionEvidenceSHA: opts.expectedExtractionEvidenceSHA,
		RehearsalRoot:                 opts.rehearsalRoot, EvidencePath: opts.evidencePath,
	})
}

func verifyHeader(chainID string, epoch uint32, headerBytes []byte, expectedHash, expectedDomain [32]byte) (verifiedIdentity, error) {
	if len(headerBytes) == 0 {
		return verifiedIdentity{}, errors.New("empty header artifact")
	}
	marshalizer := &marshal.GogoProtoMarshalizer{}
	metaHeader := &block.MetaBlock{}
	if err := marshalizer.Unmarshal(metaHeader, headerBytes); err != nil {
		return verifiedIdentity{}, fmt.Errorf("unmarshal MetaBlock: %w", err)
	}
	remarshalled, err := marshalizer.Marshal(metaHeader)
	if err != nil {
		return verifiedIdentity{}, fmt.Errorf("remarshal MetaBlock: %w", err)
	}
	if !bytes.Equal(headerBytes, remarshalled) {
		return verifiedIdentity{}, errors.New("header artifact is not canonical byte encoding")
	}
	if !bytes.Equal(metaHeader.GetChainID(), []byte(chainID)) {
		return verifiedIdentity{}, errors.New("header chain ID mismatch")
	}
	if metaHeader.GetEpoch() != epoch {
		return verifiedIdentity{}, fmt.Errorf("header epoch %d does not equal selected epoch %d", metaHeader.GetEpoch(), epoch)
	}
	if len(metaHeader.GetRootHash()) == 0 || len(metaHeader.GetValidatorStatsRootHash()) == 0 {
		return verifiedIdentity{}, errors.New("header state or validator-statistics root unavailable")
	}
	canonicalHashBytes := coreBlake2b.NewBlake2b().Compute(string(headerBytes))
	if len(canonicalHashBytes) != 32 {
		return verifiedIdentity{}, fmt.Errorf("canonical hasher returned %d bytes", len(canonicalHashBytes))
	}
	canonicalHash := [32]byte{}
	copy(canonicalHash[:], canonicalHashBytes)
	if canonicalHash != expectedHash {
		return verifiedIdentity{}, fmt.Errorf("canonical hash %x does not match expected %x", canonicalHash, expectedHash)
	}
	domain, err := drwaprototype.DeriveNetworkDomain([]byte(chainID), canonicalHash)
	if err != nil {
		return verifiedIdentity{}, fmt.Errorf("derive network domain: %w", err)
	}
	if domain != expectedDomain {
		return verifiedIdentity{}, fmt.Errorf("network domain %x does not match expected %x", domain, expectedDomain)
	}

	return verifiedIdentity{HeaderBytes: append([]byte(nil), headerBytes...), CanonicalHash: canonicalHash, NetworkDomain: domain}, nil
}

func requireNodeStopped(nodeRoot string) error {
	canonicalRoot, err := filepath.EvalSymlinks(nodeRoot)
	if err != nil {
		return fmt.Errorf("resolve node root: %w", err)
	}
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return fmt.Errorf("enumerate processes: %w", err)
	}
	for _, entry := range procEntries {
		if !entry.IsDir() {
			continue
		}
		if _, err = strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		cwd, readErr := os.Readlink(filepath.Join("/proc", entry.Name(), "cwd"))
		if readErr == nil && (cwd == canonicalRoot || strings.HasPrefix(cwd, canonicalRoot+string(os.PathSeparator))) {
			return fmt.Errorf("node process %s still uses target root %s", entry.Name(), canonicalRoot)
		}
		cmdline, readErr := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if readErr == nil && bytes.Contains(cmdline, []byte(canonicalRoot)) {
			return fmt.Errorf("process %s command line references target root %s", entry.Name(), canonicalRoot)
		}
	}
	return nil
}

func newEvidence(mode, status string, opts options, epoch uint32, verified verifiedIdentity) (migrationEvidence, error) {
	headerSHA := sha256.Sum256(verified.HeaderBytes)
	record := networkidentity.Record{
		SchemaVersion: networkidentity.Version,
		Epoch:         epoch,
		Provenance:    networkidentity.EmergencyMigration,
		ChainID:       []byte(opts.chainID),
		CanonicalHash: verified.CanonicalHash,
		NetworkDomain: verified.NetworkDomain,
		HeaderBytes:   verified.HeaderBytes,
	}
	envelope, err := networkidentity.Encode(record)
	if err != nil {
		return migrationEvidence{}, fmt.Errorf("encode expected v2 identity envelope: %w", err)
	}
	envelopeSHA := sha256.Sum256(envelope)
	provenance := "NOT_APPLIED_EXTRACTION_ONLY"
	if mode == "plan" {
		provenance = "PLANNED_EMERGENCY_MIGRATION_NOT_APPLIED"
	}
	if mode == "migrate" {
		provenance = networkidentity.EmergencyMigration.String()
	}
	if mode == "rehearse" {
		provenance = "OFFLINE_REHEARSAL_EMERGENCY_MIGRATION_NOT_LIVE"
	}
	return migrationEvidence{
		Schema:                     "drwa.s1.prototype-network-identity-migration.v2",
		Status:                     status,
		Mode:                       mode,
		TimestampUTC:               time.Now().UTC().Format(time.RFC3339Nano),
		ChainID:                    opts.chainID,
		CanonicalEpoch:             epoch,
		Provenance:                 provenance,
		CanonicalHash:              hex.EncodeToString(verified.CanonicalHash[:]),
		NetworkDomain:              hex.EncodeToString(verified.NetworkDomain[:]),
		HeaderSHA256:               hex.EncodeToString(headerSHA[:]),
		HeaderLength:               len(verified.HeaderBytes),
		IdentitySchemaVersion:      networkidentity.Version,
		StorageKeyHex:              hex.EncodeToString(networkidentity.Key(epoch)),
		EnvelopeSHA256:             hex.EncodeToString(envelopeSHA[:]),
		EnvelopeLength:             len(envelope),
		AuthoritativeRuntimeCredit: 0,
	}, nil
}

func writeEvidence(path string, evidence migrationEvidence) error {
	bytesValue, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	bytesValue = append(bytesValue, '\n')
	return writeExclusiveDurable(path, bytesValue, 0o600)
}

func writeExclusiveDurable(path string, value []byte, mode fs.FileMode) error {
	canonical, err := canonicalCreatedPath(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(canonical)
	dirFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	dirHandle := os.NewFile(uintptr(dirFD), dir)
	if dirHandle == nil {
		_ = unix.Close(dirFD)
		return errors.New("create output parent handle")
	}
	defer dirHandle.Close()
	fd, err := unix.Openat(
		dirFD,
		filepath.Base(canonical),
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		uint32(mode.Perm()),
	)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), canonical)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("create output file handle")
	}
	if _, err = file.Write(value); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return dirHandle.Sync()
}

func strictDecodeJSON(value []byte, destination interface{}) error {
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
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}

func decodeJSONNoDuplicates(value []byte, destination interface{}) error {
	if err := rejectDuplicateJSONKeys(value); err != nil {
		return err
	}
	if err := json.Unmarshal(value, destination); err != nil {
		return err
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
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
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
		if closeErr != nil {
			return closeErr
		}
		if closing != json.Delim('}') {
			return errors.New("JSON object has invalid closing delimiter")
		}
	case '[':
		for decoder.More() {
			if err = consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil {
			return closeErr
		}
		if closing != json.Delim(']') {
			return errors.New("JSON array has invalid closing delimiter")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func decode32(name, value string) ([32]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 || value != strings.ToLower(value) {
		return [32]byte{}, fmt.Errorf("%s must be exactly 32 lowercase hex bytes", name)
	}
	result := [32]byte{}
	copy(result[:], decoded)
	return result, nil
}

func canonicalPath(path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved
	}
	absolute, err := filepath.Abs(path)
	if err == nil {
		return absolute
	}
	return path
}

func boolPtr(value bool) *bool { return &value }
