package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	identityverify "github.com/multiversx/mx-chain-go/cmd/internal/drwaprototypeidentityverify"
	nodeCommon "github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwaprototype/networkidentity"
)

const (
	migrationPlanSchema          = "drwa.s1.prototype-network-identity-migration-plan.v1"
	migrationPlanReadyRehearsal  = "READY_OFFLINE_REHEARSAL_NO_LIVE_AUTHORIZATION"
	migrationPlanReadyCurrentDry = "READY_CURRENT_GENERATION_DRY_PLAN_NO_WRITE"
	extractionCompleteStatus     = "ROLE_AND_LINEAGE_BOUND_METACHAIN_FINAL_WITH_FOUR_OBSERVER_PRECURSOR_NO_NODE_MUTATION"
)

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

type migrationPlanDocument struct {
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

type checkpointTreeEntry struct {
	RelativePath string `json:"relative_path"`
	Type         string `json:"type"`
	Mode         uint32 `json:"mode"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256,omitempty"`
}

type checkpointNodeManifest struct {
	ID              string                `json:"id"`
	SourceRoot      string                `json:"source_root"`
	DestinationRoot string                `json:"destination_root"`
	Entries         []checkpointTreeEntry `json:"entries"`
}

type checkpointCopyManifest struct {
	Schema     string                   `json:"schema"`
	Status     string                   `json:"status"`
	CreatedUTC string                   `json:"created_utc"`
	Nodes      []checkpointNodeManifest `json:"nodes"`
}

type checkpointTreeScan struct {
	Entries    []checkpointTreeEntry
	Identities map[string]string
}

type heldMigrationTarget struct {
	nodeRoot   *heldDirectory
	shardRoot  *heldDirectory
	target     *heldDirectory
	targetPath string
	targetName string
}

func runCheckpoint(opts options, epoch uint32, expectedHash, expectedDomain [32]byte) error {
	if opts.checkpointOutputPath == "" || opts.migrationPlanPath == "" || opts.expectedMigrationPlanSHA == "" ||
		opts.extractionEvidencePath == "" || opts.expectedExtractionEvidenceSHA == "" || opts.headerPath == "" {
		return errors.New("checkpoint requires output, migration-plan, extraction-evidence, and header identities")
	}
	planFile, plan, err := verifyMigrationPlan(opts, epoch, expectedHash, expectedDomain)
	if err != nil {
		return err
	}
	defer planFile.file.Close()
	if plan.Status != migrationPlanReadyRehearsal {
		return errors.New("checkpoint generation requires an offline-rehearsal plan")
	}
	if plan.CheckpointManifestSHA256 != "" {
		return errors.New("checkpoint draft plan must not predeclare an output SHA")
	}
	forbiddenRoots := make([]string, 0, len(plan.Nodes)*3)
	for _, node := range plan.Nodes {
		forbiddenRoots = append(forbiddenRoots, node.SourceNodeRoot, node.NodeRoot, node.TargetDBPath)
	}
	if err = identityverify.ValidateExactArtifactOutput(
		plan.RehearsalRoot,
		opts.checkpointOutputPath,
		"checkpoint-copy-manifest.json",
		forbiddenRoots,
		[]string{
			opts.migrationPlanPath, opts.extractionEvidencePath, opts.headerPath, opts.bindingPath,
			plan.TransitionPlanPath, plan.TransitionTracePath, plan.CandidateBinaryPath,
			plan.ValidatorConfigPath, plan.ObserverConfigPath,
		},
	); err != nil {
		return fmt.Errorf("checkpoint output locus: %w", err)
	}
	outputPath, err := canonicalCreatedPath(opts.checkpointOutputPath)
	if err != nil {
		return fmt.Errorf("checkpoint output: %w", err)
	}
	plannedOutputPath, err := canonicalCreatedPath(plan.CheckpointManifestPath)
	if err != nil {
		return fmt.Errorf("planned checkpoint output: %w", err)
	}
	if outputPath != plannedOutputPath {
		return errors.New("checkpoint output differs from the draft migration plan")
	}
	headerFile, err := openRegularFileNoSymlink(opts.headerPath, plan.HeaderSHA256)
	if err != nil {
		return fmt.Errorf("header artifact: %w", err)
	}
	defer headerFile.file.Close()
	if _, err = verifyHeader(opts.chainID, epoch, headerFile.bytes, expectedHash, expectedDomain); err != nil {
		return err
	}
	bindingFile, err := openRegularFileNoSymlink(opts.bindingPath, opts.expectedBindingSHA)
	if err != nil {
		return fmt.Errorf("binding: %w", err)
	}
	defer bindingFile.file.Close()
	if err = verifyBindingBytes(bindingFile.bytes, expectedHash, expectedDomain); err != nil {
		return err
	}
	extractionFile, err := verifyExtractionEvidence(opts, plan, headerFile, bindingFile)
	if err != nil {
		return err
	}
	defer extractionFile.file.Close()
	if err = verifyMigrationPlanLineage(plan); err != nil {
		return err
	}
	if err = verifyCandidateArtifacts(plan); err != nil {
		return err
	}

	manifest, err := buildCheckpointManifest(plan, opts, scanCheckpointTree)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return writeExclusiveDurable(outputPath, append(encoded, '\n'), 0o600)
}

func buildCheckpointManifest(
	plan migrationPlanDocument,
	opts options,
	scanner func(string) (checkpointTreeScan, error),
) (checkpointCopyManifest, error) {
	manifest := checkpointCopyManifest{
		Schema:     "drwa.s1.prototype-network-identity-checkpoint-copy.v1",
		Status:     "CLOSED_SOURCE_TO_ISOLATED_DESTINATION_BYTE_IDENTICAL",
		CreatedUTC: time.Now().UTC().Format(time.RFC3339Nano),
		Nodes:      make([]checkpointNodeManifest, 0, len(plan.Nodes)),
	}
	allSourceIdentities := make(map[string]string)
	allDestinationIdentities := make(map[string]string)
	nodes := append([]migrationPlanNode(nil), plan.Nodes...)
	sort.Slice(nodes, func(left, right int) bool { return nodes[left].ID < nodes[right].ID })
	var err error
	for _, node := range nodes {
		if err = requireNodeStopped(node.SourceNodeRoot); err != nil {
			return checkpointCopyManifest{}, fmt.Errorf("checkpoint source %s is not closed: %w", node.ID, err)
		}
		if err = requireNodeStopped(node.NodeRoot); err != nil {
			return checkpointCopyManifest{}, fmt.Errorf("checkpoint destination %s is not closed: %w", node.ID, err)
		}
		targetOpts := opts
		targetOpts.nodeRoot = node.NodeRoot
		targetOpts.targetDBPath = node.TargetDBPath
		targetOpts.shardID = node.ShardID
		target, targetErr := verifyAndHoldMigrationTarget(targetOpts, node)
		if targetErr != nil {
			return checkpointCopyManifest{}, fmt.Errorf("checkpoint destination %s target: %w", node.ID, targetErr)
		}
		targetExists := target.target != nil
		target.close()
		if targetExists {
			return checkpointCopyManifest{}, fmt.Errorf("checkpoint destination %s already contains the migration target", node.ID)
		}
		sourceScan, scanErr := scanner(node.SourceNodeRoot)
		if scanErr != nil {
			return checkpointCopyManifest{}, fmt.Errorf("scan checkpoint source %s: %w", node.ID, scanErr)
		}
		destinationScan, scanErr := scanner(node.NodeRoot)
		if scanErr != nil {
			return checkpointCopyManifest{}, fmt.Errorf("scan checkpoint destination %s: %w", node.ID, scanErr)
		}
		if !equalCheckpointEntries(sourceScan.Entries, destinationScan.Entries) {
			return checkpointCopyManifest{}, fmt.Errorf("checkpoint destination %s is not byte/mode-identical to its source", node.ID)
		}
		if err = mergeDisjointCheckpointIdentities(allSourceIdentities, sourceScan.Identities, "source "+node.ID); err != nil {
			return checkpointCopyManifest{}, err
		}
		if err = mergeDisjointCheckpointIdentities(allDestinationIdentities, destinationScan.Identities, "destination "+node.ID); err != nil {
			return checkpointCopyManifest{}, err
		}
		manifest.Nodes = append(manifest.Nodes, checkpointNodeManifest{
			ID:              node.ID,
			SourceRoot:      node.SourceNodeRoot,
			DestinationRoot: node.NodeRoot,
			Entries:         sourceScan.Entries,
		})
	}
	if err = requireDisjointCheckpointIdentities(allSourceIdentities, allDestinationIdentities); err != nil {
		return checkpointCopyManifest{}, err
	}
	return manifest, nil
}

func (target *heldMigrationTarget) close() {
	if target.target != nil {
		_ = target.target.file.Close()
	}
	if target.shardRoot != nil {
		_ = target.shardRoot.file.Close()
	}
	if target.nodeRoot != nil {
		_ = target.nodeRoot.file.Close()
	}
}

func runNodeBound(opts options, epoch uint32, expectedHash, expectedDomain [32]byte) error {
	if opts.headerPath == "" || opts.targetDBPath == "" || opts.nodeRoot == "" || opts.shardID == "" || opts.evidencePath == "" {
		return errors.New("plan/rehearse require header, target-db, node-root, shard-id, and evidence")
	}
	if opts.migrationPlanPath == "" || opts.expectedMigrationPlanSHA == "" || opts.extractionEvidencePath == "" || opts.expectedExtractionEvidenceSHA == "" {
		return errors.New("plan/rehearse require migration-plan and extraction-evidence paths and expected SHAs")
	}

	planFile, plan, err := verifyMigrationPlan(opts, epoch, expectedHash, expectedDomain)
	if err != nil {
		return err
	}
	defer planFile.file.Close()
	headerFile, err := openRegularFileNoSymlink(opts.headerPath, plan.HeaderSHA256)
	if err != nil {
		return fmt.Errorf("header artifact: %w", err)
	}
	defer headerFile.file.Close()
	verified, err := verifyHeader(opts.chainID, epoch, headerFile.bytes, expectedHash, expectedDomain)
	if err != nil {
		return err
	}
	bindingFile, err := openRegularFileNoSymlink(opts.bindingPath, opts.expectedBindingSHA)
	if err != nil {
		return fmt.Errorf("binding: %w", err)
	}
	defer bindingFile.file.Close()
	if err = verifyBindingBytes(bindingFile.bytes, expectedHash, expectedDomain); err != nil {
		return err
	}
	extractionFile, err := verifyExtractionEvidence(opts, plan, headerFile, bindingFile)
	if err != nil {
		return err
	}
	defer extractionFile.file.Close()
	if err = verifyMigrationPlanLineage(plan); err != nil {
		return err
	}
	if plan.Status == migrationPlanReadyRehearsal {
		if err = verifyCheckpointCopyManifest(plan); err != nil {
			return err
		}
	} else if plan.CheckpointManifestPath != "" || plan.CheckpointManifestSHA256 != "" {
		return errors.New("current-generation dry plan must not claim a closed checkpoint-copy manifest")
	}
	if err = verifyCandidateArtifacts(plan); err != nil {
		return err
	}

	entry, err := selectMigrationNode(plan, opts)
	if err != nil {
		return err
	}
	target, err := verifyAndHoldMigrationTarget(opts, entry)
	if err != nil {
		return err
	}
	defer target.close()
	if target.target != nil {
		return errors.New("target DB already exists; read-only plan refuses to open a possibly live database and cannot prove absence")
	}

	evidence, err := newEvidence(opts.mode, "", opts, epoch, verified)
	if err != nil {
		return err
	}
	evidence.BindingPath = bindingFile.path
	evidence.BindingSHA256 = bindingFile.sha256
	evidence.HeaderOutputPath = headerFile.path
	evidence.TargetDBPath = target.targetPath
	evidence.NodeRoot = target.nodeRoot.path
	evidence.ShardID = opts.shardID
	evidence.TargetAbsentBefore = boolPtr(true)
	if opts.mode == "plan" {
		evidence.Status = "DRY_VALIDATED_16_NODE_PLAN_BOUND_ABSENT_TARGET_NO_NODE_MUTATION"
		return writeEvidence(opts.evidencePath, evidence)
	}
	return errors.New("write mode is unreachable from the production command")
}

func verifyMigrationPlan(opts options, epoch uint32, expectedHash, expectedDomain [32]byte) (*heldFile, migrationPlanDocument, error) {
	planFile, err := openRegularFileNoSymlink(opts.migrationPlanPath, opts.expectedMigrationPlanSHA)
	if err != nil {
		return nil, migrationPlanDocument{}, fmt.Errorf("migration plan: %w", err)
	}
	fail := func(reason error) (*heldFile, migrationPlanDocument, error) {
		_ = planFile.file.Close()
		return nil, migrationPlanDocument{}, reason
	}
	var plan migrationPlanDocument
	if err = strictDecodeJSON(planFile.bytes, &plan); err != nil {
		return fail(fmt.Errorf("decode migration plan: %w", err))
	}
	if plan.Schema != migrationPlanSchema {
		return fail(fmt.Errorf("migration plan schema %q is not %s", plan.Schema, migrationPlanSchema))
	}
	if plan.Status != migrationPlanReadyRehearsal && plan.Status != migrationPlanReadyCurrentDry {
		return fail(fmt.Errorf("migration plan status %q is not an accepted read-only status", plan.Status))
	}
	if !isCanonicalUTCTimestamp(plan.CreatedUTC) {
		return fail(errors.New("migration plan created_utc is not canonical UTC"))
	}
	if plan.ChainID != opts.chainID || plan.CanonicalEpoch != epoch ||
		plan.CanonicalHash != hex.EncodeToString(expectedHash[:]) ||
		plan.NetworkDomain != hex.EncodeToString(expectedDomain[:]) {
		return fail(errors.New("migration plan network identity differs from requested identity"))
	}
	if plan.BindingSHA256 != opts.expectedBindingSHA || plan.ExtractionEvidenceSHA256 != opts.expectedExtractionEvidenceSHA {
		return fail(errors.New("migration plan binding or extraction evidence SHA differs from CLI binding"))
	}
	if err = requireExactCanonicalPath(plan.BindingPath, opts.bindingPath, "binding"); err != nil {
		return fail(err)
	}
	if err = requireExactCanonicalPath(plan.ExtractionEvidencePath, opts.extractionEvidencePath, "extraction evidence"); err != nil {
		return fail(err)
	}
	if err = requireExactCanonicalPath(plan.HeaderPath, opts.headerPath, "header"); err != nil {
		return fail(err)
	}
	if plan.Status == migrationPlanReadyRehearsal {
		if plan.RehearsalRoot == "" || opts.rehearsalRoot == "" {
			return fail(errors.New("offline rehearsal migration plan and CLI require rehearsal-root"))
		}
		if err = requireExactCanonicalPath(plan.RehearsalRoot, opts.rehearsalRoot, "rehearsal root"); err != nil {
			return fail(err)
		}
	} else if plan.RehearsalRoot != "" || opts.rehearsalRoot != "" {
		return fail(errors.New("current-generation dry plan must not claim a rehearsal root"))
	}
	if err = validateMigrationPlanNodes(plan); err != nil {
		return fail(err)
	}
	return planFile, plan, nil
}

func validateMigrationPlanNodes(plan migrationPlanDocument) error {
	if len(plan.Nodes) != 16 {
		return fmt.Errorf("migration plan requires exactly 16 nodes, found %d", len(plan.Nodes))
	}
	rootIDs := make(map[string]struct{})
	sourceRootIDs := make(map[string]struct{})
	rootFilesystemIDs := make(map[string]string)
	sourceFilesystemIDs := make(map[string]string)
	targetIDs := make(map[string]struct{})
	shardCounts := make(map[string]int)
	observerCounts := make(map[string]int)
	validatorCount := 0
	for _, node := range plan.Nodes {
		if !identityverify.IsSafeArtifactComponent(node.ID) || (node.Role != "observer" && node.Role != "validator") || !supportedShard(node.ShardID) {
			return fmt.Errorf("invalid migration node identity %q", node.ID)
		}
		root, err := canonicalNoSymlinkPath(node.NodeRoot)
		if err != nil || root != node.NodeRoot {
			return fmt.Errorf("migration node %s root is not canonical/no-symlink: %w", node.ID, err)
		}
		if plan.Status == migrationPlanReadyRehearsal && !pathWithin(plan.RehearsalRoot, root) {
			return fmt.Errorf("migration node %s root is outside rehearsal root", node.ID)
		}
		sourceRoot, err := canonicalNoSymlinkPath(node.SourceNodeRoot)
		if err != nil || sourceRoot != node.SourceNodeRoot {
			return fmt.Errorf("migration node %s source root is not canonical/no-symlink: %w", node.ID, err)
		}
		if node.SourceRootDevice == 0 || node.SourceRootInode == 0 || node.NodeRootDevice == 0 || node.NodeRootInode == 0 {
			return fmt.Errorf("migration node %s has zero filesystem identity", node.ID)
		}
		expectedTarget := filepath.Join(root, "db", plan.ChainID, "Static", "Shard_"+node.ShardID, "PrototypeNetworkIdentityStorageDB")
		if filepath.Clean(node.TargetDBPath) != expectedTarget {
			return fmt.Errorf("migration node %s target does not equal exact shard path", node.ID)
		}
		if _, duplicate := rootIDs[root]; duplicate {
			return fmt.Errorf("duplicate migration node root %s", root)
		}
		if _, duplicate := sourceRootIDs[sourceRoot]; duplicate {
			return fmt.Errorf("duplicate migration source root %s", sourceRoot)
		}
		sourceIdentity := fmt.Sprintf("%d:%d", node.SourceRootDevice, node.SourceRootInode)
		if previous, duplicate := sourceFilesystemIDs[sourceIdentity]; duplicate {
			return fmt.Errorf("migration source roots %s and %s alias filesystem identity %s", previous, node.ID, sourceIdentity)
		}
		destinationIdentity := fmt.Sprintf("%d:%d", node.NodeRootDevice, node.NodeRootInode)
		if previous, duplicate := rootFilesystemIDs[destinationIdentity]; duplicate {
			return fmt.Errorf("migration destination roots %s and %s alias filesystem identity %s", previous, node.ID, destinationIdentity)
		}
		if _, duplicate := targetIDs[node.TargetDBPath]; duplicate {
			return fmt.Errorf("duplicate migration target %s", node.TargetDBPath)
		}
		rootIDs[root] = struct{}{}
		sourceRootIDs[sourceRoot] = struct{}{}
		sourceFilesystemIDs[sourceIdentity] = node.ID
		rootFilesystemIDs[destinationIdentity] = node.ID
		targetIDs[node.TargetDBPath] = struct{}{}
		shardCounts[node.ShardID]++
		if node.Role == "observer" {
			observerCounts[node.ShardID]++
		} else {
			validatorCount++
		}
	}
	for _, shard := range []string{"0", "1", "2", "metachain"} {
		if shardCounts[shard] != 4 || observerCounts[shard] != 1 {
			return fmt.Errorf("migration plan shard %s requires four nodes including exactly one observer", shard)
		}
	}
	if validatorCount != 12 {
		return fmt.Errorf("migration plan requires 12 validators, found %d", validatorCount)
	}
	return nil
}

func selectMigrationNode(plan migrationPlanDocument, opts options) (migrationPlanNode, error) {
	nodeRoot, err := canonicalNoSymlinkPath(opts.nodeRoot)
	if err != nil {
		return migrationPlanNode{}, fmt.Errorf("node root: %w", err)
	}
	targetAbsolute, err := filepath.Abs(opts.targetDBPath)
	if err != nil {
		return migrationPlanNode{}, err
	}
	for _, node := range plan.Nodes {
		if node.NodeRoot == nodeRoot {
			if node.ShardID != opts.shardID || node.TargetDBPath != filepath.Clean(targetAbsolute) {
				return migrationPlanNode{}, errors.New("caller shard or target differs from exact 16-node migration-plan entry")
			}
			return node, nil
		}
	}
	return migrationPlanNode{}, errors.New("node root is not listed in exact 16-node migration plan")
}

func verifyExtractionEvidence(opts options, plan migrationPlanDocument, headerFile, bindingFile *heldFile) (*heldFile, error) {
	file, err := openRegularFileNoSymlink(opts.extractionEvidencePath, opts.expectedExtractionEvidenceSHA)
	if err != nil {
		return nil, fmt.Errorf("extraction evidence: %w", err)
	}
	fail := func(reason error) (*heldFile, error) {
		_ = file.file.Close()
		return nil, reason
	}
	var evidence migrationEvidence
	if err = strictDecodeJSON(file.bytes, &evidence); err != nil {
		return fail(fmt.Errorf("decode extraction evidence: %w", err))
	}
	if evidence.Mode != "extract" || evidence.Status != extractionCompleteStatus || evidence.Provenance != "NOT_APPLIED_EXTRACTION_ONLY" || evidence.AuthoritativeRuntimeCredit != 0 {
		return fail(errors.New("extraction evidence status/provenance boundary mismatch"))
	}
	if evidence.Schema != "drwa.s1.prototype-network-identity-migration.v2" || !isCanonicalUTCTimestamp(evidence.TimestampUTC) {
		return fail(errors.New("extraction evidence schema or timestamp mismatch"))
	}
	if evidence.ChainID != plan.ChainID || evidence.CanonicalEpoch != plan.CanonicalEpoch ||
		evidence.CanonicalHash != plan.CanonicalHash || evidence.NetworkDomain != plan.NetworkDomain {
		return fail(errors.New("extraction evidence identity differs from migration plan"))
	}
	if evidence.HeaderSHA256 != headerFile.sha256 || plan.HeaderSHA256 != headerFile.sha256 ||
		evidence.BindingSHA256 != bindingFile.sha256 || plan.BindingSHA256 != bindingFile.sha256 {
		return fail(errors.New("extraction evidence header or binding hash differs from held inputs"))
	}
	if evidence.HeaderLength != len(headerFile.bytes) {
		return fail(errors.New("extraction evidence header length differs from held header"))
	}
	expectedHash, decodeErr := decode32("plan canonical hash", plan.CanonicalHash)
	if decodeErr != nil {
		return fail(decodeErr)
	}
	expectedDomain, decodeErr := decode32("plan network domain", plan.NetworkDomain)
	if decodeErr != nil {
		return fail(decodeErr)
	}
	expectedEnvelope, encodeErr := networkidentity.Encode(networkidentity.Record{
		SchemaVersion: networkidentity.Version,
		Epoch:         plan.CanonicalEpoch,
		Provenance:    networkidentity.EmergencyMigration,
		ChainID:       []byte(plan.ChainID),
		CanonicalHash: expectedHash,
		NetworkDomain: expectedDomain,
		HeaderBytes:   headerFile.bytes,
	})
	if encodeErr != nil {
		return fail(fmt.Errorf("encode expected extraction envelope: %w", encodeErr))
	}
	expectedEnvelopeSHA := sha256.Sum256(expectedEnvelope)
	if evidence.IdentitySchemaVersion != networkidentity.Version ||
		evidence.StorageKeyHex != hex.EncodeToString(networkidentity.Key(plan.CanonicalEpoch)) ||
		evidence.EnvelopeSHA256 != hex.EncodeToString(expectedEnvelopeSHA[:]) ||
		evidence.EnvelopeLength != len(expectedEnvelope) {
		return fail(errors.New("extraction evidence v2 key or envelope identity mismatch"))
	}
	if evidence.TransitionPlanPath == "" || evidence.TransitionPlanSHA256 == "" ||
		evidence.TransitionTracePath == "" || evidence.TransitionTraceSHA256 == "" ||
		evidence.MainConfigSHA256 == "" || evidence.NodesSetupSHA256 == "" {
		return fail(errors.New("extraction evidence omits transition/config lineage identities"))
	}
	if plan.TransitionPlanPath != evidence.TransitionPlanPath || plan.TransitionPlanSHA256 != evidence.TransitionPlanSHA256 ||
		plan.TransitionTracePath != evidence.TransitionTracePath || plan.TransitionTraceSHA256 != evidence.TransitionTraceSHA256 ||
		plan.MainConfigSHA256 != evidence.MainConfigSHA256 || plan.NodesSetupSHA256 != evidence.NodesSetupSHA256 {
		return fail(errors.New("migration plan does not exactly bind extraction transition/config lineage"))
	}
	if err = requireExactCanonicalPath(evidence.HeaderOutputPath, headerFile.path, "extracted header"); err != nil {
		return fail(err)
	}
	if err = requireExactCanonicalPath(evidence.BindingPath, bindingFile.path, "extraction binding"); err != nil {
		return fail(err)
	}
	if len(evidence.ObserverObservations) != 4 {
		return fail(errors.New("extraction evidence does not contain four typed observer observations"))
	}
	roles := make(map[string]observerObservationEvidence)
	rootIdentities := make(map[string]string)
	var expectedPartitions []int
	var precursorSHA string
	var precursorBlake string
	expectedMetaDBs := make([]string, 0, 4)
	expectedRootIdentities := make([]string, 0, 4)
	globalPartitionIdentities := make(map[string]string)
	for _, observation := range evidence.ObserverObservations {
		if _, duplicate := roles[observation.Role]; duplicate {
			return fail(fmt.Errorf("duplicate extraction observer role %s", observation.Role))
		}
		canonicalRoot, pathErr := canonicalNoSymlinkPath(observation.CanonicalRoot)
		if pathErr != nil || canonicalRoot != observation.CanonicalRoot {
			return fail(fmt.Errorf("extraction observer role %s root is not canonical/no-symlink: %w", observation.Role, pathErr))
		}
		rootInfo, statErr := os.Stat(canonicalRoot)
		if statErr != nil {
			return fail(fmt.Errorf("stat extraction observer role %s root: %w", observation.Role, statErr))
		}
		rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
		if !ok || uint64(rootStat.Dev) != observation.RootDevice || rootStat.Ino != observation.RootInode {
			return fail(fmt.Errorf("extraction observer role %s root filesystem identity mismatch", observation.Role))
		}
		rootIdentity := fmt.Sprintf("%d:%d", observation.RootDevice, observation.RootInode)
		if previous, duplicate := rootIdentities[rootIdentity]; duplicate {
			return fail(fmt.Errorf("extraction observer roles %s and %s alias root identity %s", previous, observation.Role, rootIdentity))
		}
		rootIdentities[rootIdentity] = observation.Role
		roles[observation.Role] = observation
	}
	for _, role := range []string{"0", "1", "2", "metachain"} {
		observation, exists := roles[role]
		if !exists || observation.PrecursorMatchCount != 1 || len(observation.NumericPartitions) == 0 || len(observation.PartitionIdentities) != len(observation.NumericPartitions) {
			return fail(fmt.Errorf("incomplete extraction observation for role %s", role))
		}
		for index, partition := range observation.NumericPartitions {
			if partition != index {
				return fail(fmt.Errorf("extraction observer role %s partition set is not exact contiguous 0..N-1", role))
			}
		}
		if expectedPartitions == nil {
			expectedPartitions = append([]int(nil), observation.NumericPartitions...)
		} else if !equalInts(expectedPartitions, observation.NumericPartitions) {
			return fail(fmt.Errorf("extraction observer role %s partition set differs", role))
		}
		for index, encoded := range observation.PartitionIdentities {
			partition, identity, parseErr := parsePartitionIdentity(encoded)
			if parseErr != nil || partition != observation.NumericPartitions[index] {
				return fail(fmt.Errorf("extraction observer role %s has malformed or misbound partition identity %q", role, encoded))
			}
			if previous, duplicate := globalPartitionIdentities[identity]; duplicate {
				return fail(fmt.Errorf("extraction observer partitions %s and %s:%d alias filesystem identity %s", previous, role, partition, identity))
			}
			globalPartitionIdentities[identity] = fmt.Sprintf("%s:%d", role, partition)
		}
		if _, decodeErr := decode32("precursor-sha256", observation.PrecursorSHA256); decodeErr != nil {
			return fail(fmt.Errorf("extraction observer role %s precursor SHA: %w", role, decodeErr))
		}
		if _, decodeErr := decode32("precursor-blake2b", observation.PrecursorBlake2b); decodeErr != nil {
			return fail(fmt.Errorf("extraction observer role %s precursor Blake2b: %w", role, decodeErr))
		}
		if precursorSHA == "" {
			precursorSHA = observation.PrecursorSHA256
			precursorBlake = observation.PrecursorBlake2b
		} else if observation.PrecursorSHA256 != precursorSHA || observation.PrecursorBlake2b != precursorBlake {
			return fail(fmt.Errorf("extraction observer role %s precursor digests differ from four-role set", role))
		}
		expectedMetaDBs = append(expectedMetaDBs, observation.CanonicalRoot)
		expectedRootIdentities = append(expectedRootIdentities, fmt.Sprintf(
			"%s:%d:%d:%s",
			observation.Role,
			observation.RootDevice,
			observation.RootInode,
			observation.CanonicalRoot,
		))
		if role == "metachain" {
			if observation.FinalMatchCount != 1 || observation.FinalSHA256 != headerFile.sha256 || observation.FinalBlake2b != plan.CanonicalHash {
				return fail(errors.New("metachain finalized extraction observation mismatch"))
			}
		} else if observation.FinalMatchCount != 0 || observation.FinalSHA256 != "" || observation.FinalBlake2b != "" {
			return fail(fmt.Errorf("shard %s extraction observation unexpectedly has finalized header", role))
		}
	}
	if evidence.PrecursorSHA256 != precursorSHA || evidence.PrecursorBlake2b != precursorBlake {
		return fail(errors.New("extraction evidence top-level precursor digests differ from typed observations"))
	}
	if !equalStrings(evidence.ObserverMetaDBs, expectedMetaDBs) {
		return fail(errors.New("extraction evidence observer_meta_dbs differ from typed observations"))
	}
	if !equalStrings(evidence.ObserverRootIdentities, expectedRootIdentities) {
		return fail(errors.New("extraction evidence observer_root_identities differ from typed observations"))
	}
	return file, nil
}

func verifyMigrationPlanLineage(plan migrationPlanDocument) error {
	transitionPlanFile, err := openRegularFileNoSymlink(plan.TransitionPlanPath, plan.TransitionPlanSHA256)
	if err != nil {
		return fmt.Errorf("migration lineage transition plan: %w", err)
	}
	defer transitionPlanFile.file.Close()
	transitionTraceFile, err := openRegularFileNoSymlink(plan.TransitionTracePath, plan.TransitionTraceSHA256)
	if err != nil {
		return fmt.Errorf("migration lineage transition trace: %w", err)
	}
	defer transitionTraceFile.file.Close()
	var transitionPlan transitionPlanDocument
	var transitionTrace transitionTraceDocument
	if err = decodeJSONNoDuplicates(transitionPlanFile.bytes, &transitionPlan); err != nil {
		return fmt.Errorf("decode migration lineage transition plan: %w", err)
	}
	if err = decodeJSONNoDuplicates(transitionTraceFile.bytes, &transitionTrace); err != nil {
		return fmt.Errorf("decode migration lineage transition trace: %w", err)
	}
	if transitionPlan.Status != readyTransitionPlan || transitionTrace.Status != verifiedTransitionStatus {
		return errors.New("migration lineage transition plan/trace status mismatch")
	}
	if err = verifyEmbeddedPlan(transitionPlanFile.bytes, transitionTrace.Plan); err != nil {
		return err
	}
	archivedWork, err := canonicalNoSymlinkPath(transitionTrace.ArchivedWork)
	if err != nil {
		return err
	}
	if filepath.Clean(transitionPlan.Targets.ArchivedWork) != archivedWork {
		return errors.New("migration lineage archived-work target differs from executed trace")
	}
	activeRoot, err := deriveActiveWorkRoot(transitionPlan)
	if err != nil {
		return err
	}
	expected := make(map[string]migrationPlanNode)
	for _, process := range transitionPlan.Processes.Nodes {
		workingDirectory, found := argvValue(process.Argv, "-working-directory")
		if !found {
			return errors.New("migration lineage process has no working-directory")
		}
		absoluteWorking, absErr := filepath.Abs(workingDirectory)
		if absErr != nil {
			return absErr
		}
		sourceRoot := filepath.Clean(absoluteWorking)
		if plan.Status == migrationPlanReadyRehearsal {
			relative, relErr := filepath.Rel(activeRoot, sourceRoot)
			if relErr != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
				return errors.New("migration lineage process is outside exact active-work prefix")
			}
			sourceRoot = filepath.Join(archivedWork, relative)
		}
		sourceRoot, err = canonicalNoSymlinkPath(sourceRoot)
		if err != nil {
			return err
		}
		role := "validator"
		shard, observer := argvValue(process.Argv, "-destination-shard-as-observer")
		if observer {
			role = "observer"
			if !supportedShard(shard) {
				return fmt.Errorf("migration lineage observer has unsupported shard %q", shard)
			}
		} else {
			shard, err = deriveOnlyStaticShard(sourceRoot, plan.ChainID)
			if err != nil {
				return fmt.Errorf("derive validator shard for %s: %w", sourceRoot, err)
			}
		}
		info, err := os.Stat(sourceRoot)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("migration lineage source filesystem identity unavailable")
		}
		if _, duplicate := expected[sourceRoot]; duplicate {
			return fmt.Errorf("migration lineage duplicate source root %s", sourceRoot)
		}
		expected[sourceRoot] = migrationPlanNode{Role: role, ShardID: shard, SourceRootDevice: uint64(stat.Dev), SourceRootInode: stat.Ino}
	}
	if len(expected) != 16 {
		return fmt.Errorf("migration lineage transition manifest has %d unique processes, expected 16", len(expected))
	}
	for _, node := range plan.Nodes {
		expectedNode, exists := expected[node.SourceNodeRoot]
		if !exists || node.Role != expectedNode.Role || node.ShardID != expectedNode.ShardID ||
			node.SourceRootDevice != expectedNode.SourceRootDevice || node.SourceRootInode != expectedNode.SourceRootInode {
			return fmt.Errorf("migration node %s role/shard/source identity differs from executed transition lineage", node.ID)
		}
		info, err := os.Stat(node.NodeRoot)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || uint64(stat.Dev) != node.NodeRootDevice || stat.Ino != node.NodeRootInode {
			return fmt.Errorf("migration node %s destination filesystem identity mismatch", node.ID)
		}
	}
	return nil
}

func deriveOnlyStaticShard(nodeRoot, chainID string) (string, error) {
	staticRoot := filepath.Join(nodeRoot, "db", chainID, "Static")
	entries, err := os.ReadDir(staticRoot)
	if err != nil {
		return "", err
	}
	var shards []string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "Shard_") {
			shards = append(shards, strings.TrimPrefix(entry.Name(), "Shard_"))
		}
	}
	if len(shards) != 1 || !supportedShard(shards[0]) {
		return "", fmt.Errorf("expected exactly one supported Static shard, found %v", shards)
	}
	return shards[0], nil
}

func verifyCheckpointCopyManifest(plan migrationPlanDocument) error {
	return verifyCheckpointCopyManifestWithScanner(plan, scanCheckpointTree)
}

func verifyCheckpointCopyManifestWithScanner(
	plan migrationPlanDocument,
	scanner func(string) (checkpointTreeScan, error),
) error {
	if plan.CheckpointManifestPath == "" || plan.CheckpointManifestSHA256 == "" {
		return errors.New("migration plan omits checkpoint-copy manifest identity")
	}
	manifestFile, err := openRegularFileNoSymlink(plan.CheckpointManifestPath, plan.CheckpointManifestSHA256)
	if err != nil {
		return fmt.Errorf("checkpoint-copy manifest: %w", err)
	}
	defer manifestFile.file.Close()
	var manifest checkpointCopyManifest
	if err = strictDecodeJSON(manifestFile.bytes, &manifest); err != nil {
		return fmt.Errorf("decode checkpoint-copy manifest: %w", err)
	}
	if manifest.Schema != "drwa.s1.prototype-network-identity-checkpoint-copy.v1" ||
		manifest.Status != "CLOSED_SOURCE_TO_ISOLATED_DESTINATION_BYTE_IDENTICAL" ||
		!isCanonicalUTCTimestamp(manifest.CreatedUTC) {
		return errors.New("checkpoint-copy manifest schema/status/timestamp mismatch")
	}
	if len(manifest.Nodes) != 16 {
		return fmt.Errorf("checkpoint-copy manifest requires 16 nodes, found %d", len(manifest.Nodes))
	}
	planByID := make(map[string]migrationPlanNode)
	for _, node := range plan.Nodes {
		planByID[node.ID] = node
	}
	seen := make(map[string]struct{})
	allSourceIdentities := make(map[string]string)
	allDestinationIdentities := make(map[string]string)
	for _, nodeManifest := range manifest.Nodes {
		planNode, exists := planByID[nodeManifest.ID]
		if !exists {
			return fmt.Errorf("checkpoint-copy node %s is absent from migration plan", nodeManifest.ID)
		}
		if _, duplicate := seen[nodeManifest.ID]; duplicate {
			return fmt.Errorf("duplicate checkpoint-copy node %s", nodeManifest.ID)
		}
		seen[nodeManifest.ID] = struct{}{}
		if nodeManifest.SourceRoot != planNode.SourceNodeRoot || nodeManifest.DestinationRoot != planNode.NodeRoot {
			return fmt.Errorf("checkpoint-copy node %s roots differ from migration plan", nodeManifest.ID)
		}
		sourceScan, err := scanner(nodeManifest.SourceRoot)
		if err != nil {
			return fmt.Errorf("scan checkpoint source %s: %w", nodeManifest.ID, err)
		}
		destinationScan, err := scanner(nodeManifest.DestinationRoot)
		if err != nil {
			return fmt.Errorf("scan checkpoint destination %s: %w", nodeManifest.ID, err)
		}
		if !equalCheckpointEntries(nodeManifest.Entries, sourceScan.Entries) {
			return fmt.Errorf("checkpoint-copy node %s source tree differs from manifest", nodeManifest.ID)
		}
		if !equalCheckpointEntries(nodeManifest.Entries, destinationScan.Entries) {
			return fmt.Errorf("checkpoint-copy node %s destination tree differs from source manifest", nodeManifest.ID)
		}
		if err = mergeDisjointCheckpointIdentities(allSourceIdentities, sourceScan.Identities, "source "+nodeManifest.ID); err != nil {
			return err
		}
		if err = mergeDisjointCheckpointIdentities(allDestinationIdentities, destinationScan.Identities, "destination "+nodeManifest.ID); err != nil {
			return err
		}
	}
	if err = requireDisjointCheckpointIdentities(allSourceIdentities, allDestinationIdentities); err != nil {
		return err
	}
	return nil
}

func scanCheckpointTree(root string) (checkpointTreeScan, error) {
	canonicalRoot, err := canonicalNoSymlinkPath(root)
	if err != nil {
		return checkpointTreeScan{}, err
	}
	identities := make(map[string]string)
	entries := make([]checkpointTreeEntry, 0)
	err = filepath.WalkDir(canonicalRoot, func(path string, directoryEntry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if directoryEntry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink refused at %s", path)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("filesystem identity unavailable at %s", path)
		}
		relative, err := filepath.Rel(canonicalRoot, path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("checkpoint path escapes root: %s", path)
		}
		entry := checkpointTreeEntry{
			RelativePath: filepath.ToSlash(relative),
			Mode:         uint32(info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)),
			Size:         info.Size(),
		}
		identity := fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
		if previous, duplicate := identities[identity]; duplicate {
			return fmt.Errorf("checkpoint entries %s and %s alias inode %s", previous, relative, identity)
		}
		identities[identity] = relative
		switch {
		case info.IsDir():
			entry.Type = "directory"
			entry.Size = 0
		case info.Mode().IsRegular():
			if stat.Nlink != 1 {
				return fmt.Errorf("hard-linked regular file refused at %s (nlink=%d)", path, stat.Nlink)
			}
			entry.Type = "file"
			digest, err := hashRegularFileNoSymlink(path, info)
			if err != nil {
				return err
			}
			entry.SHA256 = digest
		default:
			return fmt.Errorf("unsupported checkpoint entry type at %s", path)
		}
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return checkpointTreeScan{}, err
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].RelativePath < entries[right].RelativePath })
	return checkpointTreeScan{Entries: entries, Identities: identities}, nil
}

func mergeDisjointCheckpointIdentities(existing, addition map[string]string, label string) error {
	for identity, relative := range addition {
		if previous, duplicate := existing[identity]; duplicate {
			return fmt.Errorf("checkpoint %s identity %s aliases %s", label, identity, previous)
		}
		existing[identity] = label + ":" + relative
	}
	return nil
}

func requireDisjointCheckpointIdentities(source, destination map[string]string) error {
	for identity, destinationPath := range destination {
		if sourcePath, aliasesSource := source[identity]; aliasesSource {
			return fmt.Errorf("checkpoint destination %s aliases source %s at filesystem identity %s", destinationPath, sourcePath, identity)
		}
	}
	return nil
}

func hashRegularFileNoSymlink(path string, before os.FileInfo) (string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return "", errors.New("create checkpoint file handle")
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err = io.Copy(hasher, file); err != nil {
		return "", err
	}
	after, err := file.Stat()
	if err != nil {
		return "", err
	}
	beforeStat, beforeOK := before.Sys().(*syscall.Stat_t)
	afterStat, afterOK := after.Sys().(*syscall.Stat_t)
	if !beforeOK || !afterOK || beforeStat.Dev != afterStat.Dev || beforeStat.Ino != afterStat.Ino ||
		before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		return "", fmt.Errorf("checkpoint file changed while hashing: %s", path)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func equalCheckpointEntries(left, right []checkpointTreeEntry) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func verifyCandidateArtifacts(plan migrationPlanDocument) error {
	binary, err := openRegularFileNoSymlink(plan.CandidateBinaryPath, plan.CandidateBinarySHA256)
	if err != nil {
		return fmt.Errorf("candidate binary: %w", err)
	}
	defer binary.file.Close()
	binaryInfo, err := binary.file.Stat()
	if err != nil {
		return err
	}
	if binaryInfo.Mode().Perm()&0o111 == 0 {
		return errors.New("candidate binary is not executable")
	}
	validator, err := openRegularFileNoSymlink(plan.ValidatorConfigPath, plan.ValidatorConfigSHA256)
	if err != nil {
		return fmt.Errorf("candidate validator config: %w", err)
	}
	defer validator.file.Close()
	observer, err := openRegularFileNoSymlink(plan.ObserverConfigPath, plan.ObserverConfigSHA256)
	if err != nil {
		return fmt.Errorf("candidate observer config: %w", err)
	}
	defer observer.file.Close()
	for name, file := range map[string]*heldFile{"validator": validator, "observer": observer} {
		cfg, loadErr := nodeCommon.LoadMainConfig(procFDPath(file.file))
		if loadErr != nil {
			return fmt.Errorf("production-load candidate %s config: %w", name, loadErr)
		}
		if cfg.GeneralSettings.ChainID != plan.ChainID {
			return fmt.Errorf("candidate %s config chain ID mismatch", name)
		}
		if cfg.PrototypeNetworkIdentityStorage.DB.Type != "LvlDBSerial" ||
			cfg.PrototypeNetworkIdentityStorage.DB.MaxBatchSize != 1 ||
			cfg.PrototypeNetworkIdentityStorage.DB.BatchDelaySeconds < 1 {
			return fmt.Errorf("candidate %s config identity storage is not synchronous", name)
		}
	}
	return nil
}

func equalInts(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func verifyBindingBytes(bindingBytes []byte, expectedHash, expectedDomain [32]byte) error {
	var binding map[string]interface{}
	if err := decodeJSONNoDuplicates(bindingBytes, &binding); err != nil {
		return fmt.Errorf("decode binding: %w", err)
	}
	if binding["canonical_metachain_genesis_hash"] != hex.EncodeToString(expectedHash[:]) {
		return errors.New("binding canonical metachain genesis hash mismatch")
	}
	if binding["network_domain"] != hex.EncodeToString(expectedDomain[:]) {
		return errors.New("binding network domain mismatch")
	}
	return nil
}

func verifyAndHoldMigrationTarget(opts options, entry migrationPlanNode) (*heldMigrationTarget, error) {
	nodeRoot, err := openDirectoryNoSymlink("node-root", entry.NodeRoot)
	if err != nil {
		return nil, err
	}
	if nodeRoot.dev != entry.NodeRootDevice || nodeRoot.ino != entry.NodeRootInode {
		_ = nodeRoot.file.Close()
		return nil, errors.New("node-root filesystem identity differs from exact migration plan")
	}
	target := &heldMigrationTarget{nodeRoot: nodeRoot, targetPath: entry.TargetDBPath, targetName: filepath.Base(entry.TargetDBPath)}
	fail := func(reason error) (*heldMigrationTarget, error) {
		target.close()
		return nil, reason
	}
	staticPath := filepath.Join(nodeRoot.path, "db", opts.chainID, "Static")
	staticRoot, err := openDirectoryNoSymlink("static-root", staticPath)
	if err != nil {
		return fail(err)
	}
	entries, err := staticRoot.file.ReadDir(-1)
	if err != nil {
		_ = staticRoot.file.Close()
		return fail(err)
	}
	var shardNames []string
	for _, item := range entries {
		if item.IsDir() && strings.HasPrefix(item.Name(), "Shard_") {
			shardNames = append(shardNames, item.Name())
		}
	}
	sort.Strings(shardNames)
	expectedShardName := "Shard_" + entry.ShardID
	if len(shardNames) != 1 || shardNames[0] != expectedShardName {
		_ = staticRoot.file.Close()
		return fail(fmt.Errorf("node root proves shard directories %v, expected exactly [%s]", shardNames, expectedShardName))
	}
	shardFD, err := unix.Openat(int(staticRoot.file.Fd()), expectedShardName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	_ = staticRoot.file.Close()
	if err != nil {
		return fail(fmt.Errorf("open exact shard root: %w", err))
	}
	shardFile := os.NewFile(uintptr(shardFD), filepath.Join(staticPath, expectedShardName))
	if shardFile == nil {
		_ = unix.Close(shardFD)
		return fail(errors.New("create shard-root handle"))
	}
	shardInfo, err := shardFile.Stat()
	if err != nil {
		_ = shardFile.Close()
		return fail(err)
	}
	shardStat, ok := shardInfo.Sys().(*syscall.Stat_t)
	if !ok {
		_ = shardFile.Close()
		return fail(errors.New("shard-root filesystem identity unavailable"))
	}
	target.shardRoot = &heldDirectory{role: entry.ShardID, path: filepath.Join(staticPath, expectedShardName), file: shardFile, dev: uint64(shardStat.Dev), ino: shardStat.Ino}

	targetFD, err := unix.Openat(int(shardFile.Fd()), target.targetName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, syscall.ENOENT) {
		return target, nil
	}
	if err != nil {
		return fail(fmt.Errorf("open target DB directory with held parent: %w", err))
	}
	targetFile := os.NewFile(uintptr(targetFD), target.targetPath)
	if targetFile == nil {
		_ = unix.Close(targetFD)
		return fail(errors.New("create target DB handle"))
	}
	targetInfo, err := targetFile.Stat()
	if err != nil {
		_ = targetFile.Close()
		return fail(err)
	}
	targetStat, ok := targetInfo.Sys().(*syscall.Stat_t)
	if !ok {
		_ = targetFile.Close()
		return fail(errors.New("target DB filesystem identity unavailable"))
	}
	target.target = &heldDirectory{role: "target", path: target.targetPath, file: targetFile, dev: uint64(targetStat.Dev), ino: targetStat.Ino}
	return target, nil
}

func requireExactCanonicalPath(left, right, name string) error {
	leftCanonical, err := canonicalNoSymlinkPath(left)
	if err != nil {
		return fmt.Errorf("%s left path: %w", name, err)
	}
	rightCanonical, err := canonicalNoSymlinkPath(right)
	if err != nil {
		return fmt.Errorf("%s right path: %w", name, err)
	}
	if leftCanonical != rightCanonical {
		return fmt.Errorf("%s paths differ: %s != %s", name, leftCanonical, rightCanonical)
	}
	return nil
}

func supportedShard(value string) bool {
	return value == "0" || value == "1" || value == "2" || value == "metachain"
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}
