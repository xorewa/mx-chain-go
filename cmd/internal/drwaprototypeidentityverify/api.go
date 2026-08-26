package drwaprototypeidentityverify

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PlanRequest is the complete, hash-bound input to the DRWA prototype read-only node-plan verifier.
// It intentionally exposes no database-write mode.
type PlanRequest struct {
	ChainID                       string
	Epoch                         uint32
	ExpectedCanonicalHash         string
	ExpectedDomain                string
	BindingPath                   string
	ExpectedBindingSHA            string
	HeaderPath                    string
	TargetDBPath                  string
	NodeRoot                      string
	ShardID                       string
	MigrationPlanPath             string
	ExpectedMigrationPlanSHA      string
	ExtractionEvidencePath        string
	ExpectedExtractionEvidenceSHA string
	RehearsalRoot                 string
	EvidencePath                  string
}

// PlanEvidence is the semantic result of the exact in-process read-only verifier.
type PlanEvidence struct {
	Schema                 string
	Status                 string
	Mode                   string
	ChainID                string
	CanonicalEpoch         uint32
	Provenance             string
	CanonicalHash          string
	NetworkDomain          string
	HeaderSHA256           string
	HeaderLength           int
	IdentitySchemaVersion  byte
	StorageKeyHex          string
	EnvelopeSHA256         string
	EnvelopeLength         int
	HeaderOutputPath       string
	BindingPath            string
	BindingSHA256          string
	TargetDBPath           string
	NodeRoot               string
	ShardID                string
	TargetAbsentBefore     bool
	AuthoritativeRunCredit int
}

// VerifyPlanBoundary runs the same complete held-FD read-only checks used by the command's plan
// mode and returns the evidence in memory. It creates no file and has no write-mode branch.
func VerifyPlanBoundary(request PlanRequest) (PlanEvidence, error) {
	evidence, err := verifyPlanBoundaryEvidence(optionsFromRequest(request))
	if err != nil {
		return PlanEvidence{}, err
	}
	if evidence.TargetAbsentBefore == nil {
		return PlanEvidence{}, errors.New("plan verifier did not establish target absence")
	}
	return PlanEvidence{
		Schema: evidence.Schema, Status: evidence.Status, Mode: evidence.Mode,
		ChainID: evidence.ChainID, CanonicalEpoch: evidence.CanonicalEpoch,
		Provenance: evidence.Provenance, CanonicalHash: evidence.CanonicalHash,
		NetworkDomain: evidence.NetworkDomain, HeaderSHA256: evidence.HeaderSHA256,
		HeaderLength: evidence.HeaderLength, IdentitySchemaVersion: evidence.IdentitySchemaVersion,
		StorageKeyHex: evidence.StorageKeyHex, EnvelopeSHA256: evidence.EnvelopeSHA256,
		EnvelopeLength: evidence.EnvelopeLength, HeaderOutputPath: evidence.HeaderOutputPath,
		BindingPath: evidence.BindingPath, BindingSHA256: evidence.BindingSHA256,
		TargetDBPath: evidence.TargetDBPath, NodeRoot: evidence.NodeRoot, ShardID: evidence.ShardID,
		TargetAbsentBefore:     *evidence.TargetAbsentBefore,
		AuthoritativeRunCredit: evidence.AuthoritativeRuntimeCredit,
	}, nil
}

// RunPlanAndWriteEvidence is the command adapter. It calls VerifyPlanBoundary's private full check
// and only then emits the existing O_EXCL evidence record.
func RunPlanAndWriteEvidence(request PlanRequest) error {
	if request.EvidencePath == "" {
		return errors.New("evidence path is required")
	}
	evidence, err := verifyPlanBoundaryEvidence(optionsFromRequest(request))
	if err != nil {
		return err
	}
	return writeEvidence(request.EvidencePath, evidence)
}

func optionsFromRequest(request PlanRequest) options {
	return options{
		mode: "plan", chainID: request.ChainID, epoch: uint(request.Epoch),
		expectedCanonicalHash: request.ExpectedCanonicalHash, expectedDomain: request.ExpectedDomain,
		bindingPath: request.BindingPath, expectedBindingSHA: request.ExpectedBindingSHA,
		headerPath: request.HeaderPath, targetDBPath: request.TargetDBPath,
		nodeRoot: request.NodeRoot, shardID: request.ShardID, evidencePath: request.EvidencePath,
		migrationPlanPath: request.MigrationPlanPath, expectedMigrationPlanSHA: request.ExpectedMigrationPlanSHA,
		extractionEvidencePath:        request.ExtractionEvidencePath,
		expectedExtractionEvidenceSHA: request.ExpectedExtractionEvidenceSHA,
		rehearsalRoot:                 request.RehearsalRoot,
	}
}

func verifyPlanBoundaryEvidence(opts options) (migrationEvidence, error) {
	if opts.chainID == "" {
		return migrationEvidence{}, errors.New("chain-id is required")
	}
	expectedHash, err := decode32("expected-canonical-hash", opts.expectedCanonicalHash)
	if err != nil {
		return migrationEvidence{}, err
	}
	expectedDomain, err := decode32("expected-domain", opts.expectedDomain)
	if err != nil {
		return migrationEvidence{}, err
	}
	epoch := uint32(opts.epoch)
	if opts.headerPath == "" || opts.targetDBPath == "" || opts.nodeRoot == "" || opts.shardID == "" {
		return migrationEvidence{}, errors.New("plan requires header, target-db, node-root, and shard-id")
	}
	if opts.migrationPlanPath == "" || opts.expectedMigrationPlanSHA == "" ||
		opts.extractionEvidencePath == "" || opts.expectedExtractionEvidenceSHA == "" {
		return migrationEvidence{}, errors.New("plan requires migration-plan and extraction-evidence paths and expected SHAs")
	}

	planFile, plan, err := verifyMigrationPlan(opts, epoch, expectedHash, expectedDomain)
	if err != nil {
		return migrationEvidence{}, err
	}
	defer planFile.file.Close()
	entry, err := selectMigrationNode(plan, opts)
	if err != nil {
		return migrationEvidence{}, err
	}
	if opts.evidencePath != "" {
		if err = validatePlanEvidencePath(opts, plan, entry); err != nil {
			return migrationEvidence{}, err
		}
	}
	headerFile, err := openRegularFileNoSymlink(opts.headerPath, plan.HeaderSHA256)
	if err != nil {
		return migrationEvidence{}, err
	}
	defer headerFile.file.Close()
	verified, err := verifyHeader(opts.chainID, epoch, headerFile.bytes, expectedHash, expectedDomain)
	if err != nil {
		return migrationEvidence{}, err
	}
	bindingFile, err := openRegularFileNoSymlink(opts.bindingPath, opts.expectedBindingSHA)
	if err != nil {
		return migrationEvidence{}, err
	}
	defer bindingFile.file.Close()
	if err = verifyBindingBytes(bindingFile.bytes, expectedHash, expectedDomain); err != nil {
		return migrationEvidence{}, err
	}
	extractionFile, err := verifyExtractionEvidence(opts, plan, headerFile, bindingFile)
	if err != nil {
		return migrationEvidence{}, err
	}
	defer extractionFile.file.Close()
	if err = verifyMigrationPlanLineage(plan); err != nil {
		return migrationEvidence{}, err
	}
	if plan.Status == migrationPlanReadyRehearsal {
		if err = verifyCheckpointCopyManifest(plan); err != nil {
			return migrationEvidence{}, err
		}
	} else if plan.CheckpointManifestPath != "" || plan.CheckpointManifestSHA256 != "" {
		return migrationEvidence{}, errors.New("current-generation dry plan must not claim a checkpoint manifest")
	}
	if err = verifyCandidateArtifacts(plan); err != nil {
		return migrationEvidence{}, err
	}
	target, err := verifyAndHoldMigrationTarget(opts, entry)
	if err != nil {
		return migrationEvidence{}, err
	}
	defer target.close()
	if target.target != nil {
		return migrationEvidence{}, errors.New("target DB already exists")
	}

	evidence, err := newEvidence("plan", "DRY_VALIDATED_16_NODE_PLAN_BOUND_ABSENT_TARGET_NO_NODE_MUTATION", opts, epoch, verified)
	if err != nil {
		return migrationEvidence{}, err
	}
	evidence.BindingPath = bindingFile.path
	evidence.BindingSHA256 = bindingFile.sha256
	evidence.HeaderOutputPath = headerFile.path
	evidence.TargetDBPath = target.targetPath
	evidence.NodeRoot = target.nodeRoot.path
	evidence.ShardID = opts.shardID
	evidence.TargetAbsentBefore = boolPtr(true)
	return evidence, nil
}

func validatePlanEvidencePath(opts options, plan migrationPlanDocument, entry migrationPlanNode) error {
	forbiddenRoots := make([]string, 0, len(plan.Nodes)*2)
	for _, node := range plan.Nodes {
		forbiddenRoots = append(forbiddenRoots, node.NodeRoot, node.SourceNodeRoot, node.TargetDBPath)
	}
	return ValidateExactArtifactOutput(plan.RehearsalRoot, opts.evidencePath, "plan-"+entry.ID+".json", forbiddenRoots, []string{
		opts.bindingPath, opts.headerPath, opts.migrationPlanPath, opts.extractionEvidencePath,
		plan.TransitionPlanPath, plan.TransitionTracePath, plan.CheckpointManifestPath,
		plan.CandidateBinaryPath, plan.ValidatorConfigPath, plan.ObserverConfigPath,
	})
}

func pathWithinOrEqual(root, candidate string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}

// ValidateExactArtifactOutput constrains a generated offline artifact to one exact direct
// child of <rehearsalRoot>/artifacts, outside every supplied node root/target and input.
func ValidateExactArtifactOutput(
	rehearsalRoot string,
	outputPath string,
	expectedName string,
	forbiddenRoots []string,
	inputPaths []string,
) error {
	if !IsSafeArtifactComponent(expectedName) {
		return errors.New("artifact output name is not one safe direct-child component")
	}
	canonicalRoot, err := canonicalExistingPath(rehearsalRoot)
	if err != nil || canonicalRoot != filepath.Clean(rehearsalRoot) {
		return errors.New("artifact rehearsal root is not canonical/no-symlink")
	}
	artifactsDirectory := filepath.Join(canonicalRoot, "artifacts")
	canonicalArtifacts, err := canonicalExistingPath(artifactsDirectory)
	if err != nil || canonicalArtifacts != artifactsDirectory {
		return errors.New("artifact output directory is not canonical/no-symlink")
	}
	expectedPath := filepath.Join(canonicalArtifacts, expectedName)
	if filepath.Dir(expectedPath) != canonicalArtifacts {
		return errors.New("artifact output is not a direct artifacts child")
	}
	canonicalOutput, err := canonicalCreatedPath(outputPath)
	if err != nil || canonicalOutput != expectedPath {
		return fmt.Errorf("artifact output path must equal %s", expectedPath)
	}
	if _, err = os.Lstat(canonicalOutput); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return errors.New("artifact output path already exists")
		}
		return err
	}
	for _, root := range forbiddenRoots {
		if root != "" && pathWithinOrEqual(root, canonicalOutput) {
			return errors.New("artifact output overlaps a source/destination node root or target")
		}
	}
	for _, inputPath := range inputPaths {
		if inputPath != "" && filepath.Clean(inputPath) == canonicalOutput {
			return errors.New("artifact output aliases a bound input")
		}
	}
	return nil
}

// IsSafeArtifactComponent accepts only a non-special ASCII filename component.
func IsSafeArtifactComponent(value string) bool {
	if value == "" || value == "." || value == ".." || filepath.Base(value) != value {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}
