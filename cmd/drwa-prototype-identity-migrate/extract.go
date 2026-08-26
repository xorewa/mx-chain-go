package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	coreBlake2b "github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"golang.org/x/sys/unix"

	identityverify "github.com/multiversx/mx-chain-go/cmd/internal/drwaprototypeidentityverify"
	nodeCommon "github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
)

const (
	verifiedTransitionStatus = "CONTROLLED_TRANSITION_VERIFIED_NO_CANARY_NO_RUNTIME_CREDIT"
	readyTransitionPlan      = "READY_FOR_OWNER_APPROVED_EXECUTION"
)

type transitionPlanDocument struct {
	CreatedUTC           string `json:"created_utc"`
	Status               string `json:"status"`
	LiveGenerationHashes struct {
		NodesSetup string `json:"nodes_setup"`
	} `json:"live_generation_hashes"`
	LiveHashes struct {
		OldObserver  string `json:"old_observer"`
		OldValidator string `json:"old_validator"`
	} `json:"live_hashes"`
	Processes struct {
		Nodes []struct {
			Argv []string `json:"argv"`
		} `json:"nodes"`
	} `json:"processes"`
	Targets struct {
		ArchivedNode string `json:"archived_node"`
		ArchivedWork string `json:"archived_work"`
	} `json:"targets"`
}

type transitionTraceDocument struct {
	ArchivedNode string          `json:"archived_node"`
	ArchivedWork string          `json:"archived_work"`
	Status       string          `json:"status"`
	Plan         json.RawMessage `json:"plan"`
}

type generationBindingDocument struct {
	CanonicalHash string `json:"canonical_metachain_genesis_hash"`
	NetworkDomain string `json:"network_domain"`
	NodesSetupSHA string `json:"nodes_setup_sha256"`
	StableHashes  struct {
		MainConfig string `json:"main_config"`
	} `json:"stable_hashes"`
}

type heldFile struct {
	path   string
	file   *os.File
	bytes  []byte
	sha256 string
}

type heldDirectory struct {
	role string
	path string
	file *os.File
	dev  uint64
	ino  uint64
}

type extractionContext struct {
	plan                 transitionPlanDocument
	trace                transitionTraceDocument
	binding              generationBindingDocument
	planFile             *heldFile
	traceFile            *heldFile
	bindingFile          *heldFile
	validatorConfigFile  *heldFile
	observerConfigFile   *heldFile
	nodesSetupFile       *heldFile
	archivedNode         string
	archivedWork         string
	chainID              string
	canonicalEpoch       uint32
	metaBlockNumShards   int
	expectedObserverRoot map[string]string
	files                []*heldFile
}

func (context *extractionContext) close() {
	for _, file := range context.files {
		_ = file.file.Close()
	}
}

type scannedObserverRoot struct {
	precursorMatches [][]byte
	finalMatches     [][]byte
	partitions       []int
	partitionIDs     []string
}

func runExtractAmended(opts options, epoch uint32, expectedHash, expectedDomain [32]byte) error {
	return runExtractAmendedWithScanner(opts, epoch, expectedHash, expectedDomain, scanObserverRoot)
}

func runExtractAmendedWithScanner(
	opts options,
	epoch uint32,
	expectedHash, expectedDomain [32]byte,
	scanner func(*heldDirectory, int, string, [32]byte) (scannedObserverRoot, error),
) error {
	if opts.headerOutputPath == "" || opts.evidencePath == "" || opts.rehearsalRoot == "" {
		return errors.New("extract requires rehearsal-root, header-output and evidence")
	}

	context, err := verifyExtractionContext(opts, epoch, expectedHash, expectedDomain)
	if err != nil {
		return err
	}
	defer context.close()
	forbiddenRoots := []string{context.archivedNode, context.archivedWork}
	for _, role := range []string{"0", "1", "2", "metachain"} {
		forbiddenRoots = append(forbiddenRoots, context.expectedObserverRoot[role])
	}
	boundInputs := []string{
		opts.bindingPath, opts.transitionPlanPath, opts.transitionTracePath,
		context.validatorConfigFile.path, context.observerConfigFile.path, context.nodesSetupFile.path,
	}
	if err = identityverify.ValidateExactArtifactOutput(
		opts.rehearsalRoot, opts.headerOutputPath, "canonical-header.bin", forbiddenRoots,
		append(append([]string(nil), boundInputs...), opts.evidencePath),
	); err != nil {
		return fmt.Errorf("extracted-header output locus: %w", err)
	}
	if err = identityverify.ValidateExactArtifactOutput(
		opts.rehearsalRoot, opts.evidencePath, "extraction.json", forbiddenRoots,
		append(append([]string(nil), boundInputs...), opts.headerOutputPath),
	); err != nil {
		return fmt.Errorf("extraction-evidence output locus: %w", err)
	}

	providedRoots := map[string]string{
		"0":         opts.shard0ObserverMetaDB,
		"1":         opts.shard1ObserverMetaDB,
		"2":         opts.shard2ObserverMetaDB,
		"metachain": opts.metachainObserverMetaDB,
	}
	heldRoots := make([]*heldDirectory, 0, 4)
	defer func() {
		for _, root := range heldRoots {
			_ = root.file.Close()
		}
	}()
	identities := make(map[string]string)
	observations := make(map[string]scannedObserverRoot)
	for _, role := range []string{"0", "1", "2", "metachain"} {
		provided := providedRoots[role]
		if provided == "" {
			return fmt.Errorf("observer MetaBlock root for role %s is required", role)
		}
		expected := context.expectedObserverRoot[role]
		actual, err := filepath.Abs(provided)
		if err != nil {
			return fmt.Errorf("resolve observer role %s root: %w", role, err)
		}
		if filepath.Clean(actual) != filepath.Clean(expected) {
			return fmt.Errorf("observer role %s root %s does not equal manifest-derived path %s", role, actual, expected)
		}
		root, err := openDirectoryNoSymlink(role, actual)
		if err != nil {
			return err
		}
		heldRoots = append(heldRoots, root)
		if err = rememberDistinctRootIdentity(identities, root); err != nil {
			return err
		}

		observation, err := scanner(
			root,
			context.metaBlockNumShards,
			core.EpochStartIdentifier(epoch),
			expectedHash,
		)
		if err != nil {
			return fmt.Errorf("observer role %s: %w", role, err)
		}
		observations[role] = observation
	}
	if err = requireGloballyDistinctScannedPartitions(observations); err != nil {
		return err
	}

	var precursor []byte
	for _, role := range []string{"0", "1", "2", "metachain"} {
		observation := observations[role]
		if len(observation.precursorMatches) != 1 {
			return fmt.Errorf("observer role %s expected exactly one precursor, found %d", role, len(observation.precursorMatches))
		}
		candidate := observation.precursorMatches[0]
		if err := verifyPrecursor(context.chainID, context.canonicalEpoch, candidate); err != nil {
			return fmt.Errorf("observer role %s precursor: %w", role, err)
		}
		if precursor == nil {
			precursor = append([]byte(nil), candidate...)
		} else if !bytes.Equal(precursor, candidate) {
			return fmt.Errorf("observer role %s precursor differs from the four-observer set", role)
		}
		if role == "metachain" {
			if len(observation.finalMatches) != 1 {
				return fmt.Errorf("metachain observer expected exactly one finalized header, found %d", len(observation.finalMatches))
			}
		} else if len(observation.finalMatches) != 0 {
			return fmt.Errorf("shard observer role %s unexpectedly contains finalized header", role)
		}
	}

	finalBytes := observations["metachain"].finalMatches[0]
	verified, err := verifyHeader(context.chainID, context.canonicalEpoch, finalBytes, expectedHash, expectedDomain)
	if err != nil {
		return err
	}
	if err = verifyPrecursorFinalRelation(precursor, verified.HeaderBytes); err != nil {
		return err
	}
	if err = writeExclusiveDurable(opts.headerOutputPath, verified.HeaderBytes, 0o600); err != nil {
		return fmt.Errorf("write extracted header: %w", err)
	}

	precursorSHA := sha256.Sum256(precursor)
	precursorBlake := coreBlake2b.NewBlake2b().Compute(string(precursor))
	evidence, err := newEvidence(
		"extract",
		"ROLE_AND_LINEAGE_BOUND_METACHAIN_FINAL_WITH_FOUR_OBSERVER_PRECURSOR_NO_NODE_MUTATION",
		opts,
		epoch,
		verified,
	)
	if err != nil {
		return err
	}
	evidence.ObserverMetaDBs = []string{
		context.expectedObserverRoot["0"],
		context.expectedObserverRoot["1"],
		context.expectedObserverRoot["2"],
		context.expectedObserverRoot["metachain"],
	}
	evidence.BindingPath = context.bindingFile.path
	evidence.BindingSHA256 = context.bindingFile.sha256
	headerOutputPath, err := canonicalCreatedPath(opts.headerOutputPath)
	if err != nil {
		return fmt.Errorf("canonicalize extracted header output: %w", err)
	}
	evidence.HeaderOutputPath = headerOutputPath
	evidence.TransitionPlanPath = context.planFile.path
	evidence.TransitionPlanSHA256 = context.planFile.sha256
	evidence.TransitionTracePath = context.traceFile.path
	evidence.TransitionTraceSHA256 = context.traceFile.sha256
	evidence.ArchivedNodePath = context.archivedNode
	evidence.ArchivedWorkPath = context.archivedWork
	evidence.MainConfigSHA256 = context.validatorConfigFile.sha256
	evidence.NodesSetupSHA256 = context.nodesSetupFile.sha256
	evidence.PrecursorSHA256 = hex.EncodeToString(precursorSHA[:])
	evidence.PrecursorBlake2b = hex.EncodeToString(precursorBlake)
	for _, root := range heldRoots {
		evidence.ObserverRootIdentities = append(
			evidence.ObserverRootIdentities,
			fmt.Sprintf("%s:%d:%d:%s", root.role, root.dev, root.ino, root.path),
		)
		observation := observations[root.role]
		precursorDigest := sha256.Sum256(observation.precursorMatches[0])
		precursorBlake := coreBlake2b.NewBlake2b().Compute(string(observation.precursorMatches[0]))
		typed := observerObservationEvidence{
			Role:                root.role,
			CanonicalRoot:       root.path,
			RootDevice:          root.dev,
			RootInode:           root.ino,
			NumericPartitions:   append([]int(nil), observation.partitions...),
			PartitionIdentities: append([]string(nil), observation.partitionIDs...),
			PrecursorMatchCount: len(observation.precursorMatches),
			PrecursorSHA256:     hex.EncodeToString(precursorDigest[:]),
			PrecursorBlake2b:    hex.EncodeToString(precursorBlake),
			FinalMatchCount:     len(observation.finalMatches),
		}
		if len(observation.finalMatches) == 1 {
			finalDigest := sha256.Sum256(observation.finalMatches[0])
			finalBlake := coreBlake2b.NewBlake2b().Compute(string(observation.finalMatches[0]))
			typed.FinalSHA256 = hex.EncodeToString(finalDigest[:])
			typed.FinalBlake2b = hex.EncodeToString(finalBlake)
		}
		evidence.ObserverObservations = append(evidence.ObserverObservations, typed)
	}
	return writeEvidence(opts.evidencePath, evidence)
}

func requireGloballyDistinctScannedPartitions(observations map[string]scannedObserverRoot) error {
	identities := make(map[string]string)
	for _, role := range []string{"0", "1", "2", "metachain"} {
		observation, exists := observations[role]
		if !exists {
			return fmt.Errorf("missing scanned observer role %s", role)
		}
		if len(observation.partitionIDs) != len(observation.partitions) {
			return fmt.Errorf("observer role %s partition identity count mismatch", role)
		}
		for index, encoded := range observation.partitionIDs {
			partition, identity, parseErr := parsePartitionIdentity(encoded)
			if parseErr != nil || partition != observation.partitions[index] {
				return fmt.Errorf("observer role %s partition identity %q is malformed or misbound", role, encoded)
			}
			if previous, duplicate := identities[identity]; duplicate {
				return fmt.Errorf("observer partitions %s and %s:%d alias filesystem identity %s", previous, role, partition, identity)
			}
			identities[identity] = fmt.Sprintf("%s:%d", role, partition)
		}
	}
	return nil
}

func parsePartitionIdentity(encoded string) (int, string, error) {
	parts := strings.Split(encoded, ":")
	if len(parts) != 3 {
		return 0, "", errors.New("partition identity must contain partition:device:inode")
	}
	partition, err := strconv.Atoi(parts[0])
	if err != nil || partition < 0 {
		return 0, "", errors.New("partition identity has invalid partition")
	}
	device, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || device == 0 {
		return 0, "", errors.New("partition identity has invalid device")
	}
	inode, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil || inode == 0 {
		return 0, "", errors.New("partition identity has invalid inode")
	}
	return partition, fmt.Sprintf("%d:%d", device, inode), nil
}

func canonicalCreatedPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	parent, err := canonicalNoSymlinkPath(filepath.Dir(absolute))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(absolute)), nil
}

func rememberDistinctRootIdentity(identities map[string]string, root *heldDirectory) error {
	identity := fmt.Sprintf("%d:%d", root.dev, root.ino)
	if previousRole, exists := identities[identity]; exists {
		return fmt.Errorf("observer roles %s and %s resolve to duplicate device/inode %s", previousRole, root.role, identity)
	}
	identities[identity] = root.role
	return nil
}

func verifyExtractionContext(opts options, epoch uint32, expectedHash, expectedDomain [32]byte) (*extractionContext, error) {
	if opts.transitionPlanPath == "" || opts.expectedPlanSHA == "" || opts.transitionTracePath == "" || opts.expectedTraceSHA == "" {
		return nil, errors.New("extract requires transition plan/trace paths and expected SHAs")
	}
	if opts.bindingPath == "" || opts.expectedBindingSHA == "" {
		return nil, errors.New("extract requires binding and expected binding SHA")
	}

	context := &extractionContext{}
	var err error
	context.planFile, err = openRegularFileNoSymlink(opts.transitionPlanPath, opts.expectedPlanSHA)
	if err != nil {
		return nil, fmt.Errorf("transition plan: %w", err)
	}
	context.files = append(context.files, context.planFile)
	fail := func(value error) (*extractionContext, error) {
		context.close()
		return nil, value
	}
	context.traceFile, err = openRegularFileNoSymlink(opts.transitionTracePath, opts.expectedTraceSHA)
	if err != nil {
		return fail(fmt.Errorf("transition trace: %w", err))
	}
	context.files = append(context.files, context.traceFile)
	context.bindingFile, err = openRegularFileNoSymlink(opts.bindingPath, opts.expectedBindingSHA)
	if err != nil {
		return fail(fmt.Errorf("generation binding: %w", err))
	}
	context.files = append(context.files, context.bindingFile)

	if err = decodeJSONNoDuplicates(context.planFile.bytes, &context.plan); err != nil {
		return fail(fmt.Errorf("decode transition plan: %w", err))
	}
	if err = decodeJSONNoDuplicates(context.traceFile.bytes, &context.trace); err != nil {
		return fail(fmt.Errorf("decode transition trace: %w", err))
	}
	if err = decodeJSONNoDuplicates(context.bindingFile.bytes, &context.binding); err != nil {
		return fail(fmt.Errorf("decode generation binding: %w", err))
	}
	if context.plan.Status != readyTransitionPlan {
		return fail(fmt.Errorf("transition plan status %q is not %s", context.plan.Status, readyTransitionPlan))
	}
	if context.trace.Status != verifiedTransitionStatus {
		return fail(fmt.Errorf("transition trace status %q is not %s", context.trace.Status, verifiedTransitionStatus))
	}
	if err = verifyEmbeddedPlan(context.planFile.bytes, context.trace.Plan); err != nil {
		return fail(err)
	}

	context.archivedNode, err = canonicalExistingPath(context.trace.ArchivedNode)
	if err != nil {
		return fail(fmt.Errorf("archived node path: %w", err))
	}
	context.archivedWork, err = canonicalExistingPath(context.trace.ArchivedWork)
	if err != nil {
		return fail(fmt.Errorf("archived work path: %w", err))
	}
	if filepath.Clean(context.plan.Targets.ArchivedNode) != context.archivedNode ||
		filepath.Clean(context.plan.Targets.ArchivedWork) != context.archivedWork {
		return fail(errors.New("executed archive paths do not equal standalone transition plan targets"))
	}

	validatorConfigPath := filepath.Join(context.archivedNode, "config", "config_validator.toml")
	observerConfigPath := filepath.Join(context.archivedNode, "config", "config_observer.toml")
	nodesSetupPath := filepath.Join(context.archivedNode, "config", "nodesSetup.json")
	context.validatorConfigFile, err = openRegularFileNoSymlink(validatorConfigPath, "")
	if err != nil {
		return fail(fmt.Errorf("archived validator config: %w", err))
	}
	context.files = append(context.files, context.validatorConfigFile)
	context.observerConfigFile, err = openRegularFileNoSymlink(observerConfigPath, "")
	if err != nil {
		return fail(fmt.Errorf("archived observer config: %w", err))
	}
	context.files = append(context.files, context.observerConfigFile)
	context.nodesSetupFile, err = openRegularFileNoSymlink(nodesSetupPath, "")
	if err != nil {
		return fail(fmt.Errorf("archived nodesSetup: %w", err))
	}
	context.files = append(context.files, context.nodesSetupFile)

	if context.binding.CanonicalHash != hex.EncodeToString(expectedHash[:]) {
		return fail(errors.New("binding canonical metachain genesis hash mismatch"))
	}
	if context.binding.NetworkDomain != hex.EncodeToString(expectedDomain[:]) {
		return fail(errors.New("binding network domain mismatch"))
	}
	if context.binding.NodesSetupSHA == "" || context.binding.NodesSetupSHA != context.plan.LiveGenerationHashes.NodesSetup ||
		context.binding.NodesSetupSHA != context.nodesSetupFile.sha256 {
		return fail(errors.New("binding, plan and archived nodesSetup hashes differ"))
	}
	if context.binding.StableHashes.MainConfig == "" ||
		context.binding.StableHashes.MainConfig != context.plan.LiveHashes.OldValidator ||
		context.binding.StableHashes.MainConfig != context.plan.LiveHashes.OldObserver ||
		context.binding.StableHashes.MainConfig != context.validatorConfigFile.sha256 ||
		context.binding.StableHashes.MainConfig != context.observerConfigFile.sha256 {
		return fail(errors.New("binding, plan and archived main-config hashes differ"))
	}

	validatorConfig, err := nodeCommon.LoadMainConfig(procFDPath(context.validatorConfigFile.file))
	if err != nil {
		return fail(fmt.Errorf("production-load archived validator config: %w", err))
	}
	observerConfig, err := nodeCommon.LoadMainConfig(procFDPath(context.observerConfigFile.file))
	if err != nil {
		return fail(fmt.Errorf("production-load archived observer config: %w", err))
	}
	validatorEpoch := canonicalEpochFromConfig(validatorConfig)
	observerEpoch := canonicalEpochFromConfig(observerConfig)
	validatorNumShards := validatorConfig.MetaBlockStorage.DB.NumShards
	observerNumShards := observerConfig.MetaBlockStorage.DB.NumShards
	if validatorConfig.GeneralSettings.ChainID == "" ||
		validatorConfig.GeneralSettings.ChainID != observerConfig.GeneralSettings.ChainID ||
		validatorConfig.GeneralSettings.ChainID != opts.chainID {
		return fail(errors.New("production-loaded chain ID differs across config and requested extraction"))
	}
	if validatorEpoch != observerEpoch || validatorEpoch != epoch {
		return fail(errors.New("production-loaded canonical epoch differs across config and requested extraction"))
	}
	if validatorNumShards <= 0 || validatorNumShards != observerNumShards {
		return fail(errors.New("production-loaded MetaBlock partition count is non-positive or differs across configs"))
	}
	context.chainID = validatorConfig.GeneralSettings.ChainID
	context.canonicalEpoch = validatorEpoch
	context.metaBlockNumShards = int(validatorNumShards)

	context.expectedObserverRoot, err = deriveObserverRoots(context.plan, context.archivedWork, context.chainID, context.canonicalEpoch)
	if err != nil {
		return fail(err)
	}
	return context, nil
}

func canonicalEpochFromConfig(cfg *config.Config) uint32 {
	if cfg.Hardfork.AfterHardFork {
		return cfg.Hardfork.StartEpoch
	}
	return cfg.EpochStartConfig.GenesisEpoch
}

func verifyEmbeddedPlan(standalone, embedded []byte) error {
	var standaloneValue map[string]interface{}
	var embeddedValue map[string]interface{}
	if err := decodeJSONNoDuplicates(standalone, &standaloneValue); err != nil {
		return fmt.Errorf("decode standalone plan for comparison: %w", err)
	}
	if err := decodeJSONNoDuplicates(embedded, &embeddedValue); err != nil {
		return fmt.Errorf("decode embedded plan for comparison: %w", err)
	}
	standaloneTimestamp, standaloneOK := standaloneValue["created_utc"].(string)
	embeddedTimestamp, embeddedOK := embeddedValue["created_utc"].(string)
	if !standaloneOK || !embeddedOK || !isCanonicalUTCTimestamp(standaloneTimestamp) || !isCanonicalUTCTimestamp(embeddedTimestamp) {
		return errors.New("standalone and embedded plans require valid UTC created_utc values")
	}
	delete(standaloneValue, "created_utc")
	delete(embeddedValue, "created_utc")
	if !reflect.DeepEqual(standaloneValue, embeddedValue) {
		return errors.New("embedded transition plan differs outside top-level created_utc")
	}
	return nil
}

func isCanonicalUTCTimestamp(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return false
	}
	_, offset := parsed.Zone()
	return offset == 0
}

func deriveObserverRoots(
	plan transitionPlanDocument,
	archivedWork string,
	chainID string,
	epoch uint32,
) (map[string]string, error) {
	result := make(map[string]string)
	activeRoot, err := deriveActiveWorkRoot(plan)
	if err != nil {
		return nil, err
	}
	for _, node := range plan.Processes.Nodes {
		role, found := argvValue(node.Argv, "-destination-shard-as-observer")
		if !found {
			continue
		}
		if role != "0" && role != "1" && role != "2" && role != "metachain" {
			return nil, fmt.Errorf("transition plan contains unsupported observer role %q", role)
		}
		if _, duplicate := result[role]; duplicate {
			return nil, fmt.Errorf("transition plan contains duplicate observer role %s", role)
		}
		workingDirectory, found := argvValue(node.Argv, "-working-directory")
		if !found {
			return nil, fmt.Errorf("transition plan observer role %s has no working directory", role)
		}
		operationMode, found := argvValue(node.Argv, "-operation-mode")
		if !found || operationMode != "db-lookup-extension" {
			return nil, fmt.Errorf("transition plan observer role %s is not db-lookup-extension", role)
		}
		workingDirectory, err := filepath.Abs(workingDirectory)
		if err != nil {
			return nil, fmt.Errorf("resolve transition plan observer role %s: %w", role, err)
		}
		workingDirectory = filepath.Clean(workingDirectory)
		relative, err := filepath.Rel(activeRoot, workingDirectory)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return nil, fmt.Errorf("transition plan observer role %s is outside exact active-work prefix", role)
		}
		shard := role
		result[role] = filepath.Join(
			archivedWork,
			relative,
			"db",
			chainID,
			fmt.Sprintf("Epoch_%d", epoch),
			"Shard_"+shard,
			"MetaBlock",
		)
	}
	if len(result) != 4 {
		return nil, fmt.Errorf("transition plan must prove exactly four observer roles, got %d", len(result))
	}
	return result, nil
}

func deriveActiveWorkRoot(plan transitionPlanDocument) (string, error) {
	workingDirectories := make([]string, 0, len(plan.Processes.Nodes))
	for _, node := range plan.Processes.Nodes {
		workingDirectory, found := argvValue(node.Argv, "-working-directory")
		if !found {
			return "", errors.New("transition plan process has no working directory")
		}
		absolute, err := filepath.Abs(workingDirectory)
		if err != nil {
			return "", err
		}
		workingDirectories = append(workingDirectories, filepath.Clean(absolute))
	}
	if len(workingDirectories) != 16 {
		return "", fmt.Errorf("transition plan requires exactly 16 working directories, found %d", len(workingDirectories))
	}
	activeRoot := filepath.Dir(workingDirectories[0])
	for {
		allWithin := true
		for _, directory := range workingDirectories {
			relative, err := filepath.Rel(activeRoot, directory)
			if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
				allWithin = false
				break
			}
		}
		if allWithin {
			break
		}
		parent := filepath.Dir(activeRoot)
		if parent == activeRoot {
			return "", errors.New("transition plan working directories have no bounded common active-work prefix")
		}
		activeRoot = parent
	}
	if activeRoot == string(os.PathSeparator) {
		return "", errors.New("transition plan active-work prefix cannot be filesystem root")
	}
	seen := make(map[string]struct{})
	for _, directory := range workingDirectories {
		if _, duplicate := seen[directory]; duplicate {
			return "", fmt.Errorf("transition plan has duplicate working directory %s", directory)
		}
		seen[directory] = struct{}{}
	}
	return activeRoot, nil
}

func argvValue(argv []string, name string) (string, bool) {
	for index := 0; index < len(argv); index++ {
		if argv[index] != name {
			continue
		}
		if index+1 >= len(argv) {
			return "", false
		}
		return argv[index+1], true
	}
	return "", false
}

func openRegularFileNoSymlink(path, expectedSHA string) (*heldFile, error) {
	canonical, err := canonicalNoSymlinkPath(path)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(canonical, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), canonical)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("create file handle")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%s is not a regular file", canonical)
	}
	value, err := io.ReadAll(file)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, err
	}
	digest := sha256.Sum256(value)
	digestHex := hex.EncodeToString(digest[:])
	if expectedSHA != "" && digestHex != expectedSHA {
		_ = file.Close()
		return nil, fmt.Errorf("SHA-256 %s does not match expected %s", digestHex, expectedSHA)
	}
	return &heldFile{path: canonical, file: file, bytes: value, sha256: digestHex}, nil
}

func openDirectoryNoSymlink(role, path string) (*heldDirectory, error) {
	canonical, err := canonicalNoSymlinkPath(path)
	if err != nil {
		return nil, fmt.Errorf("observer role %s root: %w", role, err)
	}
	fd, err := unix.Open(canonical, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open observer role %s root: %w", role, err)
	}
	file := os.NewFile(uintptr(fd), canonical)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("create observer role %s directory handle", role)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		_ = file.Close()
		return nil, fmt.Errorf("observer role %s filesystem identity unavailable", role)
	}
	return &heldDirectory{role: role, path: canonical, file: file, dev: uint64(stat.Dev), ino: stat.Ino}, nil
}

func canonicalNoSymlinkPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	absolute = filepath.Clean(absolute)
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	if filepath.Clean(resolved) != absolute {
		return "", fmt.Errorf("symlink or alias path refused: %s resolves to %s", absolute, resolved)
	}
	return absolute, nil
}

func canonicalExistingPath(path string) (string, error) {
	return canonicalNoSymlinkPath(path)
}

func procFDPath(file *os.File) string {
	return "/proc/self/fd/" + strconv.FormatUint(uint64(file.Fd()), 10)
}

func scanObserverRoot(
	root *heldDirectory,
	expectedPartitions int,
	precursorKey string,
	expectedHash [32]byte,
) (scannedObserverRoot, error) {
	entries, err := root.file.ReadDir(-1)
	if err != nil {
		return scannedObserverRoot{}, err
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name() < entries[right].Name() })
	partitionNames := make(map[int]string)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		partition, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil {
			continue
		}
		if partition < 0 || partition >= expectedPartitions || strconv.Itoa(partition) != entry.Name() {
			return scannedObserverRoot{}, fmt.Errorf("unexpected numeric LevelDB partition %q", entry.Name())
		}
		if _, duplicate := partitionNames[partition]; duplicate {
			return scannedObserverRoot{}, fmt.Errorf("duplicate LevelDB partition %d", partition)
		}
		partitionNames[partition] = entry.Name()
	}
	if len(partitionNames) != expectedPartitions {
		return scannedObserverRoot{}, fmt.Errorf(
			"expected exact LevelDB partition set 0..%d, found %d partitions",
			expectedPartitions-1,
			len(partitionNames),
		)
	}

	result := scannedObserverRoot{}
	partitionIdentities := make(map[string]int)
	for partition := 0; partition < expectedPartitions; partition++ {
		name, exists := partitionNames[partition]
		if !exists {
			return scannedObserverRoot{}, fmt.Errorf("missing LevelDB partition %d", partition)
		}
		childFD, openErr := unix.Openat(
			int(root.file.Fd()),
			name,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
		if openErr != nil {
			return scannedObserverRoot{}, fmt.Errorf("open LevelDB partition %s: %w", name, openErr)
		}
		child := os.NewFile(uintptr(childFD), root.path+"/"+name)
		if child == nil {
			_ = unix.Close(childFD)
			return scannedObserverRoot{}, errors.New("create LevelDB partition handle")
		}
		childInfo, statErr := child.Stat()
		if statErr != nil {
			_ = child.Close()
			return scannedObserverRoot{}, fmt.Errorf("stat LevelDB partition %s: %w", name, statErr)
		}
		childStat, ok := childInfo.Sys().(*syscall.Stat_t)
		if !ok {
			_ = child.Close()
			return scannedObserverRoot{}, fmt.Errorf("LevelDB partition %s filesystem identity unavailable", name)
		}
		identity := fmt.Sprintf("%d:%d", childStat.Dev, childStat.Ino)
		if previous, duplicate := partitionIdentities[identity]; duplicate {
			_ = child.Close()
			return scannedObserverRoot{}, fmt.Errorf(
				"LevelDB partitions %d and %d resolve to duplicate device/inode %s",
				previous,
				partition,
				identity,
			)
		}
		partitionIdentities[identity] = partition
		result.partitions = append(result.partitions, partition)
		result.partitionIDs = append(result.partitionIDs, fmt.Sprintf("%d:%d:%d", partition, childStat.Dev, childStat.Ino))
		db, openErr := leveldb.OpenFile(procFDPath(child), &opt.Options{ReadOnly: true})
		if openErr != nil {
			_ = child.Close()
			return scannedObserverRoot{}, fmt.Errorf("open LevelDB partition %s read-only: %w", name, openErr)
		}
		iterator := db.NewIterator(nil, nil)
		for iterator.Next() {
			key := iterator.Key()
			value := iterator.Value()
			if string(key) == precursorKey {
				result.precursorMatches = append(result.precursorMatches, append([]byte(nil), value...))
			}
			if bytes.Equal(key, expectedHash[:]) {
				result.finalMatches = append(result.finalMatches, append([]byte(nil), value...))
			}
		}
		iteratorErr := iterator.Error()
		iterator.Release()
		closeErr := db.Close()
		childCloseErr := child.Close()
		if iteratorErr != nil {
			return scannedObserverRoot{}, iteratorErr
		}
		if closeErr != nil {
			return scannedObserverRoot{}, closeErr
		}
		if childCloseErr != nil {
			return scannedObserverRoot{}, childCloseErr
		}
	}
	currentInfo, err := os.Stat(root.path)
	if err != nil {
		return scannedObserverRoot{}, fmt.Errorf("re-stat observer root: %w", err)
	}
	currentStat, ok := currentInfo.Sys().(*syscall.Stat_t)
	if !ok || uint64(currentStat.Dev) != root.dev || currentStat.Ino != root.ino {
		return scannedObserverRoot{}, errors.New("observer root device/inode changed during extraction")
	}
	return result, nil
}

func verifyPrecursor(chainID string, epoch uint32, headerBytes []byte) error {
	meta := &block.MetaBlock{}
	marshalizer := &marshal.GogoProtoMarshalizer{}
	if err := marshalizer.Unmarshal(meta, headerBytes); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	remarshalled, err := marshalizer.Marshal(meta)
	if err != nil {
		return fmt.Errorf("remarshal: %w", err)
	}
	if !bytes.Equal(remarshalled, headerBytes) {
		return errors.New("not canonical protobuf encoding")
	}
	if string(meta.GetChainID()) != chainID {
		return errors.New("chain ID mismatch")
	}
	if meta.GetEpoch() != epoch {
		return errors.New("epoch mismatch")
	}
	if len(meta.GetRootHash()) == 0 {
		return errors.New("state root unavailable")
	}
	if len(meta.GetValidatorStatsRootHash()) != 32 || !bytes.Equal(meta.GetValidatorStatsRootHash(), make([]byte, 32)) {
		return errors.New("validator-statistics root is not exactly 32 zero bytes")
	}
	return nil
}

func verifyPrecursorFinalRelation(precursorBytes, finalBytes []byte) error {
	marshalizer := &marshal.GogoProtoMarshalizer{}
	precursor := &block.MetaBlock{}
	final := &block.MetaBlock{}
	if err := marshalizer.Unmarshal(precursor, precursorBytes); err != nil {
		return err
	}
	if err := marshalizer.Unmarshal(final, finalBytes); err != nil {
		return err
	}
	if len(final.GetValidatorStatsRootHash()) != 32 || bytes.Equal(final.GetValidatorStatsRootHash(), make([]byte, 32)) {
		return errors.New("finalized validator-statistics root must be exactly 32 non-zero bytes")
	}
	final.ValidatorStatsRootHash = append([]byte(nil), precursor.GetValidatorStatsRootHash()...)
	normalized, err := marshalizer.Marshal(final)
	if err != nil {
		return err
	}
	if !bytes.Equal(normalized, precursorBytes) {
		return errors.New("finalized header differs from precursor outside ValidatorStatsRootHash")
	}
	return nil
}
