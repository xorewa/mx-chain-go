package f1t

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/enablers"
	"github.com/multiversx/mx-chain-go/common/forking"
)

const (
	ProfileCatalogSchema        = "DRWA_S1_F1T_PROFILE_CATALOG_V1"
	externalProfileDigestDomain = "DRWA/S1/F1T/EXTERNAL-PROFILE/v1"
)

type ProfileCatalog struct {
	Schema              string                `json:"schema"`
	TrustedRoot         string                `json:"trusted_workspace_realpath"`
	ControlMatrixPath   string                `json:"control_matrix_path"`
	ControlMatrixSHA256 string                `json:"control_matrix_sha256"`
	Profiles            []ProfileCatalogEntry `json:"profiles"`
	RuntimeCredit       int                   `json:"authoritative_runtime_credit"`
	NumericRuling       bool                  `json:"numeric_ratification"`
}

type ProfileCatalogEntry struct {
	ID                             Profile                 `json:"id"`
	Applicability                  string                  `json:"applicability"`
	ControlMatrixJSONPointer       string                  `json:"control_matrix_json_pointer"`
	ControlMatrixSelectedRowSHA256 string                  `json:"control_matrix_selected_row_sha256"`
	ConfigPath                     string                  `json:"config_path"`
	ConfigSHA256                   string                  `json:"config_sha256"`
	LoaderIdentity                 string                  `json:"loader_identity"`
	HandlerIdentity                string                  `json:"handler_identity"`
	EvaluationEpoch                uint32                  `json:"evaluation_epoch"`
	EffectiveEpochs                SemanticEffectiveEpochs `json:"effective_epochs"`
	ExpectedFlags                  SemanticProfileFlags    `json:"expected_flags"`
	SelectorProfileSHA256          string                  `json:"selector_profile_sha256"`
	ExternalProfileSHA256          string                  `json:"external_profile_preimage_sha256"`
}

type VerifiedProfile struct {
	Entry               ProfileCatalogEntry
	Binding             SemanticProfileBinding
	SelectorDigest      string
	ExternalDigest      string
	EnableEpochsHandler common.EnableEpochsHandler
}

func LoadAndVerifyProfileCatalog(trustedRoot, catalogPath, catalogSHA256 string) ([]VerifiedProfile, error) {
	bound, err := ReadBoundRegularFile(trustedRoot, catalogPath, catalogSHA256)
	if err != nil {
		return nil, err
	}
	var catalog ProfileCatalog
	if err = decodeExactPayload(bound.Bytes, &catalog); err != nil {
		return nil, fmt.Errorf("%w: profile catalog: %v", ErrPreflight, err)
	}
	if catalog.Schema != ProfileCatalogSchema || catalog.TrustedRoot != trustedRoot || catalog.RuntimeCredit != 0 ||
		catalog.NumericRuling || len(catalog.Profiles) != 2 || !isHexDigest(catalog.ControlMatrixSHA256) {
		return nil, ErrPreflight
	}
	matrix, err := ReadBoundRegularFile(trustedRoot, catalog.ControlMatrixPath, catalog.ControlMatrixSHA256)
	if err != nil {
		return nil, err
	}
	var matrixDocument map[string]json.RawMessage
	if err = json.Unmarshal(matrix.Bytes, &matrixDocument); err != nil {
		return nil, ErrPreflight
	}
	var rows []json.RawMessage
	if err = json.Unmarshal(matrixDocument["profiles"], &rows); err != nil || len(rows) != 2 {
		return nil, ErrPreflight
	}
	verified := make([]VerifiedProfile, 0, 2)
	configRaw := make(map[Profile][]byte, 2)
	for index, entry := range catalog.Profiles {
		expectedID := ProfileLegacy
		if index == 1 {
			expectedID = ProfileV2
		}
		if entry.ID != expectedID || entry.ControlMatrixJSONPointer != "/profiles/"+strconv.Itoa(index) ||
			entry.LoaderIdentity != "common.LoadEpochConfig" || entry.HandlerIdentity != "common/enablers.NewEnableEpochsHandler" ||
			!isHexDigest(entry.ControlMatrixSelectedRowSHA256) || !isHexDigest(entry.ConfigSHA256) ||
			!isHexDigest(entry.SelectorProfileSHA256) || !isHexDigest(entry.ExternalProfileSHA256) {
			return nil, ErrPreflight
		}
		var row map[string]any
		if err = json.Unmarshal(rows[index], &row); err != nil || row["id"] != string(entry.ID) ||
			!profileRowMatchesEntry(row, entry) {
			return nil, ErrPreflight
		}
		canonicalRow, err := json.Marshal(row)
		if err != nil || digestHex(canonicalRow) != entry.ControlMatrixSelectedRowSHA256 {
			return nil, ErrPreflight
		}
		var loadedEpochs SemanticEffectiveEpochs
		var loadedFlags SemanticProfileFlags
		var loadedHandler common.EnableEpochsHandler
		var rawConfig []byte
		err = withBoundRegularFile(trustedRoot, entry.ConfigPath, entry.ConfigSHA256, func(fd int, _ string, raw []byte, _ string) error {
			rawConfig = append([]byte(nil), raw...)
			config, loadErr := common.LoadEpochConfig("/proc/self/fd/" + strconv.Itoa(fd))
			if loadErr != nil {
				return loadErr
			}
			notifier := forking.NewGenericEpochNotifier()
			handler, handlerErr := enablers.NewEnableEpochsHandler(config.EnableEpochs, notifier)
			if handlerErr != nil {
				return handlerErr
			}
			handler.EpochConfirmed(entry.EvaluationEpoch, 0)
			loadedHandler = handler
			loadedEpochs = SemanticEffectiveEpochs{
				SCDeployEnableEpoch:        config.EnableEpochs.SCDeployEnableEpoch,
				SCProcessorV2EnableEpoch:   config.EnableEpochs.SCProcessorV2EnableEpoch,
				SupernovaEnableEpoch:       config.EnableEpochs.SupernovaEnableEpoch,
				DynamicESDTEnableEpoch:     config.EnableEpochs.DynamicESDTEnableEpoch,
				DRWAEnforcementEnableEpoch: config.EnableEpochs.DRWAEnforcementEnableEpoch,
			}
			loadedFlags = SemanticProfileFlags{
				SCDeployFlag:        handler.IsFlagEnabledInEpoch(common.SCDeployFlag, entry.EvaluationEpoch),
				SCProcessorV2Flag:   handler.IsFlagEnabledInEpoch(common.SCProcessorV2Flag, entry.EvaluationEpoch),
				DRWAEnforcementFlag: handler.IsFlagEnabledInEpoch(common.DRWAEnforcementFlag, entry.EvaluationEpoch),
			}
			return nil
		})
		if err != nil || loadedEpochs != entry.EffectiveEpochs || loadedFlags != entry.ExpectedFlags {
			return nil, ErrPreflight
		}
		binding := SemanticProfileBinding{ID: entry.ID, EvaluationEpoch: entry.EvaluationEpoch,
			EffectiveEpochs: loadedEpochs, ExpectedFlags: loadedFlags}
		selectorDigest, err := SemanticProfileBindingHash(binding)
		if err != nil || hex.EncodeToString(selectorDigest[:]) != entry.SelectorProfileSHA256 {
			return nil, ErrPreflight
		}
		externalDigest, err := ExternalProfilePreimageDigest(catalog.ControlMatrixSHA256, entry, binding)
		if err != nil || externalDigest != entry.ExternalProfileSHA256 || externalDigest == entry.SelectorProfileSHA256 {
			return nil, ErrPreflight
		}
		configRaw[entry.ID] = rawConfig
		verified = append(verified, VerifiedProfile{Entry: entry, Binding: binding,
			SelectorDigest: entry.SelectorProfileSHA256, ExternalDigest: externalDigest,
			EnableEpochsHandler: loadedHandler})
	}
	expectedLegacy := bytes.Replace(configRaw[ProfileV2], []byte("SCProcessorV2EnableEpoch = 1"), []byte("SCProcessorV2EnableEpoch = 3"), 1)
	if bytes.Count(configRaw[ProfileV2], []byte("SCProcessorV2EnableEpoch = 1")) != 1 ||
		!bytes.Equal(expectedLegacy, configRaw[ProfileLegacy]) {
		return nil, fmt.Errorf("%w: legacy preimage is not the one-field successor", ErrPreflight)
	}
	return verified, nil
}

func profileRowMatchesEntry(row map[string]any, entry ProfileCatalogEntry) bool {
	if row["applicability"] != entry.Applicability || uint64FromJSON(row["evaluation_epoch"]) != uint64(entry.EvaluationEpoch) {
		return false
	}
	epochs, ok := row["effective_epochs"].(map[string]any)
	if !ok || uint64FromJSON(epochs["SCDeployEnableEpoch"]) != uint64(entry.EffectiveEpochs.SCDeployEnableEpoch) ||
		uint64FromJSON(epochs["SCProcessorV2EnableEpoch"]) != uint64(entry.EffectiveEpochs.SCProcessorV2EnableEpoch) ||
		uint64FromJSON(epochs["SupernovaEnableEpoch"]) != uint64(entry.EffectiveEpochs.SupernovaEnableEpoch) ||
		uint64FromJSON(epochs["DynamicESDTEnableEpoch"]) != uint64(entry.EffectiveEpochs.DynamicESDTEnableEpoch) ||
		uint64FromJSON(epochs["DRWAEnforcementEnableEpoch"]) != uint64(entry.EffectiveEpochs.DRWAEnforcementEnableEpoch) {
		return false
	}
	flags, ok := row["expected_flags"].(map[string]any)
	return ok && flags["SCDeployFlag"] == entry.ExpectedFlags.SCDeployFlag &&
		flags["SCProcessorV2Flag"] == entry.ExpectedFlags.SCProcessorV2Flag &&
		flags["DRWAEnforcementFlag"] == entry.ExpectedFlags.DRWAEnforcementFlag
}

func ExternalProfilePreimageDigest(controlMatrixSHA256 string, entry ProfileCatalogEntry, binding SemanticProfileBinding) (string, error) {
	if !isHexDigest(controlMatrixSHA256) || !isHexDigest(entry.ControlMatrixSelectedRowSHA256) || !isHexDigest(entry.ConfigSHA256) {
		return "", ErrPreflight
	}
	encodedBinding, err := json.Marshal(binding)
	if err != nil {
		return "", err
	}
	parts := []string{externalProfileDigestDomain, controlMatrixSHA256, entry.ControlMatrixJSONPointer, entry.ControlMatrixSelectedRowSHA256,
		entry.ConfigSHA256, entry.LoaderIdentity, entry.HandlerIdentity, string(encodedBinding), entry.Applicability}
	return digestHex([]byte(strings.Join(parts, "\x00"))), nil
}

func digestHex(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
