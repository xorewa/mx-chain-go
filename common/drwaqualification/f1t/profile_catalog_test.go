package f1t

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadAndVerifyProfileCatalogUsesRealLoaderAndRejectsMixedPreimages(t *testing.T) {
	root := t.TempDir()
	v2Raw := []byte("[EnableEpochs]\nSCDeployEnableEpoch = 0\nSCProcessorV2EnableEpoch = 1\nSupernovaEnableEpoch = 2\nDynamicESDTEnableEpoch = 1\nDRWAEnforcementEnableEpoch = 2\n")
	legacyRaw := []byte(strings.Replace(string(v2Raw), "SCProcessorV2EnableEpoch = 1", "SCProcessorV2EnableEpoch = 3", 1))
	v2Path := filepath.Join(root, "v2.toml")
	legacyPath := filepath.Join(root, "legacy.toml")
	require.NoError(t, os.WriteFile(v2Path, v2Raw, 0o600))
	require.NoError(t, os.WriteFile(legacyPath, legacyRaw, 0o600))

	rows := []map[string]any{
		{"id": string(ProfileLegacy), "applicability": "TEST", "evaluation_epoch": 2,
			"effective_epochs": map[string]any{"SCDeployEnableEpoch": 0, "SCProcessorV2EnableEpoch": 3,
				"SupernovaEnableEpoch": 2, "DynamicESDTEnableEpoch": 1, "DRWAEnforcementEnableEpoch": 2},
			"expected_flags": map[string]any{"SCDeployFlag": true, "SCProcessorV2Flag": false, "DRWAEnforcementFlag": true}},
		{"id": string(ProfileV2), "applicability": "TEST", "evaluation_epoch": 2,
			"effective_epochs": map[string]any{"SCDeployEnableEpoch": 0, "SCProcessorV2EnableEpoch": 1,
				"SupernovaEnableEpoch": 2, "DynamicESDTEnableEpoch": 1, "DRWAEnforcementEnableEpoch": 2},
			"expected_flags": map[string]any{"SCDeployFlag": true, "SCProcessorV2Flag": true, "DRWAEnforcementFlag": true}},
	}
	v17Raw, err := json.Marshal(map[string]any{"profiles": rows})
	require.NoError(t, err)
	v17Path := filepath.Join(root, "v17.json")
	require.NoError(t, os.WriteFile(v17Path, v17Raw, 0o600))
	v17Digest := digestHex(v17Raw)

	entries := make([]ProfileCatalogEntry, 0, 2)
	for index, profile := range []Profile{ProfileLegacy, ProfileV2} {
		epochs := SemanticEffectiveEpochs{SCDeployEnableEpoch: 0, SCProcessorV2EnableEpoch: 3,
			SupernovaEnableEpoch: 2, DynamicESDTEnableEpoch: 1, DRWAEnforcementEnableEpoch: 2}
		configPath, configRaw := legacyPath, legacyRaw
		flags := SemanticProfileFlags{SCDeployFlag: true, DRWAEnforcementFlag: true}
		if profile == ProfileV2 {
			epochs.SCProcessorV2EnableEpoch = 1
			flags.SCProcessorV2Flag = true
			configPath, configRaw = v2Path, v2Raw
		}
		binding := SemanticProfileBinding{ID: profile, EvaluationEpoch: 2, EffectiveEpochs: epochs, ExpectedFlags: flags}
		selector, hashErr := SemanticProfileBindingHash(binding)
		require.NoError(t, hashErr)
		rowRaw, marshalErr := json.Marshal(rows[index])
		require.NoError(t, marshalErr)
		entry := ProfileCatalogEntry{ID: profile, Applicability: "TEST", ControlMatrixJSONPointer: "/profiles/" + string(rune('0'+index)),
			ControlMatrixSelectedRowSHA256: digestHex(rowRaw), ConfigPath: configPath, ConfigSHA256: digestHex(configRaw),
			LoaderIdentity: "common.LoadEpochConfig", HandlerIdentity: "common/enablers.NewEnableEpochsHandler",
			EvaluationEpoch: 2, EffectiveEpochs: epochs, ExpectedFlags: flags, SelectorProfileSHA256: hex.EncodeToString(selector[:])}
		entry.ExternalProfileSHA256, err = ExternalProfilePreimageDigest(v17Digest, entry, binding)
		require.NoError(t, err)
		entries = append(entries, entry)
	}
	catalog := ProfileCatalog{Schema: ProfileCatalogSchema, TrustedRoot: root, ControlMatrixPath: v17Path, ControlMatrixSHA256: v17Digest, Profiles: entries}
	catalogRaw, err := json.Marshal(catalog)
	require.NoError(t, err)
	catalogPath := filepath.Join(root, "catalog.json")
	require.NoError(t, os.WriteFile(catalogPath, catalogRaw, 0o600))
	verified, err := LoadAndVerifyProfileCatalog(root, catalogPath, digestHex(catalogRaw))
	require.NoError(t, err)
	require.Len(t, verified, 2)

	entries[1].ConfigSHA256 = strings.Repeat("00", sha256.Size)
	bad, err := json.Marshal(ProfileCatalog{Schema: ProfileCatalogSchema, TrustedRoot: root, ControlMatrixPath: v17Path, ControlMatrixSHA256: v17Digest, Profiles: entries})
	require.NoError(t, err)
	badPath := filepath.Join(root, "bad.json")
	require.NoError(t, os.WriteFile(badPath, bad, 0o600))
	_, err = LoadAndVerifyProfileCatalog(root, badPath, digestHex(bad))
	require.Error(t, err)
}
