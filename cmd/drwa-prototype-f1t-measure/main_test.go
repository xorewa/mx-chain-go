//go:build drwa_s1_f1t_measure

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-communication-go/p2p/libp2p"
	"github.com/multiversx/mx-chain-go/common/drwaqualification/f1t"
	"github.com/stretchr/testify/require"
)

func TestRunIsOfflineAndZeroCreditForAllRoles(t *testing.T) {
	t.Setenv(phaseIEnvironment, "1")
	for _, mode := range []string{"collector", "publisher", "target", "passive"} {
		var buffer bytes.Buffer
		err := run([]string{"--mode", mode}, &buffer)
		if !libp2p.F1TDirectAdmissionEnabled() {
			require.ErrorContains(t, err, "tagged direct-admission seam not linked")
			require.Empty(t, buffer.String())
			continue
		}
		require.NoError(t, err)
		require.Contains(t, buffer.String(), `"authoritative_runtime_credit":0`)
		require.Contains(t, buffer.String(), `"phase_i_only":true`)
		require.Contains(t, buffer.String(), `"phase_ii_submission":false`)
		require.Contains(t, buffer.String(), `"protocol_submission":false`)
	}
}

func TestRunRequiresF1TDirectAdmissionBuildTag(t *testing.T) {
	t.Setenv(phaseIEnvironment, "1")
	err := run([]string{"--mode", "collector"}, &bytes.Buffer{})
	if libp2p.F1TDirectAdmissionEnabled() {
		require.NoError(t, err)
		return
	}
	require.ErrorContains(t, err, "tagged direct-admission seam not linked")
}

func TestRunRejectsWithoutPhaseIEnvironment(t *testing.T) {
	t.Setenv(phaseIEnvironment, "")
	require.Error(t, run([]string{"--mode", "collector"}, &bytes.Buffer{}))
}

func TestInterceptedRehearsalUsesSubprocessChannelsAndProducesZeroCreditClosure(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "drwa-prototype-f1t-measure")
	build := exec.Command("go", "build", "-tags=drwa_s1_f1t_measure", "-o", binary, ".")
	build.Env = append(os.Environ(), "GOFLAGS=-buildvcs=false")
	buildOutput, err := build.CombinedOutput()
	require.NoError(t, err, string(buildOutput))
	rehearsalRoot := t.TempDir()
	command := exec.Command(binary, "--mode=collector", "--rehearsal-root="+rehearsalRoot)
	command.Env = append(os.Environ(), phaseIEnvironment+"=1")
	result, err := command.CombinedOutput()
	require.NoError(t, err, string(result))
	var decoded output
	require.NoError(t, json.Unmarshal(result, &decoded), string(result))
	require.Equal(t, "OFFLINE_FULL_GUARDED_SEND_RECONCILIATION_REHEARSAL_PASS", decoded.Status)
	require.Zero(t, decoded.RuntimeCredit)
	require.False(t, decoded.NumericRatification)
	require.False(t, decoded.PhaseIISubmission)
	require.False(t, decoded.ProtocolSubmission)
	require.Len(t, decoded.Terminations, 3)
	for _, termination := range decoded.Terminations {
		require.Contains(t, []string{"publisher", "target", "passive"}, termination.Role)
		require.NotZero(t, termination.StopIntentNS)
		require.GreaterOrEqual(t, termination.PIDFDExitRawNS, termination.StopIntentNS)
	}
	record, err := os.ReadFile(filepath.Join(rehearsalRoot, "f1t-phase-i-rehearsal.jsonl"))
	require.NoError(t, err)
	verifyRehearsalRecord(t, record, decoded)
	transportRecord, err := os.ReadFile(filepath.Join(rehearsalRoot, "f1t-phase-i-transport-reconciliation.jsonl"))
	require.NoError(t, err)
	verifyTransportRecord(t, transportRecord, decoded)
}

func TestInterceptedRehearsalFailsClosedOnChildFailure(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "drwa-prototype-f1t-measure")
	build := exec.Command("go", "build", "-tags=drwa_s1_f1t_measure", "-o", binary, ".")
	build.Env = append(os.Environ(), "GOFLAGS=-buildvcs=false")
	buildOutput, err := build.CombinedOutput()
	require.NoError(t, err, string(buildOutput))
	command := exec.Command(binary, "--mode=collector", "--rehearsal-root="+t.TempDir())
	command.Env = append(os.Environ(), phaseIEnvironment+"=1", phaseIFailRoleEnvironment+"=target")
	result, err := command.CombinedOutput()
	require.Error(t, err, string(result))
	require.NotContains(t, string(result), "OFFLINE_FULL_GUARDED_SEND_RECONCILIATION_REHEARSAL_PASS")
}

func TestPhaseIIRehearsalBindsRealPreflightContextAcrossProcesses(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "drwa-prototype-f1t-measure")
	build := exec.Command("go", "build", "-tags=drwa_s1_f1t_measure", "-o", binary, ".")
	build.Env = append(os.Environ(), "GOFLAGS=-buildvcs=false")
	buildOutput, err := build.CombinedOutput()
	require.NoError(t, err, string(buildOutput))

	root := t.TempDir()
	paths := writePhaseIITestCatalogs(t, root, strings.Repeat("c", 40))
	factsCommand := exec.Command(binary, "--mode=collector", "--preflight-facts-only", "--trusted-root="+root)
	factsCommand.Env = append(os.Environ(), phaseIIEnvironment+"=1")
	factsRaw, err := factsCommand.CombinedOutput()
	require.NoError(t, err, string(factsRaw))
	var facts preflightFactsOutput
	require.NoError(t, json.Unmarshal(factsRaw, &facts))
	require.Equal(t, "OBSERVED_OFFLINE_NO_CAMPAIGN_NO_CREDIT", facts.Status)

	ownerAuthorization := filepath.Join(root, "owner-authorization.json")
	writeJSONFile(t, ownerAuthorization, f1t.OwnerAuthorization{
		Schema: f1t.OwnerAuthorizationSchema, AttemptID: "offline-rehearsal-attempt",
		FailedOrInvalidAttemptsMustBePreserved: true, NewAttemptRequiresNewAuthorizationAndContext: true,
	})
	profileRaw, err := os.ReadFile(paths.profileCatalog)
	require.NoError(t, err)
	fixtureRaw, err := os.ReadFile(paths.fixtureCatalog)
	require.NoError(t, err)
	authorizationRaw, err := os.ReadFile(ownerAuthorization)
	require.NoError(t, err)
	identity := f1t.CampaignIdentity{
		Schema: f1t.CampaignIdentitySchema, ProfileCatalogSHA256: hashBytes(profileRaw),
		OrderedProfileDigests: paths.orderedProfileDigests, FixtureCatalogSHA256: hashBytes(fixtureRaw),
		CampaignExecutableSHA256: facts.CampaignExecutableSHA256, ModuleGraphSHA256: facts.ModuleGraphSHA256,
		HostKernelCPUStorageFactsSHA256: facts.HostKernelCPUStorageFactsSHA256,
		PopulationManifestSHA256:        facts.PopulationManifestSHA256, OwnerAuthorizationSHA256: hashBytes(authorizationRaw),
	}
	identityPath := filepath.Join(root, "campaign-identity.json")
	writeJSONFile(t, identityPath, identity)
	identityRaw, err := os.ReadFile(identityPath)
	require.NoError(t, err)
	rehearsalRoot := filepath.Join(root, "rehearsal")
	require.NoError(t, os.Mkdir(rehearsalRoot, 0o700))
	command := exec.Command(binary,
		"--mode=collector", "--rehearsal-root="+rehearsalRoot, "--trusted-root="+root,
		"--campaign-identity="+identityPath, "--campaign-identity-sha256="+hashBytes(identityRaw),
		"--profile-catalog="+paths.profileCatalog, "--fixture-catalog="+paths.fixtureCatalog,
		"--owner-authorization="+ownerAuthorization, "--source-commit="+strings.Repeat("c", 40),
	)
	command.Env = append(os.Environ(), phaseIIEnvironment+"=1")
	resultRaw, err := command.CombinedOutput()
	require.NoError(t, err, string(resultRaw))
	var result output
	require.NoError(t, json.Unmarshal(resultRaw, &result), string(resultRaw))
	require.Equal(t, "OFFLINE_PHASE_II_FULL_PATH_REHEARSAL_PASS_NO_CAMPAIGN_NO_CREDIT", result.Status)
	require.False(t, result.PhaseIOnly)
	require.False(t, result.PhaseIISubmission)
	require.False(t, result.ProtocolSubmission)
	require.Zero(t, result.RuntimeCredit)
	require.Equal(t, mustCampaignDigest(t, identity), result.CampaignContextSHA256)
	require.Equal(t, result.CampaignContextSHA256, result.CollectorClosure.CampaignContextSHA256)
	require.Equal(t, result.CampaignContextSHA256, result.TransportClosure.CampaignContextSHA256)
	require.Equal(t, 252, result.PipelineObservations, "84 logical intents must each produce exactly three path receipts")
	transportRaw, err := os.ReadFile(filepath.Join(rehearsalRoot, "f1t-phase-ii-transport.jsonl"))
	require.NoError(t, err)
	verifyPhaseIITransportPopulation(t, transportRaw, result.CampaignContextSHA256, 84, 252)

	var fixtureCatalog f1t.FixtureCatalog
	require.NoError(t, json.Unmarshal(fixtureRaw, &fixtureCatalog))
	fixtureCatalog.CanonicalFixtureSHA256[f1t.ProfileV2] = strings.Repeat("f", 64)
	mutatedFixture := filepath.Join(root, "fixture-catalog-mutated.json")
	writeJSONFile(t, mutatedFixture, fixtureCatalog)
	mutatedFixtureRaw, err := os.ReadFile(mutatedFixture)
	require.NoError(t, err)
	_, err = f1t.LoadAndVerifyFixtureCatalog(root, mutatedFixture, hashBytes(mutatedFixtureRaw), strings.Repeat("c", 40))
	require.Error(t, err)

	var profileCatalog f1t.ProfileCatalog
	require.NoError(t, json.Unmarshal(profileRaw, &profileCatalog))
	profileCatalog.Profiles[1].ExpectedFlags.SCProcessorV2Flag = false
	mutatedProfile := filepath.Join(root, "profile-catalog-mutated.json")
	writeJSONFile(t, mutatedProfile, profileCatalog)
	mutatedProfileRaw, err := os.ReadFile(mutatedProfile)
	require.NoError(t, err)
	_, err = f1t.LoadAndVerifyProfileCatalog(root, mutatedProfile, hashBytes(mutatedProfileRaw))
	require.Error(t, err)
}

func verifyPhaseIITransportPopulation(t *testing.T, raw []byte, contextDigest string, catalogs, callbacks int) {
	t.Helper()
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'})
	require.Len(t, lines, catalogs+callbacks+1)
	seenCatalogs := make(map[string]f1t.SendCatalogEntry, catalogs)
	seenCallbacks := make(map[string]map[f1t.CallbackKey]struct{}, catalogs)
	for _, line := range lines[:len(lines)-1] {
		var record f1t.CollectorRecord
		require.NoError(t, json.Unmarshal(line, &record))
		require.Equal(t, contextDigest, record.CampaignContextSHA256)
		var header struct {
			Type f1t.PayloadType `json:"type"`
		}
		require.NoError(t, json.Unmarshal(record.Frame.Payload, &header))
		switch header.Type {
		case f1t.PayloadSendCatalog:
			var payload f1t.SendCatalogPayload
			require.NoError(t, f1t.DecodeClosedPayload(record.Frame.Payload, &payload))
			require.Len(t, payload.Entry.Expected, 3)
			_, duplicate := seenCatalogs[payload.Entry.MessageID]
			require.False(t, duplicate)
			seenCatalogs[payload.Entry.MessageID] = payload.Entry
		case f1t.PayloadCallbackEvent:
			var payload f1t.CallbackEventPayload
			require.NoError(t, f1t.DecodeClosedPayload(record.Frame.Payload, &payload))
			if seenCallbacks[payload.Event.MessageID] == nil {
				seenCallbacks[payload.Event.MessageID] = make(map[f1t.CallbackKey]struct{})
			}
			_, duplicate := seenCallbacks[payload.Event.MessageID][payload.Event.Callback]
			require.False(t, duplicate)
			seenCallbacks[payload.Event.MessageID][payload.Event.Callback] = struct{}{}
		default:
			require.Failf(t, "unexpected Phase-II transport payload", "%s", header.Type)
		}
	}
	require.Len(t, seenCatalogs, catalogs)
	require.Len(t, seenCallbacks, catalogs)
	for messageID, entry := range seenCatalogs {
		require.Len(t, seenCallbacks[messageID], 3)
		for _, expected := range entry.Expected {
			_, exists := seenCallbacks[messageID][expected]
			require.True(t, exists)
		}
	}
}

type phaseIITestCatalogPaths struct {
	profileCatalog        string
	fixtureCatalog        string
	orderedProfileDigests []string
}

func writePhaseIITestCatalogs(t *testing.T, root, sourceCommit string) phaseIITestCatalogPaths {
	t.Helper()
	v2Raw, err := os.ReadFile(filepath.Join("..", "node", "config", "enableEpochs.toml"))
	require.NoError(t, err)
	v2Raw = bytes.Replace(v2Raw, []byte("DRWAEnforcementEnableEpoch = 4294967295"), []byte("DRWAEnforcementEnableEpoch = 2"), 1)
	require.Equal(t, 1, bytes.Count(v2Raw, []byte("SCProcessorV2EnableEpoch = 1")))
	legacyRaw := bytes.Replace(v2Raw, []byte("SCProcessorV2EnableEpoch = 1"), []byte("SCProcessorV2EnableEpoch = 3"), 1)
	v2Path := filepath.Join(root, "v2.toml")
	legacyPath := filepath.Join(root, "legacy.toml")
	require.NoError(t, os.WriteFile(v2Path, v2Raw, 0o600))
	require.NoError(t, os.WriteFile(legacyPath, legacyRaw, 0o600))

	profiles := []struct {
		id            f1t.Profile
		applicability string
		scV2          uint32
		scV2Flag      bool
		path          string
		raw           []byte
	}{
		{f1t.ProfileLegacy, "offline compatibility only", 3, false, legacyPath, legacyRaw},
		{f1t.ProfileV2, "current runtime qualification", 1, true, v2Path, v2Raw},
	}
	v17Profiles := make([]map[string]any, 0, 2)
	entries := make([]f1t.ProfileCatalogEntry, 0, 2)
	ordered := make([]string, 0, 4)
	for index, profile := range profiles {
		epochs := f1t.SemanticEffectiveEpochs{SCDeployEnableEpoch: 0, SCProcessorV2EnableEpoch: profile.scV2,
			SupernovaEnableEpoch: 2, DynamicESDTEnableEpoch: 1, DRWAEnforcementEnableEpoch: 2}
		flags := f1t.SemanticProfileFlags{SCDeployFlag: true, SCProcessorV2Flag: profile.scV2Flag, DRWAEnforcementFlag: true}
		row := map[string]any{"id": profile.id, "applicability": profile.applicability, "evaluation_epoch": 2,
			"effective_epochs": map[string]any{"SCDeployEnableEpoch": 0, "SCProcessorV2EnableEpoch": profile.scV2,
				"SupernovaEnableEpoch": 2, "DynamicESDTEnableEpoch": 1, "DRWAEnforcementEnableEpoch": 2},
			"expected_flags": map[string]any{"SCDeployFlag": true, "SCProcessorV2Flag": profile.scV2Flag, "DRWAEnforcementFlag": true}}
		rowRaw, marshalErr := json.Marshal(row)
		require.NoError(t, marshalErr)
		binding := f1t.SemanticProfileBinding{ID: profile.id, EvaluationEpoch: 2, EffectiveEpochs: epochs, ExpectedFlags: flags}
		selector, hashErr := f1t.SemanticProfileBindingHash(binding)
		require.NoError(t, hashErr)
		entry := f1t.ProfileCatalogEntry{ID: profile.id, Applicability: profile.applicability,
			ControlMatrixJSONPointer: "/profiles/" + strconv.Itoa(index), ControlMatrixSelectedRowSHA256: hashBytes(rowRaw),
			ConfigPath: profile.path, ConfigSHA256: hashBytes(profile.raw), LoaderIdentity: "common.LoadEpochConfig",
			HandlerIdentity: "common/enablers.NewEnableEpochsHandler", EvaluationEpoch: 2, EffectiveEpochs: epochs,
			ExpectedFlags: flags, SelectorProfileSHA256: hex.EncodeToString(selector[:])}
		entry.ExternalProfileSHA256, hashErr = f1t.ExternalProfilePreimageDigest("", entry, binding)
		// The external digest binds the control-matrix hash, so it is filled after the matrix is written below.
		require.Error(t, hashErr)
		v17Profiles = append(v17Profiles, row)
		entries = append(entries, entry)
	}
	constructor := f1t.DefaultCanonicalSourceConstructor()
	v17 := map[string]any{
		"profiles": v17Profiles,
		"raw_identity_preimage_catalog": map[string]any{"SELECTED::V2_CURRENT_RUNTIME_CLASS": map[string]any{
			"construction_inputs": map[string]any{"semantic_fields": map[string]any{
				"network_domain":     map[string]any{"value": strings.Repeat("44", 32)},
				"source_holder":      map[string]any{"value": strings.Repeat("11", 32)},
				"destination_holder": map[string]any{"value": strings.Repeat("22", 32)},
				"sender_shard":       map[string]any{"value": 1},
				"receiver_shard":     map[string]any{"value": 2},
				"tx_hash":            map[string]any{"value": strings.Repeat("33", 32)},
				"function":           map[string]any{"value": "DRWARegulatedValueEnvelope"},
				"intent": map[string]any{"value": map[string]any{
					"TokenID": "DRWAQUAL-abcdef", "Quantity": "0a", "SourceSubject": strings.Repeat("11", 32),
					"DestinationSubject": strings.Repeat("22", 32),
				}},
			}},
		}},
		"fixture_value_catalog": map[string]any{
			"POSITIVE_CURRENT_WORK_BUDGET_PROVIDER_RESULT": map[string]any{"value": map[string]any{
				"gas_schedule_identity_hex": strings.Repeat("88", 32), "DestinationGate": 1_200_000,
				"SuccessReceipt": 1_200_000, "RefundGeneration": 1_200_000, "SourceCompletion": 1_200_000,
			}},
			"ARM_POSITIVE_GAS_PRICE": map[string]any{"value": 1_000_000_000},
		},
		"constructor_dependency_catalog": map[string]any{"CASE_BOUND_VALID_TEST_DOUBLES": map[string]any{
			"dependencies": []any{
				map[string]any{"field": "networkDomain", "value_hex": strings.Repeat("44", 32)},
				map[string]any{"field": "cebEpoch", "value": 2},
				map[string]any{"field": "settlementLifetimeRounds", "value": 4000},
			},
		}},
	}
	v17Path := filepath.Join(root, "v17.json")
	writeJSONFile(t, v17Path, v17)
	v17Raw, err := os.ReadFile(v17Path)
	require.NoError(t, err)
	for index := range entries {
		binding := f1t.SemanticProfileBinding{ID: entries[index].ID, EvaluationEpoch: 2,
			EffectiveEpochs: entries[index].EffectiveEpochs, ExpectedFlags: entries[index].ExpectedFlags}
		entries[index].ExternalProfileSHA256, err = f1t.ExternalProfilePreimageDigest(hashBytes(v17Raw), entries[index], binding)
		require.NoError(t, err)
		ordered = append(ordered, entries[index].ExternalProfileSHA256, entries[index].SelectorProfileSHA256)
	}
	profileCatalogPath := filepath.Join(root, "profile-catalog.json")
	writeJSONFile(t, profileCatalogPath, f1t.ProfileCatalog{Schema: f1t.ProfileCatalogSchema, TrustedRoot: root,
		ControlMatrixPath: v17Path, ControlMatrixSHA256: hashBytes(v17Raw), Profiles: entries})

	gasAPath := filepath.Join(root, "gas-a.toml")
	gasBPath := filepath.Join(root, "gas-b.toml")
	gasA := []byte("[DRWAPrototypeCost]\nDestinationGate = 1000000\nSuccessReceipt = 1000000\nRefundGeneration = 1000000\nSourceCompletion = 1000000\n")
	gasB := []byte("[DRWAPrototypeCost]\nDestinationGate = 1200000\nSuccessReceipt = 1200000\nRefundGeneration = 1200000\nSourceCompletion = 1200000\n")
	require.NoError(t, os.WriteFile(gasAPath, gasA, 0o600))
	require.NoError(t, os.WriteFile(gasBPath, gasB, 0o600))
	manifestPath := filepath.Join(root, "staging.json")
	writeJSONFile(t, manifestPath, map[string]any{"gas_catalog": map[string]any{
		"profile_a_identity": strings.Repeat("a", 64), "profile_b_identity": strings.Repeat("b", 64),
		"maximum_reserved_total": 4_800_000,
	}})
	manifestRaw, err := os.ReadFile(manifestPath)
	require.NoError(t, err)
	fixtureHashes := make(map[f1t.Profile]string, 2)
	for _, profile := range []f1t.Profile{f1t.ProfileLegacy, f1t.ProfileV2} {
		raw, _, fixtureErr := f1t.BuildCalibrationFixture(constructor, profile, "SELECTED", 1, "fixture", "/drwa/f1t", "peer-remote", true)
		require.NoError(t, fixtureErr)
		fixtureHashes[profile] = hashBytes(raw)
	}
	fixtureCatalogPath := filepath.Join(root, "fixture-catalog.json")
	writeJSONFile(t, fixtureCatalogPath, f1t.FixtureCatalog{Schema: f1t.FixtureCatalogSchema, TrustedRoot: root,
		ControlMatrixPath: v17Path, ControlMatrixSHA256: hashBytes(v17Raw), ActivationManifestPath: manifestPath,
		ActivationManifestSHA256: hashBytes(manifestRaw), ConstructorSourceCommit: sourceCommit, Constructor: constructor,
		GasProfiles: []f1t.GasProfileBinding{
			{ID: "A", Path: gasAPath, SHA256: hashBytes(gasA), ScheduleIdentity: strings.Repeat("a", 64),
				Budgets: f1t.DefaultCanonicalSourceConstructor().Budgets},
			{ID: "B", Path: gasBPath, SHA256: hashBytes(gasB), ScheduleIdentity: strings.Repeat("b", 64),
				Budgets: constructor.Budgets},
		}, CanonicalFixtureSHA256: fixtureHashes})
	// Profile A is deliberately lower than the catalog maximum.
	var fixtureCatalog f1t.FixtureCatalog
	fixtureCatalogRaw, err := os.ReadFile(fixtureCatalogPath)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(fixtureCatalogRaw, &fixtureCatalog))
	fixtureCatalog.GasProfiles[0].Budgets.DestinationGate = 1_000_000
	fixtureCatalog.GasProfiles[0].Budgets.SuccessReceipt = 1_000_000
	fixtureCatalog.GasProfiles[0].Budgets.RefundGeneration = 1_000_000
	fixtureCatalog.GasProfiles[0].Budgets.SourceCompletion = 1_000_000
	writeJSONFile(t, fixtureCatalogPath, fixtureCatalog)
	return phaseIITestCatalogPaths{profileCatalog: profileCatalogPath, fixtureCatalog: fixtureCatalogPath,
		orderedProfileDigests: ordered}
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.MarshalIndent(value, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, append(raw, '\n'), 0o600))
}

func hashBytes(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func mustCampaignDigest(t *testing.T, identity f1t.CampaignIdentity) string {
	t.Helper()
	digest, err := identity.Digest()
	require.NoError(t, err)
	return digest
}

func TestTransportReconciliationRejectsIndependentMutations(t *testing.T) {
	if !libp2p.F1TDirectAdmissionEnabled() {
		t.Skip("tagged direct-admission seam not linked")
	}
	identity := f1t.ProcessIdentity{StartID: "test-start", ExecutableHash: strings.Repeat("a", 64)}
	tests := map[string]transportReconciliationHooks{
		"message ID substitution": {
			MutateRemoteCatalog: func(entry *f1t.SendCatalogEntry) { entry.MessageID = strings.Repeat("0", 64) },
		},
		"payload substitution": {
			MutateRemotePayload: func(payload []byte) []byte { return append(payload, '\n') },
		},
		"wrong callback path": {
			MutateRemoteCallback: func(event *f1t.RecorderEvent) { event.Callback.Path = "wrong-path" },
		},
	}
	for name, hooks := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := runTransportReconciliationWithHooks(filepath.Join(t.TempDir(), "record.jsonl"), identity, hooks)
			require.ErrorIs(t, err, f1t.ErrReconciliation)
		})
	}
}

func TestTransportReconciliationNeverSendsBeforeDurableCatalogSync(t *testing.T) {
	if !libp2p.F1TDirectAdmissionEnabled() {
		t.Skip("tagged direct-admission seam not linked")
	}
	sendStarted := false
	injected := errors.New("injected pre-sync failure")
	hooks := transportReconciliationHooks{
		Collector:        f1t.CollectorHooks{BeforeSync: func() error { return injected }},
		BeforeRemoteSend: func() { sendStarted = true },
	}
	identity := f1t.ProcessIdentity{StartID: "test-start", ExecutableHash: strings.Repeat("a", 64)}
	_, err := runTransportReconciliationWithHooks(filepath.Join(t.TempDir(), "record.jsonl"), identity, hooks)
	require.ErrorIs(t, err, injected)
	require.False(t, sendStarted)
}

func TestAppendAndAckNeverSendsBeforeBothRecordsAreDurable(t *testing.T) {
	newFrame := func(t *testing.T) (f1t.Frame, []byte) {
		t.Helper()
		payload, payloadHash, err := f1t.NewPayload(f1t.RoleReadyPayload{
			Type:  f1t.PayloadRoleReady,
			Phase: "INTERCEPTED_REHEARSAL",
			Role:  "target",
		})
		require.NoError(t, err)
		frame := f1t.Frame{
			SchemaVersion:  f1t.SchemaVersion,
			SessionID:      "session",
			RunID:          "run",
			Role:           "target",
			PIDStartID:     "target-start",
			ExecutableHash: strings.Repeat("a", 64),
			SourceSequence: 1,
			ReleaseEpoch:   1,
			Kind:           f1t.KindEvent,
			PayloadHash:    payloadHash,
			AdmissionState: "READY",
			Payload:        payload,
		}
		packet, err := f1t.EncodeFrame(frame)
		require.NoError(t, err)
		return frame, packet
	}
	collectorIdentity := f1t.ProcessIdentity{
		StartID:        "collector-start",
		ExecutableHash: strings.Repeat("b", 64),
	}

	for _, failAtSync := range []int{1, 2} {
		t.Run("sync failure "+strconv.Itoa(failAtSync), func(t *testing.T) {
			injected := errors.New("injected sync failure")
			syncCount := 0
			collector, err := f1t.CreateDurableCollectorWithHooks(
				filepath.Join(t.TempDir(), "record.jsonl"),
				f1t.CollectorHooks{
					Clock: func() (uint64, error) { return uint64(syncCount + 1), nil },
					BeforeSync: func() error {
						syncCount++
						if syncCount == failAtSync {
							return injected
						}
						return nil
					},
				},
			)
			require.NoError(t, err)
			t.Cleanup(func() { _ = collector.Close() })
			frame, packet := newFrame(t)
			child := &childProcess{role: "target"}
			sendCount := 0
			err = appendAndAckWithSender(collector, child, collectorIdentity, frame, packet, func([]byte) error {
				sendCount++
				return nil
			})
			require.ErrorIs(t, err, injected)
			require.Zero(t, sendCount, "an ACK must not leave the process before both journal records are durable")
			if failAtSync == 1 {
				require.Zero(t, child.collectorOutbound, "the ACK must not be constructed when the incoming frame is not durable")
			}
		})
	}

	t.Run("success sends only after two syncs", func(t *testing.T) {
		syncCount := 0
		collector, err := f1t.CreateDurableCollectorWithHooks(
			filepath.Join(t.TempDir(), "record.jsonl"),
			f1t.CollectorHooks{
				Clock: func() (uint64, error) { return uint64(syncCount + 1), nil },
				BeforeSync: func() error {
					syncCount++
					return nil
				},
			},
		)
		require.NoError(t, err)
		t.Cleanup(func() { _ = collector.Close() })
		frame, packet := newFrame(t)
		child := &childProcess{role: "target"}
		sendCount := 0
		err = appendAndAckWithSender(collector, child, collectorIdentity, frame, packet, func(ackPacket []byte) error {
			require.Equal(t, 2, syncCount, "outbound send must remain ordered after both durable appends")
			require.NotEmpty(t, ackPacket)
			sendCount++
			return nil
		})
		require.NoError(t, err)
		require.Equal(t, 1, sendCount)
		require.Equal(t, uint64(1), child.collectorOutbound)
	})
}

func verifyRehearsalRecord(t *testing.T, raw []byte, result output) {
	t.Helper()
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'})
	require.Len(t, lines, 25)
	counts := make(map[f1t.PayloadType]int)
	lastSourceSequence := make(map[string]uint64)
	previousHash := ""
	for index, line := range lines[:24] {
		var record f1t.CollectorRecord
		require.NoError(t, json.Unmarshal(line, &record))
		require.Equal(t, uint64(index+1), record.GlobalSequence)
		require.Equal(t, previousHash, record.PreviousRecordSHA256)
		require.Zero(t, record.RuntimeCredit)
		require.Equal(t, lastSourceSequence[record.SourceIdentity]+1, record.Frame.SourceSequence)
		lastSourceSequence[record.SourceIdentity] = record.Frame.SourceSequence
		var payloadHeader struct {
			Type f1t.PayloadType `json:"type"`
		}
		require.NoError(t, json.Unmarshal(record.Frame.Payload, &payloadHeader))
		counts[payloadHeader.Type]++
		lineWithNewline := append(append([]byte(nil), line...), '\n')
		sum := sha256.Sum256(lineWithNewline)
		previousHash = hex.EncodeToString(sum[:])
	}
	require.Equal(t, map[f1t.PayloadType]int{
		f1t.PayloadRoleReady:  3,
		f1t.PayloadDurableAck: 9,
		f1t.PayloadCommand:    6,
		f1t.PayloadRoleAck:    3,
		f1t.PayloadDrain:      3,
	}, counts)
	require.Equal(t, map[string]uint64{
		"publisher": 3, "target": 3, "passive": 3,
		"collector/publisher": 5, "collector/target": 5, "collector/passive": 5,
	}, lastSourceSequence)
	var closure f1t.CollectorClosure
	require.NoError(t, json.Unmarshal(lines[24], &closure))
	require.Equal(t, uint64(24), closure.FinalGlobalSequence)
	require.Equal(t, previousHash, closure.FinalRecordSHA256)
	require.Zero(t, closure.AuthoritativeCredit)
	require.True(t, closure.PhaseIOnly)
	require.False(t, closure.PhaseIISubmission)
	require.False(t, closure.NumericRatification)
	require.Equal(t, closure, *result.CollectorClosure)
}

func verifyTransportRecord(t *testing.T, raw []byte, result output) {
	t.Helper()
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'})
	require.Len(t, lines, 15)
	lastSourceSequence := make(map[string]uint64)
	counts := make(map[f1t.PayloadType]int)
	previousHash := ""
	for index, line := range lines[:14] {
		var record f1t.CollectorRecord
		require.NoError(t, json.Unmarshal(line, &record))
		require.Equal(t, uint64(index+1), record.GlobalSequence)
		require.Equal(t, previousHash, record.PreviousRecordSHA256)
		require.Equal(t, lastSourceSequence[record.SourceIdentity]+1, record.Frame.SourceSequence)
		lastSourceSequence[record.SourceIdentity] = record.Frame.SourceSequence
		var header struct {
			Type f1t.PayloadType `json:"type"`
		}
		require.NoError(t, json.Unmarshal(record.Frame.Payload, &header))
		counts[header.Type]++
		hash := sha256.Sum256(append(append([]byte(nil), line...), '\n'))
		previousHash = hex.EncodeToString(hash[:])
	}
	require.Equal(t, map[f1t.PayloadType]int{f1t.PayloadSendCatalog: 5, f1t.PayloadCallbackEvent: 9}, counts)
	require.Equal(t, map[string]uint64{"publisher": 5, "target": 5, "passive": 4}, lastSourceSequence)
	var closure f1t.CollectorClosure
	require.NoError(t, json.Unmarshal(lines[14], &closure))
	require.Equal(t, uint64(14), closure.FinalGlobalSequence)
	require.Equal(t, previousHash, closure.FinalRecordSHA256)
	require.Zero(t, closure.AuthoritativeCredit)
	require.True(t, closure.PhaseIOnly)
	require.Equal(t, closure, *result.TransportClosure)
}
