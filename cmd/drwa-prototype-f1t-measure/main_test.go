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
	build.Env = os.Environ()
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
	buildOutput, err := build.CombinedOutput()
	require.NoError(t, err, string(buildOutput))
	command := exec.Command(binary, "--mode=collector", "--rehearsal-root="+t.TempDir())
	command.Env = append(os.Environ(), phaseIEnvironment+"=1", phaseIFailRoleEnvironment+"=target")
	result, err := command.CombinedOutput()
	require.Error(t, err, string(result))
	require.NotContains(t, string(result), "OFFLINE_FULL_GUARDED_SEND_RECONCILIATION_REHEARSAL_PASS")
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
