//go:build drwa_s1_qual_postauth

package builtInFunctions

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common/drwaqualification"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwa"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

func TestS1QualificationCompletionMutationChangesOneContextFieldAfterAuthentication(t *testing.T) {
	root := t.TempDir()
	domain := sha256.Sum256([]byte("domain"))
	effect := sha256.Sum256([]byte("effect"))
	context := sha256.Sum256([]byte("context"))
	destination := sha256.Sum256([]byte("destination"))
	receipt, err := drwa.BuildSettlementReceipt(domain, effect, context, destination)
	require.NoError(t, err)
	payload, err := drwa.EncodeSettlementReceipt(receipt)
	require.NoError(t, err)
	replacementContext := sha256.Sum256([]byte("replacement-context"))
	valueHash := sha256.Sum256(replacementContext[:])
	payloadHash := sha256.Sum256(payload)
	original := sha256.Sum256([]byte("original"))
	carrier := sha256.Sum256([]byte("carrier"))
	arm := &drwaqualification.Arm{
		Variant: drwaqualification.VariantPostAuth, CaseID: "DRWA-S1-ADVERSARIAL-016",
		OriginalTransactionHash: hex.EncodeToString(original[:]), CarrierHash: hex.EncodeToString(carrier[:]),
		EffectID: hex.EncodeToString(effect[:]), ContextHash: hex.EncodeToString(context[:]),
		EvidencePath:     filepath.Join(root, "events.jsonl"),
		DeclaredMutation: drwaqualification.DeclaredMutation{Kind: "REPLACE_CONTEXT_HASH", ValueHex: hex.EncodeToString(replacementContext[:]), ValueSHA256: hex.EncodeToString(valueHash[:])},
		PostAuth: &drwaqualification.PostAuthArm{CompletionFunction: DRWASettlementReceiptFunction,
			CanonicalPayloadSHA256: hex.EncodeToString(payloadHash[:]), DeclaredMutationKind: "REPLACE_CONTEXT_HASH",
			DeclaredMutationValueSHA256: hex.EncodeToString(valueHash[:]), OriginalCarrierPreservationSHA256: hex.EncodeToString(payloadHash[:])},
	}
	recorder, err := drwaqualification.CreateRecorder(arm.EvidencePath, sha256.Sum256([]byte("arm")), arm)
	require.NoError(t, err)
	defer recorder.Close()
	require.NoError(t, recorder.Append(drwaqualification.LifecycleLoaded, map[string]any{"loaded": true}))
	hook := &s1QualificationCompletionMutation{arm: arm, recorder: recorder}
	input := &vmcommon.ContractCallInput{Function: DRWASettlementReceiptFunction, VMInput: vmcommon.VMInput{
		OriginalTxHash: original[:], CurrentTxHash: carrier[:], Arguments: [][]byte{append([]byte(nil), payload...)},
	}}
	mutatedInput, mutatedPayload, err := hook.apply(input, payload)
	require.NoError(t, err)
	require.NotSame(t, input, mutatedInput)
	require.Equal(t, payload, input.Arguments[0])
	mutatedReceipt, err := drwa.DecodeSettlementReceipt(mutatedPayload)
	require.NoError(t, err)
	require.Equal(t, replacementContext, mutatedReceipt.ContextHash)
	require.Equal(t, effect, mutatedReceipt.EffectID)
}

func TestS1QualificationCompletionMutationRejectsCanonicalPayloadDrift(t *testing.T) {
	hook := &s1QualificationCompletionMutation{arm: &drwaqualification.Arm{
		PostAuth: &drwaqualification.PostAuthArm{CompletionFunction: DRWASettlementReceiptFunction, CanonicalPayloadSHA256: hex.EncodeToString(make([]byte, 32))},
	}}
	input := &vmcommon.ContractCallInput{Function: DRWASettlementReceiptFunction}
	_, _, err := hook.apply(input, []byte("different"))
	require.Error(t, err)
}

func TestS1QualificationPostAuthTaggedDisarmedIsExactIdentity(t *testing.T) {
	t.Setenv(drwaqualification.ArmPathEnvironment, "")
	mutation, err := newS1QualificationCompletionMutation()
	require.NoError(t, err)
	input := &vmcommon.ContractCallInput{}
	payload := []byte("unaltered")
	observedInput, observedPayload, err := mutation.apply(input, payload)
	require.NoError(t, err)
	require.Same(t, input, observedInput)
	require.Equal(t, payload, observedPayload)
}

func TestCloneCompletionInputIsCompleteBidirectionalAndPreservesNilEmpty(t *testing.T) {
	input := completeQualificationInput()
	clone := cloneCompletionInput(input)
	require.Equal(t, input, clone)
	require.NotSame(t, input, clone)
	require.Nil(t, clone.Arguments[1])
	require.NotNil(t, clone.Arguments[2])
	require.Empty(t, clone.Arguments[2])
	require.Nil(t, clone.ESDTTransfers[0])

	cloneSnapshot := cloneCompletionInput(clone)
	mutateEveryQualificationReference(input)
	require.Equal(t, cloneSnapshot, clone, "mutating the original must not alter the clone")

	secondOriginal := completeQualificationInput()
	secondSnapshot := cloneCompletionInput(secondOriginal)
	secondClone := cloneCompletionInput(secondOriginal)
	mutateEveryQualificationReference(secondClone)
	require.Equal(t, secondSnapshot, secondOriginal, "mutating the clone must not alter the original")
}

func TestCloneCompletionInputPinnedFieldInventory(t *testing.T) {
	fields := make([]string, 0)
	contractType := reflect.TypeOf(vmcommon.ContractCallInput{})
	vmInputType := reflect.TypeOf(vmcommon.VMInput{})
	for index := 0; index < vmInputType.NumField(); index++ {
		fields = append(fields, vmInputType.Field(index).Name)
	}
	for index := 1; index < contractType.NumField(); index++ {
		fields = append(fields, contractType.Field(index).Name)
	}
	sort.Strings(fields)
	require.Equal(t, []string{"AllowInitFunction", "Arguments", "AsyncArguments", "CallType", "CallValue", "CallerAddr", "CurrentTxHash", "ESDTTransfers", "Function", "GasLocked", "GasPrice", "GasProvided", "NativeCallOrigin", "OriginalCallerAddr", "OriginalTxHash", "PrevTxHash", "RecipientAddr", "RelayerAddr", "ReturnCallAfterError", "TxGuardian"}, fields)
}

func TestPostAuthReplacementRejectsZeroAndOriginalValues(t *testing.T) {
	domain := sha256.Sum256([]byte("domain"))
	effect := sha256.Sum256([]byte("effect"))
	context := sha256.Sum256([]byte("context"))
	destination := sha256.Sum256([]byte("destination"))
	receipt, err := drwa.BuildSettlementReceipt(domain, effect, context, destination)
	require.NoError(t, err)
	payload, err := drwa.EncodeSettlementReceipt(receipt)
	require.NoError(t, err)
	input := &vmcommon.ContractCallInput{Function: DRWASettlementReceiptFunction}

	_, err = mutateCompletionPayload(input, payload, "REPLACE_CONTEXT_HASH", make([]byte, 32))
	require.Error(t, err)
	_, err = mutateCompletionPayload(input, payload, "REPLACE_CONTEXT_HASH", context[:])
	require.Error(t, err)
	_, err = mutateCompletionPayload(input, payload, "REPLACE_EFFECT_ID", effect[:])
	require.Error(t, err)
}

func completeQualificationInput() *vmcommon.ContractCallInput {
	return &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{
		CallerAddr: []byte{1}, Arguments: [][]byte{{2}, nil, make([]byte, 0)},
		AsyncArguments: &vmcommon.AsyncArguments{CallID: []byte{3}, CallerCallID: []byte{4}, CallbackAsyncInitiatorCallID: []byte{5}, GasAccumulated: 6},
		CallValue:      big.NewInt(7), OriginalTxHash: []byte{8}, CurrentTxHash: []byte{9}, PrevTxHash: []byte{10},
		ESDTTransfers: []*vmcommon.ESDTTransfer{nil, {ESDTValue: big.NewInt(11), ESDTTokenName: []byte{12}, ESDTTokenType: 13, ESDTTokenNonce: 14}},
		TxGuardian:    []byte{15}, OriginalCallerAddr: []byte{16}, RelayerAddr: []byte{17},
	}, RecipientAddr: []byte{18}, Function: DRWASettlementReceiptFunction}
}

func mutateEveryQualificationReference(input *vmcommon.ContractCallInput) {
	input.CallerAddr[0]++
	input.Arguments[0][0]++
	input.Arguments[2] = append(input.Arguments[2], 1)
	input.AsyncArguments.CallID[0]++
	input.AsyncArguments.CallerCallID[0]++
	input.AsyncArguments.CallbackAsyncInitiatorCallID[0]++
	input.CallValue.Add(input.CallValue, big.NewInt(1))
	input.OriginalTxHash[0]++
	input.CurrentTxHash[0]++
	input.PrevTxHash[0]++
	input.ESDTTransfers[1].ESDTValue.Add(input.ESDTTransfers[1].ESDTValue, big.NewInt(1))
	input.ESDTTransfers[1].ESDTTokenName[0]++
	input.TxGuardian[0]++
	input.OriginalCallerAddr[0]++
	input.RelayerAddr[0]++
	input.RecipientAddr[0]++
}
