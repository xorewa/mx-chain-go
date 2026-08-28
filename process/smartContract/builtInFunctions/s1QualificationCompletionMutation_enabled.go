//go:build drwa_s1_qual_postauth

package builtInFunctions

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/multiversx/mx-chain-go/common/drwaqualification"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwa"
	"github.com/multiversx/mx-chain-go/process/smartContract/scrCommon"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

type s1QualificationCompletionMutation struct {
	arm      *drwaqualification.Arm
	recorder *drwaqualification.Recorder
}

type s1ReplacementPayload struct {
	Function   string `json:"function"`
	PayloadHex string `json:"payload_hex"`
}

func init() {
	drwaqualification.RegisterVariant(drwaqualification.VariantPostAuth)
}

func newS1QualificationCompletionMutation() (*s1QualificationCompletionMutation, error) {
	arm, armHash, err := drwaqualification.LoadArmFromEnvironment(drwaqualification.VariantPostAuth, time.Now())
	if errors.Is(err, drwaqualification.ErrArmUnavailable) {
		return &s1QualificationCompletionMutation{}, nil
	}
	if err != nil {
		return nil, err
	}
	if err = drwaqualification.VerifyRunningBinary(arm); err != nil {
		return nil, err
	}
	recorder, err := drwaqualification.CreateRecorder(arm.EvidencePath, armHash, arm)
	if err != nil {
		return nil, err
	}
	if err = recorder.Append(drwaqualification.LifecycleLoaded, map[string]any{
		"completion_function": arm.PostAuth.CompletionFunction,
	}); err != nil {
		_ = recorder.Close()
		return nil, err
	}
	return &s1QualificationCompletionMutation{arm: arm, recorder: recorder}, nil
}

func (mutation *s1QualificationCompletionMutation) apply(
	vmInput *vmcommon.ContractCallInput,
	payload []byte,
) (*vmcommon.ContractCallInput, []byte, error) {
	if mutation == nil || mutation.arm == nil {
		return vmInput, payload, nil
	}
	arm := mutation.arm
	canonicalHash := sha256.Sum256(payload)
	if vmInput == nil || vmInput.Function != arm.PostAuth.CompletionFunction ||
		arm.OriginalTransactionHash != hex.EncodeToString(vmInput.OriginalTxHash) ||
		arm.CarrierHash != hex.EncodeToString(vmInput.CurrentTxHash) ||
		arm.PostAuth.CanonicalPayloadSHA256 != hex.EncodeToString(canonicalHash[:]) ||
		arm.PostAuth.OriginalCarrierPreservationSHA256 != hex.EncodeToString(canonicalHash[:]) ||
		arm.PostAuth.DeclaredMutationKind != arm.DeclaredMutation.Kind ||
		arm.PostAuth.DeclaredMutationValueSHA256 != arm.DeclaredMutation.ValueSHA256 {
		return nil, nil, fmt.Errorf("%w: post-auth selector mismatch", drwaqualification.ErrInvalidArm)
	}
	effectID, contextHash, err := completionPayloadIdentities(vmInput.Function, payload)
	if err != nil || arm.EffectID != hex.EncodeToString(effectID[:]) || arm.ContextHash != hex.EncodeToString(contextHash[:]) {
		return nil, nil, fmt.Errorf("%w: canonical completion identities", drwaqualification.ErrInvalidArm)
	}
	if err = mutation.recorder.Append(drwaqualification.LifecycleReached, map[string]any{
		"canonical_payload_sha256": arm.PostAuth.CanonicalPayloadSHA256,
		"mutation_kind":            arm.DeclaredMutation.Kind,
	}); err != nil {
		return nil, nil, err
	}
	value, err := hex.DecodeString(arm.DeclaredMutation.ValueHex)
	if err != nil {
		return nil, nil, err
	}
	cloned := cloneCompletionInput(vmInput)
	mutated, err := mutateCompletionPayload(cloned, payload, arm.DeclaredMutation.Kind, value)
	if err != nil {
		return nil, nil, err
	}
	mutatedHash := sha256.Sum256(mutated)
	if err = mutation.recorder.Append(drwaqualification.LifecycleConsumed, map[string]any{
		"mutated_payload_sha256": hex.EncodeToString(mutatedHash[:]),
	}); err != nil {
		return nil, nil, err
	}
	if err = mutation.recorder.Append(drwaqualification.LifecycleReleased, map[string]any{
		"original_payload_preserved": true,
	}); err != nil {
		return nil, nil, err
	}
	if err = mutation.recorder.Close(); err != nil {
		return nil, nil, err
	}
	return cloned, mutated, nil
}

func completionPayloadIdentities(function string, payload []byte) ([32]byte, [32]byte, error) {
	switch function {
	case scrCommon.DRWASettlementReceiptFunction:
		receipt, err := drwa.DecodeSettlementReceipt(payload)
		if err != nil {
			return [32]byte{}, [32]byte{}, err
		}
		return receipt.EffectID, receipt.ContextHash, nil
	case scrCommon.DRWARefundEnvelopeFunction:
		refund, err := drwa.DecodeRefundEnvelope(payload)
		if err != nil {
			return [32]byte{}, [32]byte{}, err
		}
		return refund.EffectID, refund.ContextHash, nil
	default:
		return [32]byte{}, [32]byte{}, errors.New("unsupported completion function")
	}
}

func cloneCompletionInput(input *vmcommon.ContractCallInput) *vmcommon.ContractCallInput {
	if input == nil {
		return nil
	}
	cloned := *input
	cloned.CallerAddr = cloneQualificationBytes(input.CallerAddr)
	cloned.Arguments = cloneQualificationByteMatrix(input.Arguments)
	cloned.AsyncArguments = cloneQualificationAsyncArguments(input.AsyncArguments)
	cloned.CallValue = cloneQualificationBigInt(input.CallValue)
	cloned.OriginalTxHash = cloneQualificationBytes(input.OriginalTxHash)
	cloned.CurrentTxHash = cloneQualificationBytes(input.CurrentTxHash)
	cloned.PrevTxHash = cloneQualificationBytes(input.PrevTxHash)
	cloned.ESDTTransfers = cloneQualificationESDTTransfers(input.ESDTTransfers)
	cloned.TxGuardian = cloneQualificationBytes(input.TxGuardian)
	cloned.OriginalCallerAddr = cloneQualificationBytes(input.OriginalCallerAddr)
	cloned.RelayerAddr = cloneQualificationBytes(input.RelayerAddr)
	cloned.RecipientAddr = cloneQualificationBytes(input.RecipientAddr)
	return &cloned
}

func cloneQualificationBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	cloned := make([]byte, len(value))
	copy(cloned, value)
	return cloned
}

func cloneQualificationByteMatrix(values [][]byte) [][]byte {
	if values == nil {
		return nil
	}
	cloned := make([][]byte, len(values))
	for index := range values {
		cloned[index] = cloneQualificationBytes(values[index])
	}
	return cloned
}

func cloneQualificationBigInt(value *big.Int) *big.Int {
	if value == nil {
		return nil
	}
	return new(big.Int).Set(value)
}

func cloneQualificationAsyncArguments(value *vmcommon.AsyncArguments) *vmcommon.AsyncArguments {
	if value == nil {
		return nil
	}
	return &vmcommon.AsyncArguments{
		CallID: cloneQualificationBytes(value.CallID), CallerCallID: cloneQualificationBytes(value.CallerCallID),
		CallbackAsyncInitiatorCallID: cloneQualificationBytes(value.CallbackAsyncInitiatorCallID), GasAccumulated: value.GasAccumulated,
	}
}

func cloneQualificationESDTTransfers(values []*vmcommon.ESDTTransfer) []*vmcommon.ESDTTransfer {
	if values == nil {
		return nil
	}
	cloned := make([]*vmcommon.ESDTTransfer, len(values))
	for index, value := range values {
		if value == nil {
			continue
		}
		copyValue := *value
		copyValue.ESDTValue = cloneQualificationBigInt(value.ESDTValue)
		copyValue.ESDTTokenName = cloneQualificationBytes(value.ESDTTokenName)
		cloned[index] = &copyValue
	}
	return cloned
}

func mutateCompletionPayload(input *vmcommon.ContractCallInput, payload []byte, kind string, value []byte) ([]byte, error) {
	switch kind {
	case "REPLACE_CONTEXT_HASH", "REPLACE_EFFECT_ID":
		if len(value) != 32 || allQualificationZero(value) {
			return nil, errors.New("replacement digest must have 32 bytes")
		}
		if input.Function == scrCommon.DRWASettlementReceiptFunction {
			receipt, err := drwa.DecodeSettlementReceipt(payload)
			if err != nil {
				return nil, err
			}
			if kind == "REPLACE_CONTEXT_HASH" {
				if bytes.Equal(receipt.ContextHash[:], value) {
					return nil, errors.New("replacement context equals original")
				}
				copy(receipt.ContextHash[:], value)
			} else {
				if bytes.Equal(receipt.EffectID[:], value) {
					return nil, errors.New("replacement effect equals original")
				}
				copy(receipt.EffectID[:], value)
			}
			return drwa.EncodeSettlementReceipt(*receipt)
		}
		refund, err := drwa.DecodeRefundEnvelope(payload)
		if err != nil {
			return nil, err
		}
		if kind == "REPLACE_CONTEXT_HASH" {
			if bytes.Equal(refund.ContextHash[:], value) {
				return nil, errors.New("replacement context equals original")
			}
			copy(refund.ContextHash[:], value)
		} else {
			if bytes.Equal(refund.EffectID[:], value) {
				return nil, errors.New("replacement effect equals original")
			}
			copy(refund.EffectID[:], value)
		}
		return drwa.EncodeRefundEnvelope(*refund)
	case "REPLACE_REFUND_TO":
		if len(value) != 32 || allQualificationZero(value) || input.Function != scrCommon.DRWARefundEnvelopeFunction {
			return nil, errors.New("refund-to replacement route")
		}
		refund, err := drwa.DecodeRefundEnvelope(payload)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(refund.RefundTo[:], value) {
			return nil, errors.New("replacement refund-to equals original")
		}
		copy(refund.RefundTo[:], value)
		return drwa.EncodeRefundEnvelope(*refund)
	case "REPLACE_TERMINAL_PAYLOAD":
		var replacement s1ReplacementPayload
		if err := json.Unmarshal(value, &replacement); err != nil {
			return nil, err
		}
		decoded, err := hex.DecodeString(replacement.PayloadHex)
		if err != nil || len(decoded) == 0 {
			return nil, errors.New("replacement payload")
		}
		if _, _, err = completionPayloadIdentities(replacement.Function, decoded); err != nil {
			return nil, err
		}
		if replacement.Function == input.Function && bytes.Equal(decoded, payload) {
			return nil, errors.New("replacement terminal payload equals original")
		}
		input.Function = replacement.Function
		return decoded, nil
	default:
		return nil, fmt.Errorf("unsupported post-auth mutation %q", kind)
	}
}

func allQualificationZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}
