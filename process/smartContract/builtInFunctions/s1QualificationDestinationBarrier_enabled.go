//go:build drwa_s1_qual_barrier

package builtInFunctions

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/multiversx/mx-chain-go/common/drwaqualification"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

type s1QualificationDestinationBarrier struct {
	arm      *drwaqualification.Arm
	recorder *drwaqualification.Recorder
}

func init() {
	drwaqualification.RegisterVariant(drwaqualification.VariantBarrier)
}

func newS1QualificationDestinationBarrier() (*s1QualificationDestinationBarrier, error) {
	arm, armHash, err := drwaqualification.LoadArmFromEnvironment(drwaqualification.VariantBarrier, time.Now())
	if errors.Is(err, drwaqualification.ErrArmUnavailable) {
		return &s1QualificationDestinationBarrier{}, nil
	}
	if err != nil {
		return nil, err
	}
	if !drwaqualification.DeclaredActionTagMatches(arm, "HOLD_POST_DELEGATE_PRE_VMOUTPUT_RETURN_UNTIL_EXACT_RELEASE") {
		return nil, fmt.Errorf("%w: barrier declared action", drwaqualification.ErrInvalidArm)
	}
	if err = drwaqualification.VerifyRunningBinary(arm); err != nil {
		return nil, err
	}
	recorder, err := drwaqualification.CreateRecorder(arm.EvidencePath, armHash, arm)
	if err != nil {
		return nil, err
	}
	if err = recorder.Append(drwaqualification.LifecycleLoaded, map[string]any{
		"hold_generation": arm.Barrier.HoldGeneration,
	}); err != nil {
		_ = recorder.Close()
		return nil, err
	}
	return &s1QualificationDestinationBarrier{arm: arm, recorder: recorder}, nil
}

func (barrier *s1QualificationDestinationBarrier) reach(
	vmInput *vmcommon.ContractCallInput,
	effectID, contextHash, networkDomain [32]byte,
	protocolKind uint32,
) error {
	if barrier == nil || barrier.arm == nil {
		return nil
	}
	arm := barrier.arm
	if !drwaqualification.DeclaredActionTagMatches(arm, "HOLD_POST_DELEGATE_PRE_VMOUTPUT_RETURN_UNTIL_EXACT_RELEASE") {
		return fmt.Errorf("%w: barrier declared action", drwaqualification.ErrInvalidArm)
	}
	if vmInput == nil || arm.ProtocolMessageKind != protocolKind ||
		arm.OriginalTransactionHash != hex.EncodeToString(vmInput.OriginalTxHash) ||
		arm.CarrierHash != hex.EncodeToString(vmInput.CurrentTxHash) ||
		arm.EffectID != hex.EncodeToString(effectID[:]) ||
		arm.ContextHash != hex.EncodeToString(contextHash[:]) ||
		arm.NetworkDomain != hex.EncodeToString(networkDomain[:]) ||
		arm.Barrier.DestinationExecutionIdentity != hex.EncodeToString(vmInput.CurrentTxHash) {
		return fmt.Errorf("%w: destination barrier selector mismatch", drwaqualification.ErrInvalidArm)
	}
	if _, statErr := os.Lstat(arm.Barrier.ReleasePath); statErr == nil {
		return fmt.Errorf("%w: barrier release pre-exists reach", drwaqualification.ErrInvalidArm)
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("%w: barrier release preflight: %v", drwaqualification.ErrInvalidArm, statErr)
	}
	if err := barrier.recorder.Append(drwaqualification.LifecycleReached, map[string]any{
		"destination_execution_identity": arm.Barrier.DestinationExecutionIdentity,
		"hold_generation":                arm.Barrier.HoldGeneration,
	}); err != nil {
		return err
	}
	for {
		now := time.Now()
		if now.Unix() >= arm.ExpiresUnix {
			return fmt.Errorf("%w: barrier expired without release", drwaqualification.ErrInvalidArm)
		}
		_, err := os.Lstat(arm.Barrier.ReleasePath)
		if err == nil {
			if err = drwaqualification.VerifyExactFile(arm.Barrier.ReleasePath, arm.Barrier.ReleaseRecordSHA256); err != nil {
				return err
			}
			break
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("%w: release observation: %v", drwaqualification.ErrInvalidArm, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err := barrier.recorder.Append(drwaqualification.LifecycleConsumed, map[string]any{
		"release_record_sha256": arm.Barrier.ReleaseRecordSHA256,
	}); err != nil {
		return err
	}
	if err := barrier.recorder.Append(drwaqualification.LifecycleReleased, map[string]any{
		"release": "EXACT_FSYNCED_RECORD",
	}); err != nil {
		return err
	}
	return barrier.recorder.Close()
}
