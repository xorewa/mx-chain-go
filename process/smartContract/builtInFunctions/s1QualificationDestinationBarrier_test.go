//go:build drwa_s1_qual_barrier

package builtInFunctions

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common/drwaqualification"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

func barrierHash(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func TestS1QualificationDestinationBarrierExactRelease(t *testing.T) {
	root := t.TempDir()
	release := []byte("observer-proved-zero-credit")
	releasePath := filepath.Join(root, "release.json")
	mutation := []byte("HOLD_POST_DELEGATE_PRE_VMOUTPUT_RETURN_UNTIL_EXACT_RELEASE")
	original := sha256.Sum256([]byte("original"))
	carrier := sha256.Sum256([]byte("carrier"))
	effect := sha256.Sum256([]byte("effect"))
	context := sha256.Sum256([]byte("context"))
	domain := sha256.Sum256([]byte("domain"))
	arm := &drwaqualification.Arm{
		Schema: drwaqualification.ArmSchema, Variant: drwaqualification.VariantBarrier,
		GenerationBindingSHA256: barrierHash([]byte("generation")), NetworkDomain: hex.EncodeToString(domain[:]),
		CaseID: "DRWA-S1-ADVERSARIAL-008", OriginalTransactionHash: hex.EncodeToString(original[:]),
		EffectID: hex.EncodeToString(effect[:]), ContextHash: hex.EncodeToString(context[:]), ProtocolMessageKind: 7,
		CarrierHash: hex.EncodeToString(carrier[:]), MiniblockHash: barrierHash([]byte("miniblock")), VariantBinarySHA256: barrierHash([]byte("binary")),
		EvidencePath: filepath.Join(root, "events.jsonl"), CreatedUnix: time.Now().Add(-time.Second).Unix(), ExpiresUnix: time.Now().Add(time.Minute).Unix(),
		DeclaredMutation: drwaqualification.DeclaredMutation{Kind: string(mutation), ValueHex: hex.EncodeToString(mutation), ValueSHA256: barrierHash(mutation)},
		Barrier: &drwaqualification.BarrierArm{DestinationExecutionIdentity: hex.EncodeToString(carrier[:]),
			DestinationValidatorSetSHA256: barrierHash([]byte("validators")), HoldGeneration: 1,
			ReleaseRecordSHA256: barrierHash(release), ReleasePath: releasePath},
	}
	armHash := sha256.Sum256([]byte("arm"))
	recorder, err := drwaqualification.CreateRecorder(arm.EvidencePath, armHash, arm)
	require.NoError(t, err)
	defer recorder.Close()
	require.NoError(t, recorder.Append(drwaqualification.LifecycleLoaded, map[string]any{"loaded": true}))
	barrier := &s1QualificationDestinationBarrier{arm: arm, recorder: recorder}
	input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{
		OriginalTxHash: original[:], CurrentTxHash: carrier[:],
	}}
	go func() {
		time.Sleep(30 * time.Millisecond)
		_ = os.WriteFile(releasePath, release, 0o600)
	}()
	require.NoError(t, barrier.reach(input, effect, context, domain, 7))
}

func TestS1QualificationDestinationBarrierRejectsSelectorMismatch(t *testing.T) {
	barrier := &s1QualificationDestinationBarrier{arm: &drwaqualification.Arm{
		OriginalTransactionHash: barrierHash([]byte("expected")),
	}}
	input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{OriginalTxHash: []byte("wrong")}}
	require.Error(t, barrier.reach(input, [32]byte{}, [32]byte{}, [32]byte{}, 1))
}

func TestS1QualificationBarrierTaggedDisarmedIsExactIdentity(t *testing.T) {
	t.Setenv(drwaqualification.ArmPathEnvironment, "")
	barrier, err := newS1QualificationDestinationBarrier()
	require.NoError(t, err)
	require.NoError(t, barrier.reach(nil, [32]byte{}, [32]byte{}, [32]byte{}, 0))
}
