package drwaqualification

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testHash(label string) string {
	digest := sha256.Sum256([]byte(label))
	return hex.EncodeToString(digest[:])
}

func validTestArm(root string, variant Variant) Arm {
	mutationKind := "REPLACE_CONTEXT_HASH"
	mutation := []byte(strings.Repeat("x", 32))
	switch variant {
	case VariantTransport:
		mutationKind = "HOLD_RELEASE_FORWARD_ONCE"
		mutation = []byte(mutationKind)
	case VariantBarrier:
		mutationKind = "HOLD_POST_DELEGATE_PRE_VMOUTPUT_RETURN_UNTIL_EXACT_RELEASE"
		mutation = []byte(mutationKind)
	case VariantReplacement:
		mutationKind = "REPLAY_RETAINED_PAIR_ON_TRIGGER_ONCE"
		mutation = []byte(mutationKind)
	}
	mutationHash := sha256.Sum256(mutation)
	arm := Arm{
		Schema: ArmSchema, Variant: variant,
		GenerationBindingSHA256: testHash("generation"), NetworkDomain: testHash("domain"),
		CaseID: "DRWA-S1-ADVERSARIAL-001", OriginalTransactionHash: testHash("original"),
		EffectID: testHash("effect"), ContextHash: testHash("context"), ProtocolMessageKind: 1,
		CarrierHash: testHash("carrier"), MiniblockHash: testHash("miniblock"),
		VariantBinarySHA256: testHash("binary"), EvidencePath: filepath.Join(root, "evidence.jsonl"),
		CreatedUnix: time.Now().Add(-time.Second).Unix(), ExpiresUnix: time.Now().Add(time.Minute).Unix(),
		DeclaredMutation:           DeclaredMutation{Kind: mutationKind, ValueHex: hex.EncodeToString(mutation), ValueSHA256: hex.EncodeToString(mutationHash[:])},
		AuthoritativeRuntimeCredit: 0, ProductionEligible: false,
	}
	switch variant {
	case VariantTransport:
		arm.Transport = &TransportArm{BaseTopic: "txBlockBodies_0_1", SourceShard: 0, ReceivingShard: 1,
			CanonicalMembershipProofSHA256: testHash("membership"), DeclaredDeliveryAction: "HOLD_RELEASE_FORWARD_ONCE",
			RawDeliverySHA256: testHash("raw"), MaxMatchedDeliveries: 1,
			ReleasePath: filepath.Join(root, "release.json"), ReleaseRecordSHA256: testHash("release")}
	case VariantBarrier:
		arm.Barrier = &BarrierArm{DestinationExecutionIdentity: arm.CarrierHash,
			DestinationValidatorSetSHA256: testHash("validators"), HoldGeneration: 1,
			ReleaseRecordSHA256: testHash("release"), ReleasePath: filepath.Join(root, "release.json")}
	case VariantReplacement:
		arm.Replacement = &ReplacementArm{RetainedHeaderHash: testHash("retained"),
			RetainedHeaderMarshaledSHA256: testHash("retained-header"), RetainedBodyMarshaledSHA256: testHash("retained-body"),
			TriggerHeaderHash: testHash("trigger"), TriggerHeaderMarshaledSHA256: testHash("trigger-header"),
			TriggerBodyMarshaledSHA256: testHash("trigger-body")}
	case VariantPostAuth:
		arm.PostAuth = &PostAuthArm{CompletionFunction: "DRWASettlementReceipt",
			CanonicalPayloadSHA256: testHash("payload"), DeclaredMutationKind: arm.DeclaredMutation.Kind,
			DeclaredMutationValueSHA256:       arm.DeclaredMutation.ValueSHA256,
			OriginalCarrierPreservationSHA256: testHash("payload")}
	}
	return arm
}

func writeTestArm(t *testing.T, arm Arm, path string) {
	t.Helper()
	raw, err := json.Marshal(arm)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
}

func TestLoadArmExactAndFailClosed(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "arm.json")
	arm := validTestArm(root, VariantTransport)
	writeTestArm(t, arm, path)

	loaded, _, err := LoadArm(path, VariantTransport, time.Now())
	require.NoError(t, err)
	require.Equal(t, arm.CaseID, loaded.CaseID)

	_, _, err = LoadArm(path, VariantBarrier, time.Now())
	require.ErrorIs(t, err, ErrInvalidArm)

	require.NoError(t, os.Chmod(path, 0o644))
	_, _, err = LoadArm(path, VariantTransport, time.Now())
	require.ErrorIs(t, err, ErrInvalidArm)
}

func TestLoadArmRejectsUnknownTrailingSymlinkAndExpired(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "arm.json")
	arm := validTestArm(root, VariantTransport)
	writeTestArm(t, arm, path)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	raw = []byte(strings.Replace(string(raw), "{", "{\"unknown\":true,", 1))
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	_, _, err = LoadArm(path, VariantTransport, time.Now())
	require.ErrorIs(t, err, ErrInvalidArm)

	writeTestArm(t, arm, path)
	link := filepath.Join(root, "link.json")
	require.NoError(t, os.Symlink(path, link))
	_, _, err = LoadArm(link, VariantTransport, time.Now())
	require.ErrorIs(t, err, ErrInvalidArm)

	arm.ExpiresUnix = time.Now().Add(-time.Second).Unix()
	arm.CreatedUnix = arm.ExpiresUnix - 10
	writeTestArm(t, arm, path)
	_, _, err = LoadArm(path, VariantTransport, time.Now())
	require.ErrorIs(t, err, ErrInvalidArm)
}

func TestArmMutationValueHashAndVariantPayloadAreBinding(t *testing.T) {
	root := t.TempDir()
	arm := validTestArm(root, VariantPostAuth)
	arm.DeclaredMutation.ValueHex = hex.EncodeToString([]byte("different"))
	require.ErrorIs(t, arm.Validate(VariantPostAuth, time.Now()), ErrInvalidArm)

	arm = validTestArm(root, VariantPostAuth)
	arm.Transport = validTestArm(root, VariantTransport).Transport
	require.ErrorIs(t, arm.Validate(VariantPostAuth, time.Now()), ErrInvalidArm)

	arm = validTestArm(root, VariantTransport)
	arm.ExpiresUnix = arm.CreatedUnix + maxValiditySeconds + 1
	require.ErrorIs(t, arm.Validate(VariantTransport, time.Now()), ErrInvalidArm)
}

func FuzzArmJSONValidationNeverPanics(f *testing.F) {
	root := f.TempDir()
	seed, err := json.Marshal(validTestArm(root, VariantTransport))
	require.NoError(f, err)
	f.Add(seed)
	f.Add([]byte(`{"schema":"DRWA_S1_QUALIFICATION_ARM_V1"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var arm Arm
		if json.Unmarshal(raw, &arm) != nil {
			return
		}
		_ = arm.Validate(VariantTransport, time.Now())
	})
}
