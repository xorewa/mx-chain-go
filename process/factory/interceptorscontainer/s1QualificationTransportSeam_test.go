//go:build drwa_s1_qual_transport

package interceptorscontainer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common/drwaqualification"
	"github.com/multiversx/mx-chain-go/p2p"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/p2pmocks"
)

func transportTestHash(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func TestS1QualificationTransportSeamExactDuplicateAndNonSelectedPassThrough(t *testing.T) {
	root := t.TempDir()
	raw := []byte("canonical miniblock bytes")
	release := []byte("exact release record")
	releasePath := filepath.Join(root, "release.json")
	binary, err := os.ReadFile("/proc/self/exe")
	require.NoError(t, err)
	mutation := []byte("DUPLICATE_ONCE")
	arm := drwaqualification.Arm{
		Schema: drwaqualification.ArmSchema, Variant: drwaqualification.VariantTransport,
		GenerationBindingSHA256: transportTestHash([]byte("generation")), NetworkDomain: transportTestHash([]byte("domain")),
		CaseID: "DRWA-S1-ADVERSARIAL-004", OriginalTransactionHash: transportTestHash([]byte("original")),
		EffectID: transportTestHash([]byte("effect")), ContextHash: transportTestHash([]byte("context")), ProtocolMessageKind: 1,
		CarrierHash: transportTestHash([]byte("carrier")), MiniblockHash: transportTestHash([]byte("miniblock")),
		VariantBinarySHA256: transportTestHash(binary), EvidencePath: filepath.Join(root, "events.jsonl"),
		CreatedUnix: time.Now().Add(-time.Second).Unix(), ExpiresUnix: time.Now().Add(time.Minute).Unix(),
		DeclaredMutation: drwaqualification.DeclaredMutation{Kind: "DUPLICATE_ONCE", ValueHex: hex.EncodeToString(mutation), ValueSHA256: transportTestHash(mutation)},
		Transport: &drwaqualification.TransportArm{BaseTopic: "txBlockBodies_0_1", SourceShard: 0, ReceivingShard: 1,
			CanonicalMembershipProofSHA256: transportTestHash([]byte("membership")), DeclaredDeliveryAction: "DUPLICATE_ONCE",
			RawDeliverySHA256: transportTestHash(raw), MaxMatchedDeliveries: 1,
			ReleasePath: releasePath, ReleaseRecordSHA256: transportTestHash(release)},
	}
	armRaw, err := json.Marshal(arm)
	require.NoError(t, err)
	armPath := filepath.Join(root, "arm.json")
	require.NoError(t, os.WriteFile(armPath, armRaw, 0o600))
	t.Setenv(drwaqualification.ArmPathEnvironment, armPath)

	count := 0
	underlying := &testscommon.InterceptorStub{ProcessReceivedMessageCalled: func(_ p2p.MessageP2P) ([]byte, error) {
		count++
		return []byte("ok"), nil
	}}
	decorated, err := s1QualificationTransportSeam(arm.Transport.BaseTopic, underlying)
	require.NoError(t, err)

	_, err = decorated.ProcessReceivedMessage(&p2pmocks.P2PMessageMock{DataField: []byte("other")}, "", nil)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	go func() {
		time.Sleep(30 * time.Millisecond)
		_ = os.WriteFile(releasePath, release, 0o600)
	}()
	result, err := decorated.ProcessReceivedMessage(&p2pmocks.P2PMessageMock{
		DataField: raw, TopicField: arm.Transport.BaseTopic, SeqNoField: []byte("resolver-frame"),
		PayloadField: []byte("outer-framing-is-not-the-selector"),
	}, "", nil)
	require.NoError(t, err)
	require.Equal(t, []byte("ok"), result)
	require.Equal(t, 3, count)
}

func TestS1QualificationTransportRejectsPreexistingRelease(t *testing.T) {
	root := t.TempDir()
	releasePath := filepath.Join(root, "release.json")
	release := []byte("stale")
	require.NoError(t, os.WriteFile(releasePath, release, 0o600))
	binary, err := os.ReadFile("/proc/self/exe")
	require.NoError(t, err)
	mutation := []byte("DUPLICATE_ONCE")
	arm := drwaqualification.Arm{
		Schema: drwaqualification.ArmSchema, Variant: drwaqualification.VariantTransport,
		GenerationBindingSHA256: transportTestHash([]byte("generation")), NetworkDomain: transportTestHash([]byte("domain")),
		CaseID: "DRWA-S1-ADVERSARIAL-004", OriginalTransactionHash: transportTestHash([]byte("original")),
		EffectID: transportTestHash([]byte("effect")), ContextHash: transportTestHash([]byte("context")), ProtocolMessageKind: 1,
		CarrierHash: transportTestHash([]byte("carrier")), MiniblockHash: transportTestHash([]byte("miniblock")),
		VariantBinarySHA256: transportTestHash(binary), EvidencePath: filepath.Join(root, "events.jsonl"),
		CreatedUnix: time.Now().Add(-time.Second).Unix(), ExpiresUnix: time.Now().Add(time.Minute).Unix(),
		DeclaredMutation: drwaqualification.DeclaredMutation{Kind: "DUPLICATE_ONCE", ValueHex: hex.EncodeToString(mutation), ValueSHA256: transportTestHash(mutation)},
		Transport: &drwaqualification.TransportArm{BaseTopic: "txBlockBodies_0_1", SourceShard: 0, ReceivingShard: 1,
			CanonicalMembershipProofSHA256: transportTestHash([]byte("membership")), DeclaredDeliveryAction: "DUPLICATE_ONCE",
			RawDeliverySHA256: transportTestHash([]byte("raw")), MaxMatchedDeliveries: 1,
			ReleasePath: releasePath, ReleaseRecordSHA256: transportTestHash(release)},
	}
	armRaw, err := json.Marshal(arm)
	require.NoError(t, err)
	armPath := filepath.Join(root, "arm.json")
	require.NoError(t, os.WriteFile(armPath, armRaw, 0o600))
	t.Setenv(drwaqualification.ArmPathEnvironment, armPath)
	_, err = s1QualificationTransportSeam(arm.Transport.BaseTopic, &testscommon.InterceptorStub{})
	require.ErrorIs(t, err, drwaqualification.ErrInvalidArm)
}

func TestS1QualificationTransportTaggedDisarmedIsExactIdentity(t *testing.T) {
	t.Setenv(drwaqualification.ArmPathEnvironment, "")
	underlying := &testscommon.InterceptorStub{}
	decorated, err := s1QualificationTransportSeam("txBlockBodies_0_1", underlying)
	require.NoError(t, err)
	require.Same(t, underlying, decorated)
}
