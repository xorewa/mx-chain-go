//go:build drwa_s1_qual_replacement

package executionManager

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/common/drwaqualification"
	"github.com/multiversx/mx-chain-go/process/asyncExecution/cache"
	"github.com/multiversx/mx-chain-go/process/mock"
)

func replacementTestHook(t *testing.T, root string, retained, trigger cache.HeaderBodyPair) *s1QualificationReplacement {
	t.Helper()
	marshaller := &mock.MarshalizerMock{}
	retainedHeader, err := marshaller.Marshal(retained.Header)
	require.NoError(t, err)
	retainedBody, err := marshaller.Marshal(retained.Body)
	require.NoError(t, err)
	triggerHeader, err := marshaller.Marshal(trigger.Header)
	require.NoError(t, err)
	triggerBody, err := marshaller.Marshal(trigger.Body)
	require.NoError(t, err)
	action := []byte("REPLAY_RETAINED_PAIR_ON_TRIGGER_ONCE")
	actionHash := sha256.Sum256(action)
	arm := &drwaqualification.Arm{
		Variant: drwaqualification.VariantReplacement, CaseID: "DRWA-S1-ADVERSARIAL-001",
		EvidencePath: filepath.Join(root, "events.jsonl"),
		DeclaredMutation: drwaqualification.DeclaredMutation{Kind: string(action), ValueHex: hex.EncodeToString(action),
			ValueSHA256: hex.EncodeToString(actionHash[:])},
		Replacement: &drwaqualification.ReplacementArm{
			RetainedHeaderHash: hex.EncodeToString(retained.HeaderHash), RetainedHeaderMarshaledSHA256: digestHex(retainedHeader), RetainedBodyMarshaledSHA256: digestHex(retainedBody),
			TriggerHeaderHash: hex.EncodeToString(trigger.HeaderHash), TriggerHeaderMarshaledSHA256: digestHex(triggerHeader), TriggerBodyMarshaledSHA256: digestHex(triggerBody),
		},
	}
	recorder, err := drwaqualification.CreateRecorder(arm.EvidencePath, sha256.Sum256([]byte("arm")), arm)
	require.NoError(t, err)
	t.Cleanup(func() { _ = recorder.Close() })
	require.NoError(t, recorder.Append(drwaqualification.LifecycleLoaded, map[string]any{"loaded": true}))
	return &s1QualificationReplacement{manager: &executionManager{marshaller: marshaller}, arm: arm, recorder: recorder}
}

func digestHex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func TestS1QualificationReplacementRetainsRealPairAndReplaysOnce(t *testing.T) {
	retainedHash := sha256.Sum256([]byte("retained"))
	triggerHash := sha256.Sum256([]byte("trigger"))
	retained := cache.HeaderBodyPair{HeaderHash: retainedHash[:], Header: &block.Header{Nonce: 4}, Body: &block.Body{}}
	trigger := cache.HeaderBodyPair{HeaderHash: triggerHash[:], Header: &block.Header{Nonce: 5}, Body: &block.Body{}}
	hook := replacementTestHook(t, t.TempDir(), retained, trigger)

	pairs, replay, err := hook.prepare(retained)
	require.NoError(t, err)
	require.False(t, replay)
	require.Len(t, pairs, 1)
	pairs, replay, err = hook.prepare(trigger)
	require.NoError(t, err)
	require.True(t, replay)
	require.Len(t, pairs, 2)
	require.Equal(t, retainedHash[:], pairs[0].HeaderHash)
	require.Equal(t, triggerHash[:], pairs[1].HeaderHash)
	require.NoError(t, hook.complete(nil))
	_, _, err = hook.prepare(trigger)
	require.Error(t, err)
}

func TestS1QualificationReplacementReconstructsFromCanonicalBytesWithoutBorrowedView(t *testing.T) {
	retainedHash := sha256.Sum256([]byte("retained"))
	triggerHash := sha256.Sum256([]byte("trigger"))
	retainedHeader := &block.Header{Nonce: 4}
	retained := cache.HeaderBodyPair{HeaderHash: retainedHash[:], Header: retainedHeader, Body: &block.Body{}}
	trigger := cache.HeaderBodyPair{HeaderHash: triggerHash[:], Header: &block.Header{Nonce: 5}, Body: &block.Body{}}
	hook := replacementTestHook(t, t.TempDir(), retained, trigger)
	_, _, err := hook.prepare(retained)
	require.NoError(t, err)
	retainedHeader.Nonce = 99
	pairs, replay, err := hook.prepare(trigger)
	require.NoError(t, err)
	require.True(t, replay)
	require.Equal(t, uint64(4), pairs[0].Header.GetNonce())
	require.Equal(t, uint64(99), retainedHeader.GetNonce())
}

func TestS1QualificationReplacementRestoredPairsDoNotAliasStoredBytesOrEachOther(t *testing.T) {
	retainedHash := sha256.Sum256([]byte("retained"))
	triggerHash := sha256.Sum256([]byte("trigger"))
	retained := cache.HeaderBodyPair{HeaderHash: retainedHash[:], Header: &block.Header{Nonce: 4}, Body: &block.Body{}}
	trigger := cache.HeaderBodyPair{HeaderHash: triggerHash[:], Header: &block.Header{Nonce: 5}, Body: &block.Body{}}
	hook := replacementTestHook(t, t.TempDir(), retained, trigger)
	_, _, err := hook.prepare(retained)
	require.NoError(t, err)

	first, _, _, err := hook.restorePair(hook.retainedHeaderBytes, hook.retainedBodyBytes, hook.headerType, hook.bodyType, hook.retainedHash)
	require.NoError(t, err)
	second, _, _, err := hook.restorePair(hook.retainedHeaderBytes, hook.retainedBodyBytes, hook.headerType, hook.bodyType, hook.retainedHash)
	require.NoError(t, err)
	first.Header.(*block.Header).Nonce = 77
	first.HeaderHash[0] ^= 0xff
	require.Equal(t, uint64(4), second.Header.GetNonce())
	require.Equal(t, retainedHash[:], second.HeaderHash)
	require.Equal(t, uint64(4), retained.Header.GetNonce())
}

func TestS1QualificationReplacementTaggedDisarmedIsExactIdentity(t *testing.T) {
	t.Setenv(drwaqualification.ArmPathEnvironment, "")
	replacement, err := newS1QualificationReplacement(&executionManager{})
	require.NoError(t, err)
	pair := cache.HeaderBodyPair{}
	pairs, replay, err := replacement.prepare(pair)
	require.NoError(t, err)
	require.False(t, replay)
	require.Equal(t, []cache.HeaderBodyPair{pair}, pairs)
}
