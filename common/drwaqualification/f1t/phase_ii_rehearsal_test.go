package f1t

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// This test is the package-level guard for the Phase-II boundary.  The command
// package separately runs the complete subprocess rehearsal; here each legacy
// or mixed-context substitution is proved incapable of entering a Phase-II
// durable record.
func TestPhaseIIRehearsalRejectsLegacyAndMixedContextAtDurableBoundary(t *testing.T) {
	contextDigest := strings.Repeat("c1", 32)
	valid := validPhaseIIFrame(t, contextDigest)
	packet, err := EncodeFrame(valid)
	require.NoError(t, err)
	decoded, err := DecodeFrame(packet)
	require.NoError(t, err)
	t.Run("valid context", func(t *testing.T) {
		collector, createErr := CreateDurableCollectorForCampaign(filepath.Join(t.TempDir(), "valid.jsonl"), contextDigest, CollectorHooks{})
		require.NoError(t, createErr)
		defer collector.Close()
		_, appendErr := collector.AppendFrom("target", decoded)
		require.NoError(t, appendErr)
	})
	t.Run("legacy V1", func(t *testing.T) {
		collector, createErr := CreateDurableCollectorForCampaign(filepath.Join(t.TempDir(), "legacy.jsonl"), contextDigest, CollectorHooks{})
		require.NoError(t, createErr)
		defer collector.Close()
		legacy := valid
		legacy.SchemaVersion = SchemaVersion
		legacy.CampaignContextSHA256 = ""
		legacyPayload, legacyHash, payloadErr := NewPayload(RoleReadyPayload{Type: PayloadRoleReady, Phase: "INTERCEPTED_REHEARSAL", Role: "target"})
		require.NoError(t, payloadErr)
		legacy.Payload = legacyPayload
		legacy.PayloadHash = legacyHash
		_, appendErr := collector.AppendFrom("target", legacy)
		require.ErrorIs(t, appendErr, ErrCampaignIdentity)
	})
	t.Run("mixed context", func(t *testing.T) {
		collector, createErr := CreateDurableCollectorForCampaign(filepath.Join(t.TempDir(), "mixed.jsonl"), contextDigest, CollectorHooks{})
		require.NoError(t, createErr)
		defer collector.Close()
		mixed := valid
		mixed.CampaignContextSHA256 = strings.Repeat("d2", 32)
		_, appendErr := collector.AppendFrom("target", mixed)
		require.ErrorIs(t, appendErr, ErrCampaignIdentity)
	})
}
