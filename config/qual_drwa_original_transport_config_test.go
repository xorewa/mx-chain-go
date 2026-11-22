package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestQualDRWAOriginalTransportClone(t *testing.T) {
	first := &DRWAInitialProgrammeStartup{
		OriginalDatabasePath: "/qualification/db", RecordDigest: [32]byte{1},
		ReleaseWait: time.Millisecond, ReleaseMaxBytes: 1,
		Limits: DRWAInitialProgrammeLimits{AdmissionRole: []byte("fixture-one"), IndependentRole: []byte("fixture-two")},
	}
	second := first.Clone()
	first.RecordDigest[0] = 2
	first.Limits.AdmissionRole[0] = 0
	first.Limits.IndependentRole[0] = 0
	first.ReleaseWait = 0
	first.ReleaseMaxBytes = 0
	require.Equal(t, [32]byte{1}, second.RecordDigest)
	require.Equal(t, "/qualification/db", second.OriginalDatabasePath)
	require.Equal(t, time.Millisecond, second.ReleaseWait)
	require.Equal(t, int64(1), second.ReleaseMaxBytes)
	require.Equal(t, []byte("fixture-one"), second.Limits.AdmissionRole)
	require.Equal(t, []byte("fixture-two"), second.Limits.IndependentRole)
}
