package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualDRWAOriginalTransportRecordModeBounds(t *testing.T) {
	// The literals below exercise transport typing only.
	for _, tc := range []struct {
		name string
		raw string
		want error
	}{
		{"original_transport_fields_only", "Mode = \"original\"\nOriginalReleaseWaitMilliseconds = 1\nOriginalReleaseMaxBytes = 1\n", nil},
		{"original_missing_wait", "Mode = \"original\"\nOriginalReleaseMaxBytes = 1\n", errDRWAOriginalProvenance},
		{"original_missing_size", "Mode = \"original\"\nOriginalReleaseWaitMilliseconds = 1\n", errDRWAOriginalProvenance},
		{"original_overflow_wait", "Mode = \"original\"\nOriginalReleaseWaitMilliseconds = 9223372036854775807\nOriginalReleaseMaxBytes = 1\n", errDRWAOriginalProvenance},
		{"persisted_refuses_original_fields", "Mode = \"persisted\"\nOriginalReleaseWaitMilliseconds = 1\nOriginalReleaseMaxBytes = 1\n", errDRWAStartupRecord},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "startup.toml")
			raw := []byte(tc.raw)
			require.NoError(t, os.WriteFile(path, raw, 0600))
			digest := sha256.Sum256(raw)
			anchor := fmt.Sprintf("%x:%d:%s", digest, len(raw), path)
			record, err := readDRWAStartupRecord(anchor)
			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
				require.Nil(t, record)
				return
			}
			require.NoError(t, err)
			require.Equal(t, digest, record.recordDigest)
			require.Equal(t, int64(1), record.OriginalReleaseWaitMilliseconds)
			require.Equal(t, int64(1), record.OriginalReleaseMaxBytes)
			require.Empty(t, record.Programmes)
		})
	}
}
