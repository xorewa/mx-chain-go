package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// This is a vocabulary-only check. Neither accepted mode string supplies
// an admitted deployment identity, predecessor, database, or startup grant.
func TestQualSP259StartupModeVocabulary(t *testing.T) {
	for _, tc := range []struct {
		mode   string
		bounds string
		known  bool
	}{
		{mode: "original", bounds: "OriginalReleaseWaitMilliseconds = 1\nOriginalReleaseMaxBytes = 64\n", known: true},
		{mode: "persisted", known: true},
		{mode: "checkpoint"},
		{mode: "hardfork"},
		{mode: "import-database"},
		{mode: "migration"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			body := []byte(fmt.Sprintf("Mode = %q\n%s", tc.mode, tc.bounds))
			path := filepath.Join(t.TempDir(), "mode.toml")
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(body)
			record, err := readDRWAStartupRecord(fmt.Sprintf("%x:%d:%s", digest, len(body), path))
			if !tc.known {
				if !errors.Is(err, errDRWAStartupRecord) || record != nil {
					t.Fatalf("unsupported mode %q: record returned or wrong error: %v", tc.mode, err)
				}
				return
			}
			if err != nil || record == nil || record.Mode != tc.mode {
				t.Fatalf("known mode %q: unexpected syntax result: %v", tc.mode, err)
			}
		})
	}
}
