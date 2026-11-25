package parsing

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/stretchr/testify/require"
)

func TestQualSP281CLaneFInitialProgrammeInputAtomicity(t *testing.T) {
	dir := t.TempDir()
	raw := qualStageARaw(t)
	pin := fmt.Sprintf("%x", sha256.Sum256(raw))
	first := filepath.Join(dir, "first")
	second := filepath.Join(dir, "second")
	empty := filepath.Join(dir, "empty")
	require.NoError(t, os.WriteFile(first, raw, 0600))
	require.NoError(t, os.WriteFile(second, raw, 0600))
	require.NoError(t, os.WriteFile(empty, nil, 0600))
	alias := filepath.Join(dir, "alias")
	require.NoError(t, os.Symlink(second, alias))
	for _, tt := range []struct {
		name, path, digest string
	}{
		{"noncanonical absolute path", dir + "/./second", pin},
		{"malformed digest", second, "invalid"},
		{"symlink", alias, pin},
		{"empty file", empty, fmt.Sprintf("%x", sha256.Sum256(nil))},
		{"duplicate semantic identity in distinct files", second, pin},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out, err := LoadDRWAInitialProgrammeInputs(
				[]config.DRWAInitialProgrammeInput{{Path: first, SHA256: pin}, {Path: tt.path, SHA256: tt.digest}},
				qualStageALimits(), &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(),
			)
			require.ErrorIs(t, err, errInitialProgrammeFile)
			require.Nil(t, out)
		})
	}
}

func TestQualSP281CLaneFInitialProgrammeInputsRefuseMissingOrMalformedEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence")
	raw := []byte("malformed evidence")
	input := []config.DRWAInitialProgrammeInput{{Path: path, SHA256: fmt.Sprintf("%x", sha256.Sum256(raw))}}
	load := func() error {
		out, err := LoadDRWAInitialProgrammeInputs(input, qualStageALimits(), &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b())
		require.Nil(t, out)
		return err
	}
	require.True(t, errors.Is(load(), os.ErrNotExist))
	require.NoError(t, os.WriteFile(path, raw, 0600))
	require.Error(t, load())
}

func TestQualSP281CLaneFInitialProgrammeOpenRefusalIsAtomic(t *testing.T) {
	dir := t.TempDir()
	raw := qualStageARaw(t)
	pin := fmt.Sprintf("%x", sha256.Sum256(raw))
	first := filepath.Join(dir, "readable")
	second := filepath.Join(dir, "unreadable")
	require.NoError(t, os.WriteFile(first, raw, 0600))
	require.NoError(t, os.WriteFile(second, raw, 0000))
	info, err := os.Lstat(second)
	require.NoError(t, err)
	require.True(t, info.Mode().IsRegular())
	fd, err := os.Open(second)
	if err == nil {
		require.NoError(t, fd.Close())
		t.Skip("execution identity can read a mode-000 file")
	}
	require.ErrorIs(t, err, os.ErrPermission)
	out, err := LoadDRWAInitialProgrammeInputs(
		[]config.DRWAInitialProgrammeInput{{Path: first, SHA256: pin}, {Path: second, SHA256: pin}},
		qualStageALimits(), &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(),
	)
	require.ErrorIs(t, err, os.ErrPermission)
	require.Nil(t, out)
}
