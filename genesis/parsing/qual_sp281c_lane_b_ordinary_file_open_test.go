package parsing

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/stretchr/testify/require"
)

// A plain local file that cannot be opened must return its OS error before
// parsing. No programme, appointment, signature, or authority fixture is used.
func TestQualSP281COrdinaryInitialProgrammeFileOpenError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "local-file")
	raw := []byte("ordinary local file")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	require.NoError(t, os.Chmod(path, 0))
	t.Cleanup(func() { require.NoError(t, os.Chmod(path, 0o600)) })

	f, err := os.Open(path)
	if err == nil {
		require.NoError(t, f.Close())
		t.Skip("execution identity can read a mode-000 file")
	}
	require.ErrorIs(t, err, os.ErrPermission)

	input := config.DRWAInitialProgrammeInput{
		Path:   path,
		SHA256: fmt.Sprintf("%x", sha256.Sum256(raw)),
	}
	out, err := LoadDRWAInitialProgrammeInputs([]config.DRWAInitialProgrammeInput{input},
		qualStageALimits(), &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b())
	require.ErrorIs(t, err, os.ErrPermission)
	require.Nil(t, out)
}
