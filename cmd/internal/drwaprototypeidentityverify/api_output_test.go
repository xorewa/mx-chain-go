package drwaprototypeidentityverify

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateExactArtifactOutputRejectsUnsafeExpectedName(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "artifacts"), 0o700))

	for _, name := range []string{"", ".", "..", "../escape.json", "/escape.json", "nested/escape.json", `nested\escape.json`} {
		t.Run(name, func(t *testing.T) {
			err := ValidateExactArtifactOutput(root, filepath.Join(root, "escape.json"), name, nil, nil)
			require.ErrorContains(t, err, "safe direct-child component")
		})
	}

	valid := filepath.Join(root, "artifacts", "plan-observer0.json")
	require.NoError(t, ValidateExactArtifactOutput(root, valid, "plan-observer0.json", nil, nil))
}

func TestIsSafeArtifactComponent(t *testing.T) {
	for _, value := range []string{"observer0", "observer-0-0", "plan.observer_0.json"} {
		require.True(t, IsSafeArtifactComponent(value), value)
	}
	for _, value := range []string{"", ".", "..", "../observer0", "/observer0", "observer/0", `observer\0`, "observer 0"} {
		require.False(t, IsSafeArtifactComponent(value), value)
	}
}
