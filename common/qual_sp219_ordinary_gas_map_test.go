package common_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/stretchr/testify/require"
)

// This detached TOML fixture uses invented table and item names solely to
// verify the loader's nested map representation, not any executable schedule.
func TestQualSP219OrdinaryGasMapTableIdentity(t *testing.T) {
	t.Parallel()

	const fixture = `
[ExampleGroupA]
    SharedItem = 13
    FirstItem = 23
[ExampleGroupB]
    SharedItem = 31
    SecondItem = 47
`
	file := filepath.Join(t.TempDir(), "map.toml")
	require.NoError(t, os.WriteFile(file, []byte(fixture), 0600))

	got, err := common.LoadGasScheduleConfig(file)
	require.NoError(t, err)
	require.Equal(t, map[string]map[string]uint64{
		"ExampleGroupA": {"SharedItem": 13, "FirstItem": 23},
		"ExampleGroupB": {"SharedItem": 31, "SecondItem": 47},
	}, got)
}
