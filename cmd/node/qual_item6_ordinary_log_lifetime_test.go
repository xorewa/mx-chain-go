package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/require"
)

func TestQualItem6OrdinaryLogLifetimeValidation(t *testing.T) {
	// File logging owns a process-wide stderr observer. The validation returns
	// before the runner is constructed, so isolate the logger in a bounded child.
	const childEnv = "QUAL_ITEM6_ORDINARY_LOG_LIFETIME_CHILD"
	if os.Getenv(childEnv) != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestQualItem6OrdinaryLogLifetimeValidation$", "-test.v")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", out)
		return
	}

	dir := sp259OrdinaryFixture(t, func(tree *toml.Tree) {
		tree.Set("Logs.LogFileLifeSpanInSec", int64(0))
		tree.Set("Logs.LogFileLifeSpanInMB", int64(1))
	})
	// The logger's ordinary configuration check rejects a zero rotation
	// duration. It must be propagated, before any runner/provider setup.
	err := sp259OrdinaryRunCLI(t, dir, "--"+logSaveFile.Name)
	require.ErrorContains(t, err, "for the life span duration, minimum:")
	require.ErrorContains(t, err, "provided: 0s")
	require.DirExists(t, filepath.Join(dir, "logs"))
	require.NoDirExists(t, filepath.Join(dir, "db"))
}
