//go:build !linux

package node

import (
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process/drwa"
)

func acquireDRWAOriginal(_ *config.Configs) (*acquiredDRWAOriginal, error) {
	return nil, drwa.ErrDeploymentIdentity
}

func recheckOriginalStore(_ *acquiredDRWAOriginal) error {
	return drwa.ErrDeploymentIdentity
}
