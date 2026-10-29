package block

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-go/process"
	processFactory "github.com/multiversx/mx-chain-go/process/factory"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type sp1LegacyStatusContainer struct {
	process.VirtualMachinesContainer
	get func([]byte) (vmcommon.VMExecutionHandler, error)
}

func (c *sp1LegacyStatusContainer) Get(key []byte) (vmcommon.VMExecutionHandler, error) {
	return c.get(key)
}
func (c *sp1LegacyStatusContainer) IsInterfaceNil() bool { return c == nil }

type sp1LegacyStatusVM struct{ vmcommon.VMExecutionHandler }

func TestSP1CoverageBlockLegacyStatus(t *testing.T) {
	for _, mode := range []string{"missing container", "missing VM", "typed nil VM", "old VM"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			bp := &baseProcessor{}
			if mode != "missing container" {
				bp.vmContainer = &sp1LegacyStatusContainer{get: func(key []byte) (vmcommon.VMExecutionHandler, error) {
					calls++
					require.Equal(t, processFactory.SystemVirtualMachine, key)
					if mode == "missing VM" {
						return nil, errors.New("native VM absent in unconfigured context")
					}
					if mode == "typed nil VM" {
						var absent *sp1LegacyStatusVM
						return absent, nil
					}
					return &sp1LegacyStatusVM{}, nil
				}}
			}
			require.NoError(t, bp.drwaExecutionError(), "ordinary optional capability creates no DRWA failure")
			if mode == "missing container" {
				require.Zero(t, calls)
			} else {
				require.Equal(t, 1, calls)
			}
		})
	}
}
