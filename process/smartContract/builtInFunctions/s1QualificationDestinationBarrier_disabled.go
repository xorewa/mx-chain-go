//go:build !drwa_s1_qual_barrier

package builtInFunctions

import vmcommon "github.com/multiversx/mx-chain-vm-common-go"

type s1QualificationDestinationBarrier struct{}

func newS1QualificationDestinationBarrier() (*s1QualificationDestinationBarrier, error) {
	return &s1QualificationDestinationBarrier{}, nil
}

func (barrier *s1QualificationDestinationBarrier) reach(
	_ *vmcommon.ContractCallInput,
	_, _, _ [32]byte,
	_ uint32,
) error {
	return nil
}
