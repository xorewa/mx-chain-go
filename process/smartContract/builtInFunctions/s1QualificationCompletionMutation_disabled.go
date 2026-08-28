//go:build !drwa_s1_qual_postauth

package builtInFunctions

import vmcommon "github.com/multiversx/mx-chain-vm-common-go"

type s1QualificationCompletionMutation struct{}

func newS1QualificationCompletionMutation() (*s1QualificationCompletionMutation, error) {
	return &s1QualificationCompletionMutation{}, nil
}

func (mutation *s1QualificationCompletionMutation) apply(
	vmInput *vmcommon.ContractCallInput,
	payload []byte,
) (*vmcommon.ContractCallInput, []byte, error) {
	return vmInput, payload, nil
}
