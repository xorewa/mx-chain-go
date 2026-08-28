//go:build !drwa_s1_qual_replacement

package executionManager

import "github.com/multiversx/mx-chain-go/process/asyncExecution/cache"

type s1QualificationReplacement struct{}

func newS1QualificationReplacement(_ *executionManager) (*s1QualificationReplacement, error) {
	return &s1QualificationReplacement{}, nil
}

func (replacement *s1QualificationReplacement) prepare(pair cache.HeaderBodyPair) ([]cache.HeaderBodyPair, bool, error) {
	return []cache.HeaderBodyPair{pair}, false, nil
}

func (replacement *s1QualificationReplacement) complete(_ error) error {
	return nil
}
