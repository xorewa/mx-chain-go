package systemSmartContracts

import (
	"testing"

	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type qualGateG21OrdinaryClassifier struct{ calls int }

func (c *qualGateG21OrdinaryClassifier) IsInterfaceNil() bool { return c == nil }
func (c *qualGateG21OrdinaryClassifier) ValidateAccounts(state.AccountsAdapter, state.AccountsAdapter) error {
	return nil
}
func (c *qualGateG21OrdinaryClassifier) WithTokenClassification(_ state.AccountsAdapter, _ []byte, execute func(bool) (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
	c.calls++
	return execute(false)
}

func TestQualGateG21Configured(t *testing.T) {
	baseline := qualGateG21Transcript(t, nil)
	classifier := &qualGateG21OrdinaryClassifier{}
	configured := qualGateG21Transcript(t, func(args *VMContextArgs) { args.DRWAClassifier = classifier })
	require.Equal(t, baseline, configured)
	require.Equal(t, 3, classifier.calls, "pause, duplicate pause and unPause must use classification")
}
