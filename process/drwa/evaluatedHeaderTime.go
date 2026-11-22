package drwa

import (
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process/drwa/headertime"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// Preserve the existing DRWA type identities. The single context implementation
// lives below native hooks, so importing native factories cannot create a cycle.
type HeaderMilliseconds = headertime.HeaderMilliseconds
type HeaderTimeContext = headertime.HeaderTimeContext
type EvaluatedHeaderTime = headertime.EvaluatedHeaderTime

var (
	ErrInactiveHeaderTime    = headertime.ErrInactiveHeaderTime
	ErrUnavailableHeaderTime = headertime.ErrUnavailableHeaderTime
)

type HeaderTimeSource interface {
	headertime.HeaderTimeSource
	GetAccountsAdapter() state.AccountsAdapter
}

func NewEvaluatedHeaderTime(flags common.EnableEpochsHandler, marshaller marshal.Marshalizer, hasher hashing.Hasher) (*EvaluatedHeaderTime, error) {
	return headertime.NewEvaluatedHeaderTime(flags, marshaller, hasher)
}

func withHeaderTime(source HeaderTimeSource, context *HeaderTimeContext,
	execute func() (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
	return headertime.WithHeaderTime(source, context, execute)
}

func executeWithHeaderTime(boundary *RollbackContainment, source HeaderTimeSource,
	context *HeaderTimeContext, execute func() (*vmcommon.VMOutput, error)) error {
	return boundary.Execute(func() (*vmcommon.VMOutput, error) {
		return withHeaderTime(source, context, execute)
	})
}
