package drwa

import "github.com/multiversx/mx-chain-go/state"

// Qualification-only unbound source. Native T42 consumer tests bind the actual
// hook instead. This fixture is not canonical installation evidence.
type qualHeaderTimeSource struct {
	*qualUnboundHeaderTime
	accounts state.AccountsAdapter
}

func (s *qualHeaderTimeSource) GetAccountsAdapter() state.AccountsAdapter { return s.accounts }
func qualClockSource(clock *qualUnboundHeaderTime, accounts state.AccountsAdapter) HeaderTimeSource {
	return &qualHeaderTimeSource{clock, accounts}
}
