package mock

// IntRandomizerStub -
type IntRandomizerStub struct {
	// IntnCalled returns the int the test wants. Tests that need to
	// exercise the entropy-error path use IntnCalledWithError instead.
	IntnCalled          func(n int) int
	IntnCalledWithError func(n int) (int, error)
}

// Intn -
//
// ISSUE-045: signature changed to (int, error) to match the
// IntRandomizer interface. Tests that don't care about the error
// continue to use the legacy `IntnCalled` field — the stub returns
// (val, nil). Tests exercising entropy failures should set
// `IntnCalledWithError` instead.
func (irs *IntRandomizerStub) Intn(n int) (int, error) {
	if irs.IntnCalledWithError != nil {
		return irs.IntnCalledWithError(n)
	}
	if irs.IntnCalled != nil {
		return irs.IntnCalled(n), nil
	}

	return 0, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (irs *IntRandomizerStub) IsInterfaceNil() bool {
	return irs == nil
}
