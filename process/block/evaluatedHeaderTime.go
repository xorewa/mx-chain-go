package block

import "github.com/multiversx/mx-chain-core-go/data"

// Bind the native proposal owner's existing installation position and lifetime.
// Upstream hooks/stubs without the optional adapter retain their exact installer;
// they cannot furnish a DRWA HeaderTimeSource merely by using this fallback.
func beginEvaluatedHeaderTime(hook interface {
	SetCurrentHeader(data.HeaderHandler) error
}) (
	func(data.HeaderHandler) error, func(), error) {
	if owner, exists := hook.(interface {
		BeginDRWAHeaderEvaluation() (func(data.HeaderHandler) error, func(), error)
	}); exists {
		return owner.BeginDRWAHeaderEvaluation()
	}
	return hook.SetCurrentHeader, func() {}, nil
}
