package groups

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
)

func TestQualSP281COrdinaryStandardTokenLabel(t *testing.T) {
	// The ordinary legacy report has no explicit non-fungible display label.
	if got := getTokenType(uint32(core.NonFungible), 1); got != "" {
		t.Fatalf("legacy report label: got %q, want empty", got)
	}
}
