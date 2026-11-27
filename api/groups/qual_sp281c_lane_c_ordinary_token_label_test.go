package groups

import (
	"github.com/multiversx/mx-chain-core-go/core"
	"testing"
)

func TestQualSP281COrdinaryTokenLabel(t *testing.T) {
	if got := getTokenType(uint32(core.Fungible), 0); got != "FungibleESDT" {
		t.Fatalf("ordinary display label: got %q", got)
	}
}
