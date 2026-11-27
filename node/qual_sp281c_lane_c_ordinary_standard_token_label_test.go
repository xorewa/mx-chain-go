package node

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
)

func TestQualSP281COrdinaryStandardTokenLabel(t *testing.T) {
	for _, label := range []string{core.NonFungibleESDTv2, core.SemiFungibleESDT} {
		t.Run(label, func(t *testing.T) {
			if !tokenTypeEquals([]byte(label), label) {
				t.Fatalf("identical ordinary report labels %q should compare equal", label)
			}
		})
	}
}
