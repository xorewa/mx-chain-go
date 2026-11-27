package node

import "testing"

func TestQualSP281COrdinaryTokenLabel(t *testing.T) {
	const label = "FungibleESDT"
	if !tokenTypeEquals([]byte(label), label) {
		t.Fatal("ordinary identical report labels should compare equal")
	}
}
