package node

import (
	"math/big"
	"testing"
)

func TestQualSP281COrdinarySupplyDisplay(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value *big.Int
		want  string
	}{
		{name: "absent", want: "0"},
		{name: "zero", value: big.NewInt(0), want: "0"},
		{name: "positive", value: big.NewInt(12345), want: "12345"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := bigToString(tc.value); got != tc.want {
				t.Fatalf("display = %q; want %q", got, tc.want)
			}
		})
	}
}
