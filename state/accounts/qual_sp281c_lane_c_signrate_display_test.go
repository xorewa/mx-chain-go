package accounts

import "testing"

func TestQualSP281COrdinarySignRateDisplay(t *testing.T) {
	dto := &SignRate{NumSuccess: 7, NumFailure: 11}
	if got, want := dto.String(), "&SignRate{NumSuccess:7,NumFailure:11,}"; got != want {
		t.Fatalf("String: got %q, want %q", got, want)
	}
	if got, want := dto.GoString(), "&accounts.SignRate{NumSuccess: 0x7,\nNumFailure: 0xb,\n}"; got != want {
		t.Fatalf("GoString: got %q, want %q", got, want)
	}
	var absent *SignRate
	if got := absent.String(); got != "nil" {
		t.Fatalf("nil String: got %q", got)
	}
	if got := absent.GoString(); got != "nil" {
		t.Fatalf("nil GoString: got %q", got)
	}
}
