package accounts

import (
	"strings"
	"testing"
)

func TestQualSP281COrdinaryPeerDTODisplay(t *testing.T) {
	dto := &PeerAccountData{Nonce: 17}
	if got := dto.String(); !strings.HasPrefix(got, "&PeerAccountData{") || !strings.Contains(got, "Nonce:17,") || !strings.HasSuffix(got, "}") {
		t.Fatal("unexpected scalar DTO String display")
	}
	if got := dto.GoString(); !strings.HasPrefix(got, "&accounts.PeerAccountData{") || !strings.Contains(got, "Nonce: 0x11,\n") || !strings.HasSuffix(got, "}") {
		t.Fatal("unexpected scalar DTO GoString display")
	}
	var absent *PeerAccountData
	if absent.String() != "nil" || absent.GoString() != "nil" {
		t.Fatal("unexpected absent DTO display")
	}
}
