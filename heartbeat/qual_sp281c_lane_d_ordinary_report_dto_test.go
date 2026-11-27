package heartbeat

import (
	"strings"
	"testing"
)

func TestQualLaneDHeartbeatReportLabels(t *testing.T) {
	report := &HeartbeatV2{VersionNumber: "demo", NodeDisplayName: "label"}
	if got := report.GetVersionNumber(); got != "demo" {
		t.Errorf("version label = %q, want demo", got)
	}
	if got := report.GetNodeDisplayName(); got != "label" {
		t.Errorf("display label = %q, want label", got)
	}
	for _, part := range []string{"&HeartbeatV2{", "VersionNumber:demo,", "NodeDisplayName:label,"} {
		if got := report.String(); !strings.Contains(got, part) {
			t.Errorf("String() missing %q", part)
		}
	}
	for _, part := range []string{"&heartbeat.HeartbeatV2{", `VersionNumber: "demo",`, `NodeDisplayName: "label",`} {
		if got := report.GoString(); !strings.Contains(got, part) {
			t.Errorf("GoString() missing %q", part)
		}
	}
	if got := report.Size(); got != 13 {
		t.Errorf("Size() = %d, want 13", got)
	}
	if got := report.XXX_Size(); got != 13 {
		t.Errorf("XXX_Size() = %d, want 13", got)
	}
	empty := &HeartbeatV2{}
	if got := empty.Size(); got != 0 {
		t.Errorf("empty Size() = %d, want 0", got)
	}
	if got := empty.XXX_Size(); got != 0 {
		t.Errorf("empty XXX_Size() = %d, want 0", got)
	}
}

func TestQualLaneDAbsentHeartbeatReport(t *testing.T) {
	var report *HeartbeatV2
	if got := report.String(); got != "nil" {
		t.Errorf("String() = %q, want nil", got)
	}
	if got := report.GoString(); got != "nil" {
		t.Errorf("GoString() = %q, want nil", got)
	}
	if got := report.GetVersionNumber(); got != "" {
		t.Errorf("version label = %q, want empty", got)
	}
	if got := report.GetNodeDisplayName(); got != "" {
		t.Errorf("display label = %q, want empty", got)
	}
	if got := report.Size(); got != 0 {
		t.Errorf("Size() = %d, want 0", got)
	}
	if got := report.XXX_Size(); got != 0 {
		t.Errorf("XXX_Size() = %d, want 0", got)
	}
}

func TestQualLaneDHeartbeatNumericReport(t *testing.T) {
	report := &HeartbeatV2{Nonce: 17, NumTrieNodesSynced: 130}
	if got := report.GetNonce(); got != 17 {
		t.Errorf("nonce display = %d, want 17", got)
	}
	if got := report.GetNumTrieNodesSynced(); got != 130 {
		t.Errorf("count display = %d, want 130", got)
	}
	if got := report.Size(); got != 5 {
		t.Errorf("Size() = %d, want 5", got)
	}
	if got := report.XXX_Size(); got != 5 {
		t.Errorf("XXX_Size() = %d, want 5", got)
	}
	var absent *HeartbeatV2
	if got := absent.GetNonce(); got != 0 {
		t.Errorf("absent nonce display = %d, want 0", got)
	}
	if got := absent.GetNumTrieNodesSynced(); got != 0 {
		t.Errorf("absent count display = %d, want 0", got)
	}
}

func TestQualLaneDOpaqueHeartbeatReportLabel(t *testing.T) {
	report := &HeartbeatV2{Identity: "display"}
	if got := report.GetIdentity(); got != "display" {
		t.Errorf("opaque display label = %q, want display", got)
	}
	if got := report.Size(); got != 9 {
		t.Errorf("Size() = %d, want 9", got)
	}
	if got := report.XXX_Size(); got != 9 {
		t.Errorf("XXX_Size() = %d, want 9", got)
	}
	var absent *HeartbeatV2
	if got := absent.GetIdentity(); got != "" {
		t.Errorf("absent display label = %q, want empty", got)
	}
}
