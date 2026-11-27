package heartbeat

import "testing"

func TestQualSP214LaneDHeartbeatLabel(t *testing.T) {
	var holder heartBeatComponents
	if got := holder.String(); got != "heartBeat" {
		t.Fatalf("unexpected heartbeat component label: %q", got)
	}
}
