package config

import "testing"

// A valid startup declaration has room for every required member and two
// distinct role names. Copies must preserve those values independently.
func TestQualDRWALaneBProgrammeLimits(t *testing.T) {
	valid := DRWAInitialProgrammeLimits{
		Files: 5, FileBytes: 64, AggregateBytes: 320, RecordBytes: 64,
		FieldBytes: 16, RoleBytes: 8, Members: 5, Records: 5,
		RetainedBytes: 320, NewRecordsPerEpoch: 5,
		AdmissionRole: []byte("admit"), IndependentRole: []byte("review"),
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid limits: %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*DRWAInitialProgrammeLimits)
	}{
		{"zero files", func(l *DRWAInitialProgrammeLimits) { l.Files = 0 }},
		{"aggregate below file", func(l *DRWAInitialProgrammeLimits) { l.AggregateBytes = l.FileBytes - 1 }},
		{"record below file", func(l *DRWAInitialProgrammeLimits) { l.RecordBytes = l.FileBytes - 1 }},
		{"members below minimum", func(l *DRWAInitialProgrammeLimits) { l.Members = 4 }},
		{"missing admission role", func(l *DRWAInitialProgrammeLimits) { l.AdmissionRole = nil }},
		{"overlong independent role", func(l *DRWAInitialProgrammeLimits) { l.IndependentRole = []byte("too-long-role") }},
		{"same roles", func(l *DRWAInitialProgrammeLimits) { l.IndependentRole = []byte("admit") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limits := valid.Clone()
			tc.edit(limits)
			if err := limits.Validate(); err == nil {
				t.Fatal("expected invalid limits to be refused")
			}
		})
	}
	var missing *DRWAInitialProgrammeLimits
	if missing.Clone() != nil || missing.Validate() == nil {
		t.Fatal("missing limits must remain absent and fail validation")
	}
	startup := &DRWAInitialProgrammeStartup{Limits: valid}
	copied := startup.Clone()
	copied.Limits.AdmissionRole[0] = 'X'
	copied.Limits.IndependentRole[0] = 'Y'
	if string(valid.AdmissionRole) != "admit" || string(valid.IndependentRole) != "review" {
		t.Fatal("startup clone changed the original role declarations")
	}
	var absent *DRWAInitialProgrammeStartup
	if absent.Clone() != nil {
		t.Fatal("cloning absent startup must preserve absence")
	}
}
