package drwa

import "testing"

// Native update subset; regulated metadata restrictions remain SP2-25/68/40.
func TestQualTransitionR11UpdateNative(t *testing.T) { qualTransitionMetadataNative(t, "update") }
