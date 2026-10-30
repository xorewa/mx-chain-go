package drwa

import "testing"

// Native royalties only; regulated frozen policy remains SP2-25/68/40.
func TestQualTransitionR12RoyaltiesNative(t *testing.T) { qualTransitionMetadataNative(t, "royalties") }
