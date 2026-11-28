package drwa

// EXPERIMENTAL family and phase values (Part A E.17.4; G3 model r3 rows T01 to
// T07 and T10). The approved documents fix no byte value for a family or a
// phase: the model says its names "are not wire constants". These values are
// construction inputs awaiting the owner's allocation; a phase name the
// architecture itself uses (Part A L1413-1418, L5466-5480) is kept as written.
// Family separation is in the storage namespace (model Q5, accepted).
//
// Not defined, hence refused: the plane and release/profile families (model
// T08, T09) and the emergency crossing-boundary case (C04), which the owner
// left out of code until the model's Q3, Q4 and Q6 are answered.
const (
	ConvergenceFamilyBootstrap    = "BOOTSTRAP_READINESS"
	ConvergenceFamilySetup        = "SETUP_LIFECYCLE"
	ConvergenceFamilyCEB          = "CEB_CURRENTIZATION"
	ConvergenceFamilyContinuation = "requalification continuation/cancellation"
	ConvergenceFamilyRecoveryCEB  = "RECOVERY_CEB"
	ConvergenceFamilyRebindFence  = "RECOVERY_REBIND_FENCE"
	ConvergenceFamilyRoot         = "ROOT_SUCCESSION"
	ConvergenceFamilyRetirement   = "RETIREMENT"
)

type convergenceFamily struct {
	phases map[string]struct{}
	// entitlement: one predecessor outcome admits exactly one instance.
	entitlement bool
}

func convergencePhases(names ...string) map[string]struct{} {
	phases := make(map[string]struct{}, len(names))
	for _, name := range names {
		phases[name] = struct{}{}
	}
	return phases
}

var convergenceFamilies = map[string]*convergenceFamily{
	ConvergenceFamilyBootstrap: {phases: convergencePhases("TYPE_PROFILE_READINESS")},
	ConvergenceFamilySetup:     {phases: convergencePhases("SETUP_READY_ACK", "SETUP_SEALED", "DRWAQuiescenceAck")},
	ConvergenceFamilyCEB: {phases: convergencePhases("CLOSURE_ACK", "DRWAQuiescenceAck", "REQUALIFICATION_ADMIN",
		"ADMIN_QUIESCENCE_ACK", "PREPARED_ACK", "CURRENT_ACK", "continuation")},
	ConvergenceFamilyContinuation: {phases: convergencePhases("cancellation-fence", "CLOSURE_ACK", "DRWAQuiescenceAck",
		"CURRENT_ACK", "continuation"), entitlement: true},
	ConvergenceFamilyRecoveryCEB: {phases: convergencePhases("PREPARED_ACK", "CURRENT_ACK")},
	ConvergenceFamilyRebindFence: {phases: convergencePhases("FENCE_ACTIVATION_ACK", "FENCE_CLEAR_ACK")},
	ConvergenceFamilyRoot: {phases: convergencePhases("ROOT_FENCE_ACK", "ROOT_TARGET_READY_ACK", "ROOT_CURRENT_ACK",
		"ROOT_FENCE_CLEAR_ACK")},
	ConvergenceFamilyRetirement: {phases: convergencePhases("WIND_DOWN_PREPARATION", "WIND_DOWN_SEALED", "TERMINAL_ATTESTATION")},
}
