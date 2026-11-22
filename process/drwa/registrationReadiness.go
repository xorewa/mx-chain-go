package drwa

// RegistrationStateAck is untrusted E10 transport (Part A L2349-2373), not
// readiness. GlobalState must be a positively present canonical native record;
// native IsBurnForAll's false result on a missing record is insufficient.
type RegistrationStateAck struct {
	Shard                                 uint32
	GlobalState, AdminState, Dependencies []byte
	Proof                                 []byte
}

// RegistrationAckVerifier authenticates the exact candidate preimage against
// canonical shard result/state evidence. It must prove the native global state
// has the expected token type, admin/profile/dependencies and permanent member,
// not merely a local receipt, matching hash, source message or supplied boolean.
// Expected is DRWA-defined experimental Batch framing, not an allocated wire
// format. G3/P13 bootstrap/ACK admission remains required. No default verifier.
type RegistrationAckVerifier interface {
	VerifyRegistrationAck(shard uint32, expected, proof []byte) error
	IsInterfaceNil() bool
}
