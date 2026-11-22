package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Native journals, explicitly synthetic signed appointment/header inputs. These
// cases supply no native creating-owner, canonical genesis or funding admission.
func TestQualD20InitialPairExistingNestedBoundaryRefuses(t *testing.T) {
	f, g, args, proofs, bodies, approval := qualInitialPair(t)
	before, err := f.store.RootHash()
	require.NoError(t, err)
	err = f.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		return nil, qualInitialInstall(f, g, args, proofs, bodies, approval)
	})
	require.ErrorIs(t, err, ErrExecutionBusy)
	after, err := f.store.RootHash()
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.Zero(t, f.store.JournalLen())
	for _, w := range qualInitialWrites(t, f) {
		require.Empty(t, qualRegistryValue(t, f.store, string(w.key)))
	}
}

func TestQualD20RegistrationExistingNestedBoundaryRefuses(t *testing.T) {
	s, records, digest, id := qualRecordStore(t)
	r, owner := qualRegistrationOwner(t, s, 2)
	before, err := s.RootHash()
	require.NoError(t, err)
	called := false
	err = owner.executeOwned(func(*rollbackOperation) ([]*vmcommon.VMOutput, error) {
		return nil, r.registerTokenForIntent(records, id, digest, bytes.Repeat([]byte{0x22}, 32),
			func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
				called = true
				return qualRegistrationCreator(t, "TOKEN-abcdef")(accounts)
			})
	})
	require.ErrorIs(t, err, ErrExecutionBusy)
	require.False(t, called)
	after, err := s.RootHash()
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.Zero(t, s.JournalLen())
	_, body, _, _ := qualRecordBody()
	require.Equal(t, qualRecordFrame(body, []byte("OPEN"), nil), qualRegistryValue(t, s, registrationIntentPrefix+string(id)))
	require.Empty(t, qualRegistryValue(t, s, registrationAssociationPrefix+"TOKEN-abcdef"))
	require.Empty(t, qualRegistryValue(t, s, registrationActivationPrefix+"TOKEN-abcdef"))
}

func TestQualD20OwnedInitialPairSingleJournal(t *testing.T) {
	f, g, args, proofs, bodies, approval := qualInitialPair(t)
	writes := qualInitialWrites(t, f) // hand-framed, independent of the installer
	before := qualRegistryValue(t, f.store, scopedAdmissionPrefix+"budget")
	var retained *rollbackOperation
	install := func(operation *rollbackOperation) error {
		return f.records.installInitialPurposePairOwned(operation, f.context, f.d.owner, g, args, proofs, bodies, approval,
			[]byte("admission\x00opaque"), []byte("independent\xc3\xa9"))
	}
	require.NoError(t, f.boundary.executeOwned(func(operation *rollbackOperation) ([]*vmcommon.VMOutput, error) {
		retained = operation
		return nil, install(operation)
	}))
	require.Equal(t, 2, f.mandates.calls)
	var delta uint64
	for _, w := range writes {
		delta += uint64(len(w.key) + len(w.value))
		require.Equal(t, w.value, qualRegistryValue(t, f.store, string(w.key)))
	}
	budget := qualRegistryValue(t, f.store, scopedAdmissionPrefix+"budget")
	require.Equal(t, binary.BigEndian.Uint64(before)+4, binary.BigEndian.Uint64(budget))
	require.Equal(t, binary.BigEndian.Uint64(before[8:])+delta, binary.BigEndian.Uint64(budget[8:]))
	require.Equal(t, uint64(10), binary.BigEndian.Uint64(budget[16:]))
	require.Equal(t, uint64(6), binary.BigEndian.Uint64(budget[24:]))
	root, err := f.store.RootHash()
	require.NoError(t, err)
	journal := f.store.JournalLen()
	require.NoError(t, f.boundary.executeOwned(func(operation *rollbackOperation) ([]*vmcommon.VMOutput, error) {
		require.ErrorIs(t, install(retained), ErrExecutionClosed)
		return nil, install(operation)
	}))
	require.Equal(t, 4, f.mandates.calls) // duplicate still authenticates both roles
	after, err := f.store.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
	require.Equal(t, journal, f.store.JournalLen())
	require.Equal(t, budget, qualRegistryValue(t, f.store, scopedAdmissionPrefix+"budget"))
	roots, outputs, err := f.boundary.Commit()
	require.NoError(t, err)
	require.Empty(t, outputs)
	require.NoError(t, f.store.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
	for _, w := range writes {
		require.Equal(t, w.value, qualRegistryValue(t, f.store, string(w.key)))
	}
	require.ErrorIs(t, install(retained), ErrExecutionClosed)
}

func TestQualD20OwnedInitialPairFailureContainment(t *testing.T) {
	for _, failure := range []string{"outer", "save", "header", "rollback"} {
		t.Run(failure, func(t *testing.T) {
			f, g, args, proofs, bodies, approval := qualInitialPair(t)
			before, err := f.store.RootHash()
			require.NoError(t, err)
			original := errors.New("synthetic native save/outer failure")
			rollback := errors.New("synthetic native rollback failure")
			if failure == "save" || failure == "rollback" {
				f.store.saveErr = original
			}
			if failure == "rollback" {
				f.store.revertErr = rollback
			}
			if failure == "header" {
				f.mandates.hook = func() { f.clock.Reset() }
			}
			var local error
			err = f.boundary.executeOwned(func(operation *rollbackOperation) ([]*vmcommon.VMOutput, error) {
				local = f.records.installInitialPurposePairOwned(operation, f.context, f.d.owner, g, args, proofs, bodies, approval,
					[]byte("admission\x00opaque"), []byte("independent\xc3\xa9"))
				if failure == "outer" {
					require.NoError(t, local)
					return []*vmcommon.VMOutput{{ReturnData: [][]byte{[]byte("unpublished")}}}, original
				}
				require.Error(t, local)
				return []*vmcommon.VMOutput{{ReturnData: [][]byte{[]byte("unpublished")}}}, nil // swallowed local failure must not commit
			})
			require.Error(t, err)
			if failure != "header" {
				require.ErrorIs(t, err, original)
			} else {
				require.ErrorIs(t, err, local)
			}
			if failure == "rollback" {
				require.ErrorIs(t, err, rollback)
				_, outputs, commitErr := f.boundary.Commit()
				require.ErrorIs(t, commitErr, original)
				require.ErrorIs(t, commitErr, rollback)
				require.Empty(t, outputs)
				require.NoError(t, f.boundary.Recover())
			}
			after, err := f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Zero(t, f.store.JournalLen())
			for _, w := range qualInitialWrites(t, f) {
				require.Empty(t, qualRegistryValue(t, f.store, string(w.key)))
			}
		})
	}
}

func TestQualD20OwnedWriteBindingAndLifetime(t *testing.T) {
	for _, refusal := range []string{"nil", "foreign-owner", "foreign-store", "nil-store", "nil-writer"} {
		t.Run(refusal, func(t *testing.T) {
			f, _, _, _, _, _ := qualInitialPair(t)
			other := qualRegistrationStore(t, 0)
			foreign, err := NewRollbackContainment(other)
			require.NoError(t, err)
			calls := 0
			err = f.boundary.executeOwned(func(operation *rollbackOperation) ([]*vmcommon.VMOutput, error) {
				write := func() error { calls++; return nil }
				var local error
				switch refusal {
				case "nil":
					local = (*rollbackOperation)(nil).withWrite(f.boundary, f.store, write)
				case "foreign-owner":
					local = operation.withWrite(foreign, other, write)
				case "foreign-store":
					local = operation.withWrite(f.boundary, other, write)
				case "nil-store":
					local = operation.withWrite(f.boundary, nil, write)
				case "nil-writer":
					local = operation.withWrite(f.boundary, f.store, nil)
				}
				require.Error(t, local)
				return nil, local
			})
			require.Error(t, err)
			require.Zero(t, calls)
			require.Zero(t, f.store.JournalLen())
			require.Zero(t, other.JournalLen())
		})
	}
	var owner *RollbackContainment
	require.ErrorIs(t, owner.executeOwned(nil), ErrExecutionClosed)
	f, _, _, _, _, _ := qualInitialPair(t)
	require.ErrorIs(t, f.boundary.executeOwned(nil), ErrInvalidOperation)
}

func TestQualD20OwnedWriteConcurrentAndReentrantRefusal(t *testing.T) {
	for _, concurrent := range []bool{false, true} {
		t.Run(map[bool]string{false: "reentrant", true: "concurrent"}[concurrent], func(t *testing.T) {
			f, _, _, _, _, _ := qualInitialPair(t)
			before, err := f.store.RootHash()
			require.NoError(t, err)
			key := []byte("synthetic-D20-uncommitted-marker")
			calls := 0
			err = f.boundary.executeOwned(func(operation *rollbackOperation) ([]*vmcommon.VMOutput, error) {
				require.NoError(t, operation.withWrite(f.boundary, f.store, func() error {
					qualRecordPut(t, f.store, key, []byte("must rollback"))
					attempt := func() error { return operation.withWrite(f.boundary, f.store, func() error { calls++; return nil }) }
					if concurrent {
						result := make(chan error, 1)
						go func() { result <- attempt() }()
						require.ErrorIs(t, <-result, ErrExecutionBusy)
					} else {
						require.ErrorIs(t, attempt(), ErrExecutionBusy)
					}
					return nil
				}))
				require.ErrorIs(t, operation.withWrite(f.boundary, f.store, func() error { calls++; return nil }), ErrExecutionBusy)
				return nil, nil
			})
			require.ErrorIs(t, err, ErrExecutionBusy)
			require.Zero(t, calls)
			after, err := f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Empty(t, qualRegistryValue(t, f.store, string(key)))
			require.Zero(t, f.store.JournalLen())
		})
	}
}

func TestQualD20OwnedWriteStickyErrorAndPanic(t *testing.T) {
	for _, panicCase := range []bool{false, true} {
		t.Run(map[bool]string{false: "swallowed-error", true: "panic"}[panicCase], func(t *testing.T) {
			f, _, _, _, _, _ := qualInitialPair(t)
			before, err := f.store.RootHash()
			require.NoError(t, err)
			original := errors.New("synthetic closed-writer failure")
			var retained *rollbackOperation
			calls := 0
			execute := func() {
				err = f.boundary.executeOwned(func(operation *rollbackOperation) ([]*vmcommon.VMOutput, error) {
					retained = operation
					local := operation.withWrite(f.boundary, f.store, func() error {
						qualRecordPut(t, f.store, []byte("synthetic-D20-transient"), []byte("must rollback"))
						if panicCase {
							panic(original)
						}
						return original
					})
					require.ErrorIs(t, local, original)
					require.ErrorIs(t, operation.withWrite(f.boundary, f.store, func() error { calls++; return nil }), original)
					return nil, nil
				})
			}
			if panicCase {
				require.PanicsWithValue(t, original, execute)
				_, outputs, commitErr := f.boundary.Commit()
				require.ErrorIs(t, commitErr, ErrExecutionInterrupted)
				require.Empty(t, outputs)
				require.NoError(t, f.boundary.Recover())
			} else {
				execute()
				require.ErrorIs(t, err, original)
			}
			require.ErrorIs(t, retained.withWrite(f.boundary, f.store, func() error { calls++; return nil }), ErrExecutionClosed)
			require.Zero(t, calls)
			after, err := f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Zero(t, f.store.JournalLen())
		})
	}
}

func TestQualD20OwnedInitialPairMalformedCannotBeSwallowed(t *testing.T) {
	f, g, args, proofs, bodies, approval := qualInitialPair(t)
	var absent *scopedAdmissionRecords
	require.ErrorIs(t, absent.installInitialPurposePairOwned(nil, f.context, f.d.owner, g, args, proofs, bodies, approval, nil, nil), errScopedAdmission)
	err := f.boundary.executeOwned(func(operation *rollbackOperation) ([]*vmcommon.VMOutput, error) {
		err := f.records.installInitialPurposePairOwned(operation, f.context, f.d.owner, g, nil, proofs, bodies, approval, []byte("admission\x00opaque"), []byte("independent\xc3\xa9"))
		require.ErrorIs(t, err, errScopedAdmission)
		return nil, nil
	})
	require.ErrorIs(t, err, errScopedAdmission)
	require.Zero(t, f.store.JournalLen())
	for _, w := range qualInitialWrites(t, f) {
		require.Empty(t, qualRegistryValue(t, f.store, string(w.key)))
	}
}

func TestQualD20OwnedWritePreservesOriginalError(t *testing.T) {
	for _, returnsSame := range []bool{false, true} {
		t.Run(map[bool]string{false: "swallowed", true: "returned"}[returnsSame], func(t *testing.T) {
			f, _, _, _, _, _ := qualInitialPair(t)
			original := errors.New("synthetic single native error")
			err := f.boundary.executeOwned(func(operation *rollbackOperation) ([]*vmcommon.VMOutput, error) {
				local := operation.withWrite(f.boundary, f.store, func() error { return original })
				require.Same(t, original, local)
				if returnsSame {
					return nil, local
				}
				return nil, nil
			})
			// Native successful rollback preserves the original error object;
			// containment adds diagnostics only when there is another failure.
			require.Same(t, original, err)
			require.Zero(t, f.store.JournalLen())
		})
	}
}

func TestQualD20OwnedWritePreservesDistinctErrors(t *testing.T) {
	for _, wrapped := range []bool{false, true} {
		t.Run(map[bool]string{false: "distinct", true: "wrapped"}[wrapped], func(t *testing.T) {
			f, _, _, _, _, _ := qualInitialPair(t)
			writer := errors.New("synthetic writer failure")
			outer := errors.New("distinct native operation failure")
			var original error = outer
			if wrapped {
				original = fmt.Errorf("native outer context: %w", writer)
			}
			err := f.boundary.executeOwned(func(operation *rollbackOperation) ([]*vmcommon.VMOutput, error) {
				require.Same(t, writer, operation.withWrite(f.boundary, f.store, func() error { return writer }))
				return nil, original
			})
			require.ErrorIs(t, err, writer)
			if wrapped {
				require.Same(t, original, err)
			} else {
				require.ErrorIs(t, err, outer)
			}
			require.Zero(t, f.store.JournalLen())
		})
	}
}

// These are closed-writer construction cases using the existing explicitly
// synthetic OPEN intent and native account creator. They are not authenticated
// endpoint, authority-body, finality, fee or funding qualification.
func TestQualD20OwnedRegistrationSingleJournal(t *testing.T) {
	s, records, digest, id := qualRecordStore(t)
	r, owner := qualRegistrationOwner(t, s, 2)
	manager := bytes.Repeat([]byte{0x22}, 32)
	token := []byte("TOKEN-abcdef")
	var retained *rollbackOperation
	err := owner.executeOwned(func(operation *rollbackOperation) ([]*vmcommon.VMOutput, error) {
		retained = operation
		output, err := r.registerTokenForIntentOwned(operation, records, id, digest, manager, qualRegistrationCreator(t, string(token)))
		return []*vmcommon.VMOutput{output}, err
	})
	require.NoError(t, err)
	_, body, _, _ := qualRecordBody()
	require.Equal(t, qualRecordFrame(token, id, digest, body, manager), qualRegistryValue(t, s, registrationAssociationPrefix+string(token)))
	require.Equal(t, qualRecordFrame(token, id, []byte("BootstrapDeny")), qualRegistryValue(t, s, registrationActivationPrefix+string(token)))
	require.Equal(t, qualRecordFrame(body, []byte("CONSUMED"), token), qualRegistryValue(t, s, registrationIntentPrefix+string(id)))
	require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 1}, qualRegistryValue(t, s, registryCountKey))
	require.Equal(t, []byte{1}, qualRegistryValue(t, s, registryMemberKeyPrefix+string(token)))
	before, err := s.RootHash()
	require.NoError(t, err)
	called := false
	creator := func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) { called = true; return nil, nil, nil }
	err = owner.executeOwned(func(operation *rollbackOperation) ([]*vmcommon.VMOutput, error) {
		output, err := r.registerTokenForIntentOwned(operation, records, id, digest, manager, creator)
		require.Error(t, err)
		require.Nil(t, output)
		return nil, nil // a consumed intent cannot be admitted by swallowing error
	})
	require.ErrorIs(t, err, errInvalidRegistrationRecord)
	require.False(t, called)
	after, err := s.RootHash()
	require.NoError(t, err)
	require.Equal(t, before, after)
	output, err := r.registerTokenForIntentOwned(retained, records, id, digest, manager, creator)
	require.ErrorIs(t, err, ErrExecutionClosed)
	require.Nil(t, output)
	require.False(t, called)
	roots, outputs, err := owner.Commit()
	require.NoError(t, err)
	require.Len(t, outputs, 1)
	require.Equal(t, vmcommon.Ok, outputs[0].ReturnCode)
	require.Equal(t, [][]byte{token}, outputs[0].ReturnData)
	require.NoError(t, s.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
	require.Equal(t, qualRecordFrame(token, id, digest, body, manager), qualRegistryValue(t, s, registrationAssociationPrefix+string(token)))
}

func TestQualD20OwnedRegistrationFailureContainment(t *testing.T) {
	for _, fault := range []string{"creator", "guard", "save", "count-tamper", "consume", "rollback", "nested-owned"} {
		t.Run(fault, func(t *testing.T) {
			s, records, digest, id := qualRecordStore(t)
			r, owner := qualRegistrationOwner(t, s, 2)
			manager := bytes.Repeat([]byte{0x22}, 32)
			before, err := s.RootHash()
			require.NoError(t, err)
			original, rollback := errors.New("synthetic registration native failure"), errors.New("synthetic registration rollback failure")
			if fault == "save" || fault == "rollback" {
				s.saveErr = original
			}
			if fault == "rollback" {
				s.revertErr = rollback
			}
			if fault == "consume" {
				records.retain = func(account state.UserAccountHandler, writes ...scopedAdmissionWrite) error {
					if err := account.SaveKeyValue(writes[0].key, writes[0].value); err != nil {
						return err
					}
					if err := s.SaveAccount(account); err != nil {
						return err
					}
					return original
				}
			}
			guard := func(stores []state.AccountsAdapter, execute func() (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
				require.Len(t, stores, 1)
				require.Same(t, s, stores[0])
				output, err := execute()
				if err == nil && fault == "guard" {
					return nil, original
				}
				return output, err
			}
			nestedCalled := false
			err = owner.executeOwned(func(operation *rollbackOperation) ([]*vmcommon.VMOutput, error) {
				creator := func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
					token, output, err := qualRegistrationCreator(t, "TOKEN-abcdef")(accounts)
					if err != nil {
						return nil, nil, err
					}
					if fault == "creator" {
						return nil, nil, original
					}
					if fault == "count-tamper" {
						qualRecordPut(t, s, []byte(registryCountKey), []byte{0, 0, 0, 0, 0, 0, 0, 2})
					}
					if fault == "nested-owned" {
						inner, err := r.registerTokenForIntentOwned(operation, records, id, digest, manager,
							func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
								nestedCalled = true
								return nil, nil, nil
							})
						require.ErrorIs(t, err, ErrExecutionBusy)
						require.Nil(t, inner)
					}
					return token, output, nil
				}
				output, local := r.registerTokenForIntentOwned(operation, records, id, digest, manager, creator, guard)
				if fault != "nested-owned" {
					require.Error(t, local)
					require.Nil(t, output)
				}
				return []*vmcommon.VMOutput{{ReturnCode: vmcommon.Ok, ReturnData: [][]byte{[]byte("never publish")}}}, nil
			})
			switch fault {
			case "count-tamper":
				require.ErrorIs(t, err, ErrInvalidRegistryRegistration)
			case "nested-owned":
				require.ErrorIs(t, err, ErrExecutionBusy)
			default:
				require.ErrorIs(t, err, original)
			}
			require.False(t, nestedCalled)
			if fault == "rollback" {
				require.ErrorIs(t, err, rollback)
				_, outputs, err := owner.Commit()
				require.ErrorIs(t, err, original)
				require.ErrorIs(t, err, rollback)
				require.Empty(t, outputs)
				require.NoError(t, owner.Recover())
			}
			after, err := s.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Zero(t, s.JournalLen())
			_, body, _, _ := qualRecordBody()
			require.Equal(t, qualRecordFrame(body, []byte("OPEN"), nil), qualRegistryValue(t, s, registrationIntentPrefix+string(id)))
			require.Empty(t, qualRegistryValue(t, s, registrationAssociationPrefix+"TOKEN-abcdef"))
			require.Empty(t, qualRegistryValue(t, s, registrationActivationPrefix+"TOKEN-abcdef"))
			require.Empty(t, qualRegistryValue(t, s, registryMemberKeyPrefix+"TOKEN-abcdef"))
			require.Equal(t, make([]byte, 8), qualRegistryValue(t, s, registryCountKey))
			if fault != "rollback" {
				_, outputs, err := owner.Commit()
				require.NoError(t, err)
				require.Empty(t, outputs)
			}
		})
	}
}

func TestQualD20OwnedRegistrationLateOuterFailure(t *testing.T) {
	s, records, digest, id := qualRecordStore(t)
	r, owner := qualRegistrationOwner(t, s, 2)
	before, err := s.RootHash()
	require.NoError(t, err)
	late := errors.New("synthetic later original native effect failure")
	err = owner.executeOwned(func(operation *rollbackOperation) ([]*vmcommon.VMOutput, error) {
		output, err := r.registerTokenForIntentOwned(operation, records, id, digest, bytes.Repeat([]byte{0x22}, 32), qualRegistrationCreator(t, "TOKEN-abcdef"))
		require.NoError(t, err)
		return []*vmcommon.VMOutput{output}, late
	})
	require.Same(t, late, err)
	after, err := s.RootHash()
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.Zero(t, s.JournalLen())
	_, outputs, err := owner.Commit()
	require.NoError(t, err)
	require.Empty(t, outputs)
}

func TestQualD20OwnedRegistrationInputBindings(t *testing.T) {
	for _, fault := range []string{"nil-scope", "nil-records", "foreign-records", "nil-creator", "extra-guard", "equal-root-foreign-owner"} {
		t.Run(fault, func(t *testing.T) {
			s, records, digest, id := qualRecordStore(t)
			r, owner := qualRegistrationOwner(t, s, 2)
			before, err := s.RootHash()
			require.NoError(t, err)
			selected := r
			if fault == "foreign-records" {
				other, foreign, _, _ := qualRecordStore(t)
				root, err := other.RootHash()
				require.NoError(t, err)
				require.Equal(t, before, root)
				records = foreign
			}
			if fault == "equal-root-foreign-owner" {
				foreign, err := NewRollbackContainment(s)
				require.NoError(t, err)
				copy := *r
				copy.boundary = foreign // ONLY ownership changes: same accounts and root
				selected = &copy
			}
			if fault == "nil-records" {
				records = nil
			}
			called := false
			creator := func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
				called = true
				return qualRegistrationCreator(t, "TOKEN-abcdef")(accounts)
			}
			if fault == "nil-creator" {
				creator = nil
			}
			var guards []registrationGuard
			if fault == "extra-guard" {
				guards = []registrationGuard{nil, nil}
			}
			err = owner.executeOwned(func(operation *rollbackOperation) ([]*vmcommon.VMOutput, error) {
				if fault == "nil-scope" {
					operation = nil
				}
				output, err := selected.registerTokenForIntentOwned(operation, records, id, digest, bytes.Repeat([]byte{0x22}, 32), creator, guards...)
				require.Error(t, err)
				require.Nil(t, output)
				return nil, err
			})
			require.Error(t, err)
			require.False(t, called)
			after, err := s.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Zero(t, s.JournalLen())
		})
	}
}

// The second native account store participates in the SAME original owner.
// Synthetic OPEN/creator inputs here establish no positive ingress authority.
func TestQualD20OwnedRegistrationParticipatingStores(t *testing.T) {
	for _, outcome := range []string{"success", "late-native", "peer-rollback"} {
		t.Run(outcome, func(t *testing.T) {
			s, records, digest, id := qualRecordStore(t)
			peer := qualRegistrationStore(t, 0)
			r, _ := qualRegistrationOwner(t, s, 2)
			owner, err := NewRollbackContainment(s, peer)
			require.NoError(t, err)
			r.boundary = owner
			beforeUser, err := s.RootHash()
			require.NoError(t, err)
			beforePeer, err := peer.RootHash()
			require.NoError(t, err)
			late := errors.New("synthetic second-store native effect failure")
			rollback := errors.New("synthetic second-store rollback failure")
			if outcome == "peer-rollback" {
				peer.revertErr = rollback
			}
			marker := "synthetic-D20-peer-effect"
			manager := bytes.Repeat([]byte{0x22}, 32)
			token := []byte("TOKEN-abcdef")
			err = owner.executeOwned(func(operation *rollbackOperation) ([]*vmcommon.VMOutput, error) {
				output, err := r.registerTokenForIntentOwned(operation, records, id, digest, manager, qualRegistrationCreator(t, string(token)))
				if err != nil {
					return nil, err
				}
				// An ordinary participating native effect follows the closed DRWA writer.
				qualRecordPut(t, peer, []byte(marker), []byte("original native peer effect"))
				if outcome != "success" {
					return []*vmcommon.VMOutput{output}, late
				}
				return []*vmcommon.VMOutput{output}, nil
			})
			if outcome == "success" {
				require.NoError(t, err)
				roots, outputs, err := owner.Commit()
				require.NoError(t, err)
				require.Len(t, roots, 2)
				require.Len(t, outputs, 1)
				require.Equal(t, [][]byte{token}, outputs[0].ReturnData)
				require.NoError(t, s.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
				require.NoError(t, peer.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[1])))
				_, body, _, _ := qualRecordBody()
				require.Equal(t, qualRecordFrame(token, id, digest, body, manager), qualRegistryValue(t, s, registrationAssociationPrefix+string(token)))
				require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 1}, qualRegistryValue(t, s, registryCountKey))
				require.Equal(t, []byte("original native peer effect"), qualRegistryValue(t, peer, marker))
				return
			}
			require.ErrorIs(t, err, late)
			if outcome == "peer-rollback" {
				require.ErrorIs(t, err, rollback)
				_, outputs, commitErr := owner.Commit()
				require.ErrorIs(t, commitErr, late)
				require.ErrorIs(t, commitErr, rollback)
				require.Empty(t, outputs)
				require.NoError(t, owner.Recover())
			} else {
				_, outputs, commitErr := owner.Commit()
				require.NoError(t, commitErr)
				require.Empty(t, outputs)
			}
			afterUser, err := s.RootHash()
			require.NoError(t, err)
			afterPeer, err := peer.RootHash()
			require.NoError(t, err)
			require.Equal(t, beforeUser, afterUser)
			require.Equal(t, beforePeer, afterPeer)
			require.Zero(t, s.JournalLen())
			require.Zero(t, peer.JournalLen())
			require.Empty(t, qualRegistryValue(t, peer, marker))
			require.Empty(t, qualRegistryValue(t, s, registrationAssociationPrefix+string(token)))
			require.Empty(t, qualRegistryValue(t, s, registryMemberKeyPrefix+string(token)))
			require.Equal(t, make([]byte, 8), qualRegistryValue(t, s, registryCountKey))
			_, body, _, _ := qualRecordBody()
			require.Equal(t, qualRecordFrame(body, []byte("OPEN"), nil), qualRegistryValue(t, s, registrationIntentPrefix+string(id)))
		})
	}
}
