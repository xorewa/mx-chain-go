package drwa

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon/vmcommonMocks"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// R7 EXPERIMENTAL: reuse T44/T45/T46's domain, epoch, time, capacities and
// records. These accepting test adapters isolate native refusal predicates;
// they provide no signature, ingress, canonicality or authority evidence.
type qualFA01RegistrationAccept struct{ calls int }

func (v *qualFA01RegistrationAccept) IsInterfaceNil() bool { return v == nil }
func (v *qualFA01RegistrationAccept) VerifyRegistration(_ string, _, _, _, _, _ []byte, _ HeaderMilliseconds, _ uint32) error {
	v.calls++
	return nil
}

type qualFA01AckAccept struct{ calls int }

func (v *qualFA01AckAccept) IsInterfaceNil() bool                              { return v == nil }
func (v *qualFA01AckAccept) VerifyRegistrationAck(_ uint32, _, _ []byte) error { v.calls++; return nil }

type qualFA01CancellationAccept struct{ calls int }

func (v *qualFA01CancellationAccept) IsInterfaceNil() bool { return v == nil }
func (v *qualFA01CancellationAccept) VerifyBootstrapCancellation(_ string, _, _ []byte, _ HeaderMilliseconds, _ uint32) error {
	v.calls++
	return nil
}

func TestQualFA01RegistrationNativeExpiry(t *testing.T) {
	for _, retain := range []bool{false, true} {
		for _, expired := range []bool{false, true} {
			name := "register/at_expiry"
			if retain {
				name = "retain/at_expiry"
			}
			if expired {
				name += "/expired"
			}
			t.Run(name, func(t *testing.T) {
				f := qualRegistrationAdmission(t, core.FungibleESDT)
				accept := &qualFA01RegistrationAccept{}
				f.admit.verifier = accept
				require.Equal(t, HeaderMilliseconds(1), f.body.expiry)
				if expired {
					f.end()
					_, f.end = qualT42Install(t, f.hook, core.MetachainShardId, 2)
				}
				defer f.end()
				key := append([]byte(registrationIntentPrefix), f.owner.id...)
				if retain {
					qualRecordPut(t, f.store, key, nil)
					budgetKey := []byte(scopedAdmissionPrefix + "budget")
					budget := bytes.Clone(qualRegistryValue(t, f.store, string(budgetKey)))
					binary.BigEndian.PutUint64(budget, 1)
					binary.BigEndian.PutUint64(budget[8:], uint64(len(budgetKey)+32))
					qualRecordPut(t, f.store, budgetKey, budget)
				}
				before, err := f.store.RootHash()
				require.NoError(t, err)
				journal, outputs := f.store.JournalLen(), len(f.boundary.outputs)
				creatorCalls := 0
				if retain {
					err = f.admit.RetainBootstrapIntent(f.verify.body, []byte("explicit-step1-mandate"))
				} else {
					err = f.register(t, func(a state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
						creatorCalls++
						return qualRegistrationCreator(t, "TOKEN-abcdef")(a)
					})
				}
				if !expired {
					require.NoError(t, err)
					require.Positive(t, accept.calls)
					return
				}
				require.ErrorIs(t, err, errInvalidRegistrationRecord)
				require.Zero(t, accept.calls)
				require.Zero(t, creatorCalls)
				after, e := f.store.RootHash()
				require.NoError(t, e)
				require.Equal(t, before, after)
				require.Equal(t, journal, f.store.JournalLen())
				require.Len(t, f.boundary.outputs, outputs)
			})
		}
	}
}

func TestQualFA01RegistrationReadinessNativeBurnRefusal(t *testing.T) {
	for _, burn := range []bool{false, true} {
		name := "false"
		if burn {
			name = "true"
		}
		t.Run(name, func(t *testing.T) {
			f := qualRegistrationAdmission(t, core.FungibleESDT)
			defer f.end()
			require.NoError(t, f.register(t, qualRegistrationCreator(t, "TOKEN-abcdef")))
			acks, _ := qualRegistrationAcks(t, f)
			if burn {
				acks[1].GlobalState = []byte{4, 1}
			}
			accept := &qualFA01AckAccept{}
			called := 0
			before, err := f.store.RootHash()
			require.NoError(t, err)
			journal, outputs := f.store.JournalLen(), len(f.boundary.outputs)
			err = f.admit.WithBootstrapReadiness([]byte("TOKEN-abcdef"), acks, accept, func() (*vmcommon.VMOutput, error) { called++; return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil })
			if !burn {
				require.NoError(t, err)
				require.Equal(t, 1, called)
				require.Equal(t, 3, accept.calls)
				return
			}
			require.ErrorIs(t, err, errInvalidRegistrationRecord)
			require.Zero(t, called)
			after, e := f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, before, after)
			require.Equal(t, journal, f.store.JournalLen())
			require.Len(t, f.boundary.outputs, outputs)
		})
	}
}

func TestQualFA01CancellationNativeDomainAndRecheck(t *testing.T) {
	for _, fault := range []string{"healthy", "domain", "native-recheck"} {
		t.Run(fault, func(t *testing.T) {
			x := qualT46New(t, core.FungibleESDT)
			f := x.f
			defer f.end()
			accept := &qualFA01CancellationAccept{}
			x.c.verifier = accept
			if fault == "domain" {
				x.c.domain = []byte("other-network")
			}
			calls := 0
			x.nativeHook = func() {
				calls++
				if fault == "native-recheck" && calls == 2 {
					x.native = append(bytes.Clone(x.native), '!')
				}
			}
			before, e := f.store.RootHash()
			require.NoError(t, e)
			journal, outputs := f.store.JournalLen(), len(f.boundary.outputs)
			err := x.cancel(f.owner.id)
			if fault == "healthy" {
				require.NoError(t, err)
				require.Equal(t, 2, calls)
				require.Equal(t, 3, accept.calls)
				return
			}
			require.ErrorIs(t, err, errInvalidRegistrationRecord)
			if fault == "domain" {
				require.Zero(t, calls)
				require.Zero(t, accept.calls)
			} else {
				require.Equal(t, 2, calls)
				require.Equal(t, 3, accept.calls)
			}
			after, e := f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, before, after)
			require.Equal(t, journal, f.store.JournalLen())
			require.Len(t, f.boundary.outputs, outputs)
		})
	}
}

func TestQualFA01MaterializationNativeTypeRecheck(t *testing.T) {
	for _, fault := range []bool{false, true} {
		name := "healthy"
		if fault {
			name = "wrong-native-type"
		}
		t.Run(name, func(t *testing.T) {
			f := qualBurnFixtureFor(t, false, core.FungibleESDT, "", nil)
			f.args.EnableEpochsHandler.(vmcommon.EpochSubscriberHandler).EpochConfirmed(7, 0)
			qualBurnPrepare(t, f)
			if fault {
				// A qualification-only failed setter writes canonical metadata with an
				// unset type while reporting success. Keep the real native reader and
				// normalization so only the post-write type comparison can refuse it.
				f.b.tokenType = &vmcommonMocks.BuiltInFunctionExecutableStub{ProcessBuiltinFunctionCalled: func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
					account, err := f.b.material.state.systemAccount()
					if err != nil {
						return nil, err
					}
					key := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), f.id...)
					if err = account.SaveKeyValue(key, []byte{0, 0}); err != nil {
						return nil, err
					}
					if err = f.db.SaveAccount(account); err != nil {
						return nil, err
					}
					return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
				}}
			}
			before, e := f.db.RootHash()
			require.NoError(t, e)
			journal := f.db.JournalLen()
			err := f.b.MaterializeRegistration(f.id, f.w)
			if !fault {
				require.NoError(t, err)
				require.Equal(t, []byte{0, 1}, qualBurnValue(t, f.db, f.id))
				return
			}
			require.ErrorIs(t, err, errInvalidRegistrationRecord)
			after, e := f.db.RootHash()
			require.NoError(t, e)
			require.Equal(t, before, after)
			require.Equal(t, journal, f.db.JournalLen())
			require.Empty(t, qualBurnValue(t, f.db, f.id))
		})
	}
}
