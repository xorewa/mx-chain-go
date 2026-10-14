package drwa

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// R2/model09 development adversaries. Existing synthetic hosts and experimental
// fixtures are reused; native journals run, protocol provenance remains unproved.
func TestQualDRWAOwnedAuthenticationSourceGrant(t *testing.T) {
	for _, op := range []string{"install", "consume", "unused"} {
		for _, change := range []string{"manufacture", "erase", "other"} {
			t.Run(op+"/"+change, func(t *testing.T) {
				f := qualSourceGrantNew(t)
				if op != "install" || change == "erase" {
					f.install(t)
				}
				if op == "consume" && change == "erase" {
					require.NoError(t, f.consume())
				}
				if op == "unused" && change == "erase" {
					require.NoError(t, f.close("STALE_BINDING"))
				}
				before := qualRegistryValue(t, f.store, string(f.key))
				roots, _, err := f.owner.Commit()
				require.NoError(t, err)
				f.reopen(t, f.store)
				calls := f.host.effectCalls
				other := []byte("fixture/owned-auth/source")
				f.host.hooks["verify"] = func() {
					key, value := f.key, qualRecordFrame(f.body, []byte("OPEN"), nil, nil)
					if change == "erase" {
						value = nil
					}
					if change == "manufacture" && op == "consume" {
						value = qualRecordFrame(f.body, []byte("CONSUMED"), nil, f.host.effect)
					}
					if change == "manufacture" && op == "unused" {
						value = qualRecordFrame(f.body, []byte("CLOSED_UNUSED"), []byte("STALE_BINDING"), nil)
					}
					if change == "other" {
						key, value = other, []byte("preserved")
					}
					qualRecordPut(t, f.store, key, value)
				}
				if op == "install" {
					err = f.records.install(f.context, f.p, []byte("synthetic-canonical-proof"))
				} else if op == "consume" {
					err = f.consume()
				} else {
					err = f.close("STALE_BINDING")
				}
				if change == "other" {
					require.NoError(t, err)
					require.Equal(t, []byte("preserved"), qualRegistryValue(t, f.store, string(other)))
					return
				}
				require.ErrorIs(t, err, errSourceGrant)
				require.Equal(t, calls, f.host.effectCalls)
				require.Equal(t, before, qualRegistryValue(t, f.store, string(f.key)))
				after, e := f.store.RootHash()
				require.NoError(t, e)
				require.Equal(t, roots[0], after)
				_, outputs, e := f.owner.Commit()
				require.NoError(t, e)
				require.Empty(t, outputs)
			})
		}
	}
}

func TestQualDRWAOwnedAuthenticationConvergence(t *testing.T) {
	for _, op := range []string{"create", "ack", "complete"} {
		for _, stage := range []string{"transition", "ack"} {
			if stage == "ack" && op != "ack" {
				continue
			}
			for _, change := range []string{"manufacture", "erase", "other"} {
				t.Run(op+"/"+stage+"/"+change, func(t *testing.T) {
					f := qualConvergenceNew(t, 3)
					if op != "create" || change == "erase" {
						f.create(t)
					}
					if op == "complete" && change != "manufacture" {
						for _, shard := range f.tr.shards {
							require.NoError(t, f.ack(shard))
						}
					}
					before := qualRegistryValue(t, f.store, string(f.key))
					roots, _, err := f.owner.Commit()
					require.NoError(t, err)
					f.reopen(t, f.store)
					calls := f.host.completeCalls
					other := []byte("fixture/owned-auth/convergence")
					f.host.hooks[stage] = func() {
						key, value := f.key, []byte(nil)
						if change == "manufacture" {
							value, _ = f.expected("PENDING", 0, 1, 2)
						}
						if change == "other" {
							key, value = other, []byte("preserved")
						}
						qualRecordPut(t, f.store, key, value)
					}
					if op == "create" {
						err = f.records.create(f.tr)
					} else if op == "ack" {
						err = f.ack(0)
					} else {
						err = f.records.complete(f.tr)
					}
					if change == "other" {
						require.NoError(t, err)
						require.Equal(t, []byte("preserved"), qualRegistryValue(t, f.store, string(other)))
						return
					}
					require.ErrorIs(t, err, errConvergence)
					require.Equal(t, calls, f.host.completeCalls)
					require.Equal(t, before, qualRegistryValue(t, f.store, string(f.key)))
					after, e := f.store.RootHash()
					require.NoError(t, e)
					require.Equal(t, roots[0], after)
					_, outputs, e := f.owner.Commit()
					require.NoError(t, e)
					require.Empty(t, outputs)
				})
			}
		}
	}
}

func TestQualDRWAOwnedAuthenticationSourceTerminalReopen(t *testing.T) {
	for _, op := range []string{"consume", "unused"} {
		t.Run(op, func(t *testing.T) {
			f := qualSourceGrantNew(t)
			f.install(t)
			if op == "consume" {
				require.NoError(t, f.consume())
			} else {
				require.NoError(t, f.close("STALE_BINDING"))
			}
			before := qualRegistryValue(t, f.store, string(f.key))
			roots, _, err := f.owner.Commit()
			require.NoError(t, err)
			f.reopen(t, f.store)
			calls := f.host.effectCalls
			f.host.hooks["verify"] = func() { qualRecordPut(t, f.store, f.key, qualRecordFrame(f.body, []byte("OPEN"), nil, nil)) }
			if op == "consume" {
				err = f.consume()
			} else {
				err = f.close("STALE_BINDING")
			}
			require.ErrorIs(t, err, errSourceGrant)
			require.Equal(t, calls, f.host.effectCalls)
			require.Equal(t, before, qualRegistryValue(t, f.store, string(f.key)))
			after, e := f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, roots[0], after)
		})
	}
}

func TestQualDRWAOwnedAuthenticationScopedSuccessor(t *testing.T) {
	for _, item := range []string{"version", "current", "predecessor", "budget", "other"} {
		t.Run(item, func(t *testing.T) {
			f := qualScopedNew(t)
			f.enroll(t)
			next := qualScopedHash("VERSION", f.scope, f.d.authority, f.versionBody)
			proof := f.mandates.proof("SUCCESSOR", f.d.authority, next)
			before, err := f.store.RootHash()
			require.NoError(t, err)
			other := []byte("fixture/owned-auth/successor")
			f.mandates.hook = func() {
				key, value := f.records.key("version", next), qualRecordFrame(f.scope, f.d.authority, f.versionBody)
				switch item {
				case "current":
					qualRecordPut(t, f.store, key, value)
					key, value = f.records.key("current", qualScopedHash("SCOPE", f.scope)), qualRecordFrame(f.scope, next)
				case "predecessor":
					key, value = f.records.key("version", f.d.authority), nil
				case "budget":
					key = []byte(scopedAdmissionPrefix + "budget")
					value = qualRegistryValue(t, f.store, string(key))
					binary.BigEndian.PutUint64(value, 2)
				case "other":
					key, value = other, []byte("preserved")
				}
				qualRecordPut(t, f.store, key, value)
			}
			err = f.records.install(f.context, f.d.owner, f.d.program, f.d.authority, f.versionBody, proof)
			if item == "other" {
				require.NoError(t, err)
				require.Equal(t, []byte("preserved"), qualRegistryValue(t, f.store, string(other)))
				return
			}
			require.ErrorIs(t, err, errScopedAdmission)
			after, e := f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, before, after)
		})
	}
}

func TestQualDRWAOwnedAuthenticationScopedPredecessorBuffer(t *testing.T) {
	f := qualScopedNew(t)
	f.enroll(t)
	predecessor := bytes.Clone(f.d.authority)
	predecessor[0] ^= 1
	next := qualScopedHash("VERSION", f.scope, predecessor, f.versionBody)
	proof := f.mandates.proof("SUCCESSOR", predecessor, next)
	before, err := f.store.RootHash()
	require.NoError(t, err)
	f.mandates.hook = func() { copy(predecessor, f.d.authority) }
	require.ErrorIs(t, f.records.install(f.context, f.d.owner, f.d.program, predecessor, f.versionBody, proof), errScopedAdmission)
	after, err := f.store.RootHash()
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestQualDRWAOwnedAuthenticationGASInitializeBuffer(t *testing.T) {
	f := qualGovernedActionNew(t)
	token := bytes.Clone(f.p.token)
	boundKey, err := f.g.key("active", f.g.domain, token)
	require.NoError(t, err)
	f.h.hooks["initialize"] = func() { token[0] ^= 1 }
	require.NoError(t, f.g.initialize(f.x, f.p.subject, f.p.class, token))
	require.NotEmpty(t, qualRegistryValue(t, f.s, string(boundKey)), "initialize retains the authenticated token binding")
	changedKey, err := f.g.key("active", f.g.domain, token)
	require.NoError(t, err)
	require.Empty(t, qualRegistryValue(t, f.s, string(changedKey)))
}

func TestQualDRWAOwnedAuthenticationScopedAdmission(t *testing.T) {
	for _, op := range []string{"ENROLL", "ADMISSION", "WITHDRAW"} {
		for _, change := range []string{"manufacture", "erase", "budget", "other"} {
			t.Run(op+"/"+change, func(t *testing.T) {
				f := qualScopedNew(t)
				if op != "ENROLL" || change == "erase" {
					f.enroll(t)
				}
				if op == "WITHDRAW" || op == "ADMISSION" && change == "erase" {
					f.admit(t)
				}
				if op == "WITHDRAW" && change == "erase" {
					require.NoError(t, f.records.withdraw(f.context, f.d, f.withdrawProof()))
				}
				key, value := f.records.key("version", f.d.authority), qualRecordFrame(f.scope, nil, f.versionBody)
				proof := f.mandates.proof("ENROLL", nil, f.d.authority)
				if op == "ADMISSION" {
					key, value = f.records.key("decision", f.id()), f.body()
					proof = f.mandates.proof(op, f.d.authority, qualScopedHash("ADMISSION", f.body()))
				}
				if op == "WITHDRAW" {
					key, value = f.records.key("withdrawn", f.id()), f.body()
					proof = f.withdrawProof()
				}
				before, err := f.store.RootHash()
				require.NoError(t, err)
				other := []byte("fixture/owned-auth/scope")
				f.mandates.hook = func() {
					k, v := key, value
					if change == "erase" {
						v = nil
					}
					if change == "budget" {
						k = []byte(scopedAdmissionPrefix + "budget")
						v = qualRegistryValue(t, f.store, string(k))
						binary.BigEndian.PutUint64(v, 2)
					}
					if change == "other" {
						k, v = other, []byte("preserved")
					}
					qualRecordPut(t, f.store, k, v)
				}
				if op == "ENROLL" {
					err = f.records.install(f.context, f.d.owner, f.d.program, nil, f.versionBody, proof)
				} else if op == "ADMISSION" {
					err = f.records.admit(f.context, f.d, proof)
				} else {
					err = f.records.withdraw(f.context, f.d, proof)
				}
				if change == "other" {
					require.NoError(t, err)
					require.Equal(t, []byte("preserved"), qualRegistryValue(t, f.store, string(other)))
					return
				}
				require.ErrorIs(t, err, errScopedAdmission)
				after, e := f.store.RootHash()
				require.NoError(t, e)
				require.Equal(t, before, after)
			})
		}
	}
}

func TestQualDRWAOwnedAuthenticationGASInitialize(t *testing.T) {
	for _, item := range []string{"nonce", "active"} {
		for _, change := range []string{"manufacture", "erase", "other"} {
			t.Run(item+"/"+change, func(t *testing.T) {
				f := qualGovernedActionNew(t)
				if change == "erase" {
					f.initialize(t)
				}
				key, err := f.g.key("nonce", f.g.domain, f.p.subject, f.p.class)
				require.NoError(t, err)
				value := binary.BigEndian.AppendUint64(nil, 1)
				if item == "active" {
					key, err = f.g.key("active", f.g.domain, f.p.token)
					require.NoError(t, err)
					value = qualRecordFrame(make([]byte, 8), make([]byte, 8), f.g.codec.hasher.Compute(""), nil)
				}
				before, err := f.s.RootHash()
				require.NoError(t, err)
				other := []byte("fixture/owned-auth/gas")
				f.h.hooks["initialize"] = func() {
					k, v := key, value
					if change == "erase" {
						v = nil
					}
					if change == "other" {
						k, v = other, []byte("preserved")
					}
					qualRecordPut(t, f.s, k, v)
				}
				err = f.g.initialize(f.x, f.p.subject, f.p.class, f.p.token)
				if change == "other" {
					require.NoError(t, err)
					require.Equal(t, []byte("preserved"), qualRegistryValue(t, f.s, string(other)))
					return
				}
				require.ErrorIs(t, err, errGovernedActionRecord)
				after, e := f.s.RootHash()
				require.NoError(t, e)
				require.Equal(t, before, after)
			})
		}
	}
}

func TestQualDRWAOwnedAuthenticationCurrentLocal(t *testing.T) {
	for _, stage := range []string{"current", "decoder", "dependency"} {
		t.Run(stage, func(t *testing.T) {
			f := qualCurrentLocalNew(t)
			if stage == "dependency" {
				qualRecordPut(t, f.store, f.keys[4], nil)
				f.host.hooks[stage] = func() {
					if f.host.calls[stage] == 1 {
						qualRecordPut(t, f.store, f.keys[4], f.materials[4])
					}
				}
			} else {
				f.host.hooks[stage] = func() { qualRecordPut(t, f.store, f.pointerKey, []byte("changed before another verifier")) }
				restore := "decoder"
				if stage == "decoder" {
					restore = "dependency"
				}
				f.host.hooks[restore] = func() { qualRecordPut(t, f.store, f.pointerKey, f.pointer) }
			}
			v, err := f.resolve()
			require.ErrorIs(t, err, errCurrentLocalDependency)
			require.Nil(t, v)
		})
	}
}
