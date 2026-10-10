package drwa

import (
	"testing"

	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Synthetic host adversary only. Native accounts/journals and containment are
// real; no source projection canonicality or regulated debit is established.
type qualSourceGrantAfterAck struct {
	*qualSourceGrantHost
	after func()
}

func (h *qualSourceGrantAfterAck) Ack(projection []byte, status, reason string, effect []byte, output *vmcommon.VMOutput) error {
	if err := h.qualSourceGrantHost.Ack(projection, status, reason, effect, output); err != nil {
		return err
	}
	h.after()
	return nil
}

func TestQualDRWASourceGrantCallbackState(t *testing.T) {
	for _, name := range []string{"admission_consumes", "consume_closes", "apply_closes", "started_ack_reopens", "unused_consumes", "unused_ack_reopens", "started_redrive_reopens", "unused_redrive_consumes"} {
		t.Run(name, func(t *testing.T) {
			f := qualSourceGrantNew(t)
			isAdmission := name == "admission_consumes"
			isUnused := name == "unused_consumes" || name == "unused_ack_reopens" || name == "unused_redrive_consumes"
			isRedrive := name == "started_redrive_reopens" || name == "unused_redrive_consumes"
			if !isAdmission {
				f.install(t)
			}
			if isRedrive {
				if isUnused {
					require.NoError(t, f.close("STALE_BINDING"))
				} else {
					require.NoError(t, f.consume())
				}
			}
			before := qualRegistryValue(t, f.store, string(f.key))
			roots, _, err := f.owner.Commit()
			require.NoError(t, err)
			f.reopen(t, f.store)
			effects := f.host.effectCalls
			write := func(status, reason string, effect []byte) func() {
				return func() {
					qualRecordPut(t, f.store, f.key, qualRecordFrame(f.body, []byte(status), []byte(reason), effect))
				}
			}
			switch name {
			case "admission_consumes":
				f.host.hooks["admission"] = write("CONSUMED", "", f.host.effect)
			case "consume_closes":
				f.host.hooks["consume"] = write("CLOSED_UNUSED", "STALE_BINDING", nil)
			case "apply_closes":
				f.host.hooks["apply"] = write("CLOSED_UNUSED", "STALE_BINDING", nil)
			case "unused_consumes":
				f.host.hooks["unused"] = write("CONSUMED", "", f.host.effect)
			default:
				mutation := write("OPEN", "", nil)
				if name == "unused_redrive_consumes" {
					mutation = write("CONSUMED", "", f.host.effect)
				}
				f.records.host = &qualSourceGrantAfterAck{f.host, mutation}
			}
			if isAdmission {
				err = f.records.install(f.context, f.p, []byte("synthetic-canonical-proof"))
			} else if isUnused {
				err = f.close("STALE_BINDING")
			} else {
				err = f.consume()
			}
			require.ErrorIs(t, err, errSourceGrant)
			require.Equal(t, before, qualRegistryValue(t, f.store, string(f.key)))
			balance := int64(100)
			if name == "started_redrive_reopens" {
				balance = 97
			}
			qualAssertContainmentBalance(t, f.store, balance)
			if name == "apply_closes" || name == "started_ack_reopens" {
				require.Equal(t, effects+1, f.host.effectCalls)
			} else {
				require.Equal(t, effects, f.host.effectCalls, "validation and redrive never execute another effect")
			}
			after, rootErr := f.store.RootHash()
			require.NoError(t, rootErr)
			require.Equal(t, roots[0], after)
			_, output, commitErr := f.owner.Commit()
			require.NoError(t, commitErr)
			require.Empty(t, output, "no successful native effect or ACK output survives the failed operation")
		})
	}
}

func TestQualDRWASourceGrantCallbackOtherKey(t *testing.T) {
	for _, stage := range []string{"admission", "consume", "apply", "unused", "ack"} {
		t.Run(stage, func(t *testing.T) {
			f := qualSourceGrantNew(t)
			key := []byte("fixture/source-grant-callback/" + stage)
			write := func() { qualRecordPut(t, f.store, key, []byte("preserved")) }
			if stage == "admission" {
				f.host.hooks[stage] = write
				f.install(t)
				f.assertState(t, "OPEN", "", nil)
			} else {
				f.install(t)
				if stage == "ack" {
					f.records.host = &qualSourceGrantAfterAck{f.host, write}
				} else {
					f.host.hooks[stage] = write
				}
				if stage == "unused" {
					require.NoError(t, f.close("STALE_BINDING"))
					f.assertState(t, "CLOSED_UNUSED", "STALE_BINDING", nil)
				} else {
					require.NoError(t, f.consume())
					f.assertState(t, "CONSUMED", "", f.host.effect)
				}
			}
			require.Equal(t, []byte("preserved"), qualRegistryValue(t, f.store, string(key)))
		})
	}
}
