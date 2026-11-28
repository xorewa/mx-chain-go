package drwa

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"
)

// SP2-37, inventory row S3: the native supply path of the supply-origin shard
// reads the shard's own lifecycle record, the record the seal owner advances.
// With that record SETUP_SEALED a setup mint is refused and leaves nothing;
// with SETUP (the lagging state before the seal) and with OPEN it is the
// CEB's rule that decides. The supply writer and its fixture are those of the
// supply rows; the record bytes are framed independently.
func TestQualSP237NativeSupplyCannotStartOnASealedShard(t *testing.T) {
	for _, c := range []struct {
		phase    string
		admitted bool
	}{{"SETUP", true}, {"SETUP_SEALED", false}, {"OPEN", true}} {
		t.Run(c.phase, func(t *testing.T) {
			w := qualOwnedSupplyNew(t, core.Fungible)
			w.begin(t)
			local := &qualNativeStore{AccountsAdapter: w.db}
			qualRecordPut(t, local, sp237Key(string(w.token)), sp237Record(string(w.token), 1, c.phase))
			before, err := w.db.RootHash()
			require.NoError(t, err)
			before = bytes.Clone(before)
			journal, outputs := w.db.JournalLen(), len(w.owner.outputs)
			mint := w.input(core.BuiltInFunctionESDTLocalMint, w.origin, w.origin, w.token, []byte{5})
			err = w.supply(t, mint, 0, big.NewInt(5))
			after, rootErr := w.db.RootHash()
			require.NoError(t, rootErr)
			if c.admitted {
				require.NoError(t, err)
				require.NotEqual(t, before, after)
				return
			}
			require.ErrorIs(t, err, errSupplyAccounting)
			require.Equal(t, before, after, "a refused setup mint leaves no state")
			require.Equal(t, journal, w.db.JournalLen())
			require.Len(t, w.owner.outputs, outputs)
		})
	}
}
