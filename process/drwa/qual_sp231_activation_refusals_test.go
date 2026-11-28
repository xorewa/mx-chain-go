package drwa

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/stretchr/testify/require"
)

// The activation write this row changed, at its other refusals: each leaves
// the registered-but-inactive token as it is. They complete the statement
// coverage of the changed function; the admission check runs first in all.
func TestQualSP231ActivationWriteRefusals(t *testing.T) {
	commitment := blake2b.NewBlake2b().Compute("readiness commitment")
	type call struct {
		token, commitment []byte
		ended             bool
	}
	for name, prepare := range map[string]func(w *qualSP231World, x *qualActivationFixture, c *call){
		"evaluation ended":       func(_ *qualSP231World, _ *qualActivationFixture, c *call) { c.ended = true },
		"token never registered": func(_ *qualSP231World, _ *qualActivationFixture, c *call) { c.token = []byte("OTHR-abcdef") },
		"class identity over the record bound": func(_ *qualSP231World, x *qualActivationFixture, _ *call) {
			x.h.view.classes = []activationActionClass{{make([]byte, 2040), make([]byte, 2050)}}
		},
		"class without a subject": func(_ *qualSP231World, x *qualActivationFixture, _ *call) {
			x.h.view.classes = []activationActionClass{{nil, []byte("class")}}
		},
		"the same class twice": func(_ *qualSP231World, x *qualActivationFixture, _ *call) {
			x.h.view.classes = append(x.h.view.classes, x.h.view.classes[0])
		},
		"a lifecycle record already exists": func(w *qualSP231World, _ *qualActivationFixture, _ *call) {
			qualRecordPut(w.t, w.f.store, append([]byte(lifecycleRecordPrefix), qualRecordFrame([]byte(qualSP231Token))...), []byte("present"))
		},
		"short readiness commitment": func(_ *qualSP231World, _ *qualActivationFixture, c *call) { c.commitment = []byte("short") },
		"activation record is not BootstrapDeny": func(w *qualSP231World, _ *qualActivationFixture, _ *call) {
			qualRecordPut(w.t, w.f.store, append([]byte(registrationActivationPrefix), []byte(qualSP231Token)...), []byte("other"))
		},
		"registry member is not set": func(w *qualSP231World, _ *qualActivationFixture, _ *call) {
			qualRecordPut(w.t, w.f.store, append([]byte(registryMemberKeyPrefix), []byte(qualSP231Token)...), []byte{2})
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := qualSP231New(t, 200, true)
			created := 0
			require.NoError(t, w.register(&created))
			x := w.activation(true)
			c := &call{token: []byte(qualSP231Token), commitment: commitment}
			prepare(w, x, c)
			context, err := w.f.hook.EvaluatedHeaderTimeContext()
			require.NoError(t, err)
			if c.ended {
				w.f.end()
			}
			root, journal := w.state()
			var written []scopedAdmissionWrite
			_, err = x.a.writeActivationInHeader(context, c.token, w.f.owner.id, []byte("synthetic-complete-genesis-body"),
				[]byte("synthetic-complete-activation-proof"), c.commitment, &written)
			require.Error(t, err)
			after, afterJournal := w.state()
			require.Equal(t, root, after, "a refused activation writes nothing")
			require.Equal(t, journal, afterJournal)
		})
	}
}
