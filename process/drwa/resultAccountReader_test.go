package drwa

import (
	"errors"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

type proofRecreateFault struct {
	common.Trie
	at, calls int
	failure   error
}

func (s *proofRecreateFault) Recreate(root common.RootHashHolder) (common.Trie, error) {
	s.calls++
	if s.calls == s.at {
		return nil, s.failure
	}
	return s.Trie.Recreate(root)
}

type proofAccountFactoryFault struct {
	state.AccountFactory
	failure error
}

func (s *proofAccountFactoryFault) CreateAccount([]byte) (vmcommon.AccountHandler, error) {
	return nil, s.failure
}

func TestResultAccountReader_Read(t *testing.T) {
	for _, mode := range []string{"main recreate", "data recreate", "account factory"} {
		t.Run(strings.ReplaceAll(mode, "/", " ")+" should preserve the expected result", func(t *testing.T) {
			f := qualNativeReaderFixture(t, false, 1)
			reader, err := NewResultAccountReader(qualReaderArgs(false))
			require.NoError(t, err)
			sentinel := errors.New("native authenticated-item dependency unavailable")
			if mode == "account factory" {
				reader.accountFactory = &proofAccountFactoryFault{AccountFactory: reader.accountFactory, failure: sentinel}
			} else {
				at := 1
				if mode == "data recreate" {
					at = 2
				}
				reader.proofTrie = &proofRecreateFault{Trie: reader.proofTrie, at: at, failure: sentinel}
			}
			root, err := f.adb.RootHash()
			require.NoError(t, err)
			item, err := reader.Read(f.anchor, 1, f.address, f.key, f.w, f.budget)
			require.ErrorIs(t, err, sentinel)
			require.Nil(t, item)
			after, err := f.adb.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
		})
	}
	f := qualRegistryTransport(t, false, []byte{0, 0, 0, 0, 0, 0, 0, 2}, []byte{1})
	item, err := f.reader.readRegistryItem(f.anchor, []byte(registryCountKey), f.count, 0)
	require.Error(t, err)
	require.Nil(t, item)
}
