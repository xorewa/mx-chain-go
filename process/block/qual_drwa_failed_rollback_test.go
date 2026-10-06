package block

import (
	"errors"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/stateChange"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/state/disabled"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/hashingMocks"
	"github.com/multiversx/mx-chain-go/testscommon/marshallerMock"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	trieMock "github.com/multiversx/mx-chain-go/testscommon/trie"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Part A 5.4 P-05: exercise the actual AccountsDB account-creation undo and
// outer block commit/creation barriers. The fault is below the native journal;
// no production qualification seam or node/network process is used.
func TestQualDRWAFailedRollbackOuterBlockContainment(t *testing.T) {
	for _, failingStore := range []state.AccountsDbIdentifier{state.UserAccountsState, state.PeerAccountsState} {
		for _, boundary := range []string{"commit", "commit_epoch", "shard_commit", "meta_commit", "verify_root"} {
			t.Run(fmt.Sprintf("store_%d/%s", failingStore, boundary), func(t *testing.T) {
				fault := errors.New("native journal trie update failed")
				failUndo := false
				commits := 0
				tr := &trieMock.TrieStub{
					GetCalled:  func([]byte) ([]byte, uint32, error) { return nil, 0, nil },
					RootCalled: func() ([]byte, error) { return []byte("root"), nil },
					UpdateCalled: func(_, _ []byte) error {
						if failUndo {
							return fault
						}
						return nil
					},
					CommitCalled: func() error { commits++; return nil },
				}
				adb, err := state.NewAccountsDB(state.ArgsAccountsDB{
					Trie:       tr,
					Hasher:     &hashingMocks.HasherMock{},
					Marshaller: &marshallerMock.MarshalizerMock{},
					AccountFactory: &stateMock.AccountsFactoryStub{CreateAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
						return stateMock.NewAccountWrapMock(address), nil
					}},
					StoragePruningManager: &stateMock.StoragePruningManagerStub{},
					AddressConverter:      testscommon.NewPubkeyConverterMock(32),
					SnapshotsManager:      disabled.NewDisabledSnapshotsManager(),
					StateAccessesCollector: &stateMock.StateAccessesCollectorStub{
						IsInterfaceNilCalled:                func() bool { return false },
						SetIndexToLatestStateAccessesCalled: func(int) error { return nil },
						GetAccountChangesCalled:             func(vmcommon.AccountHandler, vmcommon.AccountHandler) uint32 { return stateChange.NoChange },
						AddStateChangeCalled:                func(*stateChange.StateAccess) {},
					},
				})
				require.NoError(t, err)
				require.NoError(t, adb.SaveAccount(stateMock.NewAccountWrapMock([]byte("first"))))
				snapshot := adb.JournalLen()
				require.NoError(t, adb.SaveAccount(stateMock.NewAccountWrapMock([]byte("second"))))
				failUndo = true
				require.ErrorIs(t, adb.RevertToSnapshot(snapshot), fault)
				healthy := &stateMock.AccountsStub{
					RootHashCalled:      func() ([]byte, error) { return []byte("healthy"), nil },
					CommitCalled:        func() ([]byte, error) { commits++; return []byte("healthy"), nil },
					CommitInEpochCalled: func(uint32, uint32) ([]byte, error) { commits++; return []byte("healthy"), nil },
				}
				bp := &baseProcessor{accountsDB: map[state.AccountsDbIdentifier]state.AccountsAdapter{
					state.UserAccountsState: healthy,
					state.PeerAccountsState: healthy,
				}}
				bp.accountsDB[failingStore] = adb
				busyCalls := 0
				bp.blockChain = &testscommon.ChainHandlerStub{
					GetCurrentBlockHeaderCalled:     func() data.HeaderHandler { return nil },
					GetCurrentBlockHeaderHashCalled: func() []byte { return nil },
				}
				bp.processStatusHandler = &testscommon.ProcessStatusHandlerStub{
					TrySetBusyCalled: func(string) bool { busyCalls++; return false },
				}
				sp := &shardProcessor{baseProcessor: bp}
				mp := &metaProcessor{baseProcessor: bp}
				switch boundary {
				case "commit":
					err = bp.commit()
				case "commit_epoch":
					err = bp.commitInEpoch(7, 6)
				case "shard_commit":
					err = sp.CommitBlock(&block.Header{}, &block.Body{})
				case "meta_commit":
					err = mp.CommitBlock(&block.MetaBlock{}, &block.Body{})
				case "verify_root":
					if failingStore == state.UserAccountsState {
						require.False(t, bp.verifyStateRoot(nil))
					}
					err = bp.checkAccountsState()
				}
				require.ErrorIs(t, err, fault)
				require.Zero(t, commits, "neither healthy nor failed store commits, regardless of map order")
				require.Zero(t, busyCalls, "the latch alone cannot stop CommitBlock's prologue before account commit")
			})
		}
	}
}
