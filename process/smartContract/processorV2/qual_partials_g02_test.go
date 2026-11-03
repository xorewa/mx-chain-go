package processorV2

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// G02: real node entrypoint and account/code journal. The VM fixture supplies
// direct/indirect upgrade outputs; it does not execute guest WASM or earn native
// compilation/cache/factory credit. Values are experimental local fixtures.
func TestQualPartialsG02NodeUpgrade(t *testing.T) {
	for _, mode := range []string{"healthy", "vm_failure", "late_failure", "owner_denial"} {
		t.Run(mode, func(t *testing.T) {
			db := qualPartialsR01Accounts(t)
			owner := bytes.Repeat([]byte{7}, 32)
			first, second := make([]byte, 32), make([]byte, 32)
			first[8], first[31] = 5, 1
			second[8], second[31] = 5, 2
			oldMeta := (&vmcommon.CodeMetadata{Upgradeable: true}).ToBytes()
			newMeta := (&vmcommon.CodeMetadata{Upgradeable: true, Readable: true}).ToBytes()
			for i, addr := range [][]byte{first, second} {
				a, e := db.LoadAccount(addr)
				require.NoError(t, e)
				u := a.(state.UserAccountHandler)
				u.SetCode([]byte("old"))
				u.SetCodeMetadata(oldMeta)
				if i == 0 {
					u.SetOwnerAddress(owner)
				} else {
					u.SetOwnerAddress(first)
				}
				u.IncreaseNonce(4)
				require.NoError(t, u.SaveKeyValue([]byte("key"), []byte("before")))
				require.NoError(t, db.SaveAccount(u))
			}
			before, e := db.Commit()
			require.NoError(t, e)
			args := createMockSmartContractProcessorArguments()
			args.AccountsDB = db
			args.ArgsParser = smartContract.NewArgumentParser()
			args.Hasher = blake2b.NewBlake2b()
			args.Marshalizer = &marshal.GogoProtoMarshalizer{}
			args.EnableEpochsHandler = enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.SCDeployFlag, common.FixCorrectSmallIntAndGasLimitsFlag)
			args.ShardCoordinator = &testscommon.ShardsCoordinatorMock{SelfIDCalled: func() uint32 { return 0 }, ComputeIdCalled: func([]byte) uint32 { return 0 }}
			calls := 0
			machine := &mock.VMExecutionHandlerStub{RunSmartContractCallCalled: func(in *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
				calls++
				require.Equal(t, "upgradeContract", in.Function)
				require.Equal(t, first, in.RecipientAddr)
				out := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 50000, GasRefund: big.NewInt(0), OutputAccounts: map[string]*vmcommon.OutputAccount{}}
				for i, addr := range [][]byte{first, second} {
					deployer := owner
					if i == 1 {
						deployer = first
					}
					nonce := uint64(5)
					if mode == "late_failure" && i == 1 {
						nonce = 3
					}
					out.OutputAccounts[string(addr)] = &vmcommon.OutputAccount{Address: addr, Code: []byte{"a"[0] + byte(i)}, CodeMetadata: newMeta, CodeDeployerAddress: deployer, Nonce: nonce, BalanceDelta: big.NewInt(0), StorageUpdates: map[string]*vmcommon.StorageUpdate{"key": {Offset: []byte("key"), Data: []byte("after")}}}
				}
				if mode == "vm_failure" {
					out.ReturnCode = vmcommon.UserError
					out.ReturnMessage = "fixture upgrade rejected"
				}
				return out, nil
			}}
			args.VmContainer = &mock.VMContainerMock{GetCalled: func([]byte) (vmcommon.VMExecutionHandler, error) { return machine, nil }}
			sc, e := NewSmartContractProcessorV2(args)
			require.NoError(t, e)
			caller := owner
			if mode == "owner_denial" {
				caller = bytes.Repeat([]byte{8}, 32)
			}
			tx := &transaction.Transaction{SndAddr: caller, RcvAddr: first, Value: big.NewInt(0), GasLimit: 100000, GasPrice: 0, Data: []byte("upgradeContract@61@" + hex.EncodeToString(newMeta))}
			dst, e := db.GetExistingAccount(first)
			require.NoError(t, e)
			rc, e := sc.ExecuteSmartContractTransaction(tx, nil, dst.(state.UserAccountHandler))
			require.NoError(t, e)
			want := vmcommon.Ok
			if mode == "late_failure" {
				want = vmcommon.ExecutionFailed
			} else if mode != "healthy" {
				want = vmcommon.UserError
			}
			require.Equal(t, want, rc, "native upgrade terminal code")
			if mode == "owner_denial" {
				require.Zero(t, calls, "owner guard precedes VM")
			} else {
				require.Equal(t, 1, calls)
			}
			after, e := db.Commit()
			require.NoError(t, e)
			if mode != "healthy" {
				require.Equal(t, before, after, "failed upgrade restores code/storage root")
			}
			require.NoError(t, db.RecreateTrie(holders.NewDefaultRootHashesHolder(after)))
			for i, addr := range [][]byte{first, second} {
				a, e := db.GetExistingAccount(addr)
				require.NoError(t, e)
				u := a.(state.UserAccountHandler)
				code, meta, value, nonce := []byte("old"), oldMeta, []byte("before"), uint64(4)
				if mode == "healthy" {
					code = []byte{"a"[0] + byte(i)}
					meta = newMeta
					value = []byte("after")
					nonce = 5
				}
				require.Equal(t, code, db.GetCode(u.GetCodeHash()), "direct/indirect upgrade code persisted")
				require.Equal(t, meta, u.GetCodeMetadata())
				v, _, e := u.RetrieveValue([]byte("key"))
				require.NoError(t, e)
				require.Equal(t, value, v)
				require.Equal(t, nonce, u.GetNonce())
				wantOwner := owner
				if i == 1 {
					wantOwner = first
				}
				require.Equal(t, wantOwner, u.GetOwnerAddress())
			}
		})
	}
}
