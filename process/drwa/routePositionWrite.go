package drwa

import (
	"bytes"
	"math/big"
	"slices"
	"sort"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// positionTransferBinding comes from the original owner. Limits and version
// are supplied by the admitted profile and are never taken from call arguments.
type positionTransferBinding struct {
	token, cebHash   []byte
	epoch            uint64
	maxLegs, maxKeys int
	leafVersion      *core.TrieNodeVersion
}

type nativePositionTransfer struct {
	reader   *setupLocalStateReader
	db       *state.AccountsDB
	local    localSetupState
	binding  positionTransferBinding
	balances []transferPositionBalance
}

type transferPositionBalance struct {
	holder []byte
	nonce  uint64
	change positionLeafChange
}

func (w *nativePositionTransfer) prepare(o *routeNativeOperation, source []byte, parsed *vmcommon.ParsedESDTTransfers) error {
	p := w.local.positions
	if parsed == nil || parsed.CallFunction != "" || len(parsed.ESDTTransfers) == 0 || len(parsed.ESDTTransfers) > w.binding.maxLegs ||
		len(source) != len(core.SystemAccountAddress) || len(parsed.RcvAddr) != len(core.SystemAccountAddress) ||
		o.coordinator.SelfId() != w.reader.current.coordinator.SelfId() ||
		o.coordinator.ComputeId(source) != o.coordinator.SelfId() || o.coordinator.ComputeId(parsed.RcvAddr) != o.coordinator.SelfId() {
		return errSetupLocalState
	}
	same := bytes.Equal(source, parsed.RcvAddr)
	holders := [][]byte{source}
	if !same {
		holders = append(holders, parsed.RcvAddr)
	}
	maxBytes := w.reader.records.maxAmountBytes
	moved := make(map[uint64]*big.Int)
	for _, leg := range parsed.ESDTTransfers {
		if leg == nil || !bytes.Equal(leg.ESDTTokenName, p.token) ||
			leg.ESDTTokenType != uint32(p.family) ||
			!positionNonceValid(p.family, leg.ESDTTokenNonce) ||
			!supplyIntegerFits(leg.ESDTValue, maxBytes) || leg.ESDTValue.Sign() <= 0 {
			return errSetupLocalState
		}
		total := moved[leg.ESDTTokenNonce]
		if total == nil {
			if len(moved) == w.binding.maxKeys/len(holders) {
				return errSetupLocalState
			}
			total = new(big.Int)
			moved[leg.ESDTTokenNonce] = total
		}
		if !same {
			total.Add(total, leg.ESDTValue)
			if !supplyIntegerFits(total, maxBytes) {
				return errSetupLocalState
			}
		}
	}
	nonces := make([]uint64, 0, len(moved))
	for nonce := range moved {
		nonces = append(nonces, nonce)
	}
	slices.Sort(nonces)
	for i, holder := range holders {
		for _, nonce := range nonces {
			total := moved[nonce]
			before, err := w.balance(o, holder, nonce)
			if err != nil {
				return err
			}
			next := new(big.Int).Set(before)
			if i == 0 {
				next.Sub(next, total)
			} else {
				next.Add(next, total)
			}
			if !supplyIntegerFits(next, maxBytes) {
				return errSetupLocalState
			}
			key, err := w.reader.records.positionKey(p.token, p.family, nonce, holder)
			if err != nil {
				return err
			}
			w.balances = append(w.balances, transferPositionBalance{holder: bytes.Clone(holder), nonce: nonce,
				change: positionLeafChange{key: key, before: positionBalanceBytes(before), final: positionBalanceBytes(next)}})
		}
	}
	sort.Slice(w.balances, func(i, j int) bool { return bytes.Compare(w.balances[i].change.key, w.balances[j].change.key) < 0 })
	return nil
}

func (w *nativePositionTransfer) balance(o *routeNativeOperation, holder []byte, nonce uint64) (*big.Int, error) {
	account, err := o.accounts.GetExistingAccount(holder)
	if err != nil {
		return nil, err
	}
	user, ok := account.(vmcommon.UserAccountHandler)
	if !ok {
		return nil, errSetupLocalState
	}
	p := w.local.positions
	return nativePositionBalance(o.storage, o.guard, user, p.token, p.family, nonce, w.reader.records.maxAmountBytes)
}

func (w *nativePositionTransfer) finish(o *routeNativeOperation) error {
	changes := make([]positionLeafChange, 0, len(w.balances))
	for _, item := range w.balances {
		actual, err := w.balance(o, item.holder, item.nonce)
		if err != nil {
			return err
		}
		if !bytes.Equal(positionBalanceBytes(actual), item.change.final) {
			return errSetupLocalState
		}
		changes = append(changes, item.change)
	}
	return w.reader.records.writePositionMap(w.db, w.local, changes, w.binding.maxKeys, w.binding.leafVersion)
}
