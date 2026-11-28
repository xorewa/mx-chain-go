package drwa

import (
	"bytes"
	"math/big"

	"github.com/multiversx/mx-chain-core-go/core"

	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// AcknowledgeRegistryDelta is the metachain's funded application of one
// shard's acknowledgment (ParseRegistryAcknowledgment): the leg of that shard
// gets its one outcome, paid at the retained completion entry from the gas the
// callback carries. A repeated acknowledgment changes nothing; the callback of
// a member that was never funded, or one with too little gas, is refused and
// leaves the leg open.
func (f *CarrierFunding) AcknowledgeRegistryDelta(input *vmcommon.ContractCallInput, shards uint32) (*RegistryAcknowledgment, CarrierOutcomeResult, error) {
	acknowledgment, err := ParseRegistryAcknowledgment(input, shards)
	if err != nil {
		return nil, CarrierOutcomeResult{}, err
	}
	result, err := f.Outcome(RegistryDeltaCarrierClass, registryDeltaEffect(acknowledgment.TokenID, acknowledgment.Ordinal),
		acknowledgment.Shard, input.GasProvided)
	if err != nil {
		return nil, CarrierOutcomeResult{}, err
	}
	return acknowledgment, result, nil
}

// RedriveRegistryDelta adds to output the same delta of one member for one
// execution shard that has not acknowledged it, funded at the retained entries
// from available gas units of the operation in execution, and returns what is
// left of them. The delivery carries the identifiers of the first one, so the
// shard applies nothing twice and the metachain counts one acknowledgment.
func (f *CarrierFunding) RedriveRegistryDelta(output *vmcommon.VMOutput, tokenID []byte, ordinal uint64, shard, shards uint32, available uint64) (uint64, error) {
	if output == nil || shards > maxCarrierLegs || shard >= shards || !vmcommon.ValidateToken(tokenID) {
		return 0, ErrInvalidRegistryDelta
	}
	index, found := uint32(0), false
	for _, account := range output.OutputAccounts {
		if account == nil {
			return 0, ErrInvalidRegistryDelta
		}
		for _, transfer := range account.OutputTransfers {
			if !found || transfer.Index >= index {
				if transfer.Index == ^uint32(0) {
					return 0, ErrInvalidRegistryDelta
				}
				index, found = transfer.Index+1, true
			}
		}
	}
	member := registryDeltaEffect(tokenID, ordinal)
	reservation, err := f.Redrive(RegistryDeltaCarrierClass, member, shard, available)
	if err != nil {
		return 0, err
	}
	if reservation.LegGas == 0 {
		return 0, ErrInvalidRegistryDelta
	}
	address := registryDeltaSystemAddress(shard)
	if output.OutputAccounts == nil {
		output.OutputAccounts = make(map[string]*vmcommon.OutputAccount, 1)
	}
	account, exists := output.OutputAccounts[string(address)]
	if !exists {
		account = &vmcommon.OutputAccount{Address: address, BalanceDelta: big.NewInt(0)}
		output.OutputAccounts[string(address)] = account
	}
	delivery := append(bytes.Clone(member), uint8(shard))
	account.OutputTransfers = append(account.OutputTransfers, vmcommon.OutputTransfer{
		Index: index, Value: big.NewInt(0), GasLimit: reservation.LegGas,
		Data:      []byte(RegistryDeltaFunctionName + "@" + hexEncode(tokenID) + "@" + hexEncode(member[len(tokenID):])),
		AsyncData: []byte("@" + hexEncode(delivery) + "@" + hexEncode(member)),
		CallType:  vmData.AsynchronousCall, SenderAddress: bytes.Clone(core.ESDTSCAddress),
	})
	return reservation.Remaining, nil
}
