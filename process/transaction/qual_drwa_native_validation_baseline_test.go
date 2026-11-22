package transaction

// Qualification-only exact native function comparator; official mx-chain-go
// 06c383cf316ab391d60695a4eeb7c085fb40232b, process/transaction/interceptedTransaction.go.
// Actual source snapshot/hash and function-scoped limitations are in TASK_RECORD.
func QualD18UntouchedNativeCheckValidity(inTx *InterceptedTransaction) error {
	err := inTx.integrity(inTx.tx)
	if err != nil {
		return err
	}

	whiteListedVerified := inTx.whiteListerVerifiedTxs.IsWhiteListed(inTx)
	if !whiteListedVerified {
		err = inTx.verifySig(inTx.tx)
		if err != nil {
			return err
		}

		err = inTx.VerifyGuardianSig(inTx.tx)
		if err != nil {
			return err
		}

		err = inTx.verifyIfRelayedTxV3(inTx.tx)
		if err != nil {
			return err
		}

		err = inTx.verifyIfRelayedTx(inTx.tx)
		if err != nil {
			return err
		}

		err = inTx.verifyIfRelayedTxV2(inTx.tx)
		if err != nil {
			return err
		}

		inTx.whiteListerVerifiedTxs.Add([][]byte{inTx.Hash()})
	}

	return nil
}

// ShouldAllowDuplicates returns if this type of intercepted data should allow duplicates
