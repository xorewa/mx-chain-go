package systemSmartContracts

import (
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// Structural DRWA-only coupling to L41's experimental creation binding. T14
// must supply the authenticated body digest/current authority before admission.
type drwaCommittedRegistrationOwner interface {
	RegisterTokenForCommittedCreation(issuer, manager, family, profile, name, ticker []byte,
		decimals uint32, bodyDigest []byte,
		create func(state.AccountsAdapter, []byte, []byte, []byte, []byte, []byte, uint32, [][]byte) ([]byte, *vmcommon.VMOutput, error)) error
	IsInterfaceNil() bool
}

// drwaCreationJournal invokes the native primitive inside the existing T04
// operation. It creates no journal, performs no commit and releases no output.
type drwaCreationJournal struct {
	accounts   state.AccountsAdapter
	identifier []byte
	output     *vmcommon.VMOutput
}

func (o *drwaCreationJournal) RegisterToken(create func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error)) error {
	var err error
	o.identifier, o.output, err = create(o.accounts)
	return err
}

func (o *drwaCreationJournal) IsInterfaceNil() bool { return o == nil }

// registerDRWACommittedToken couples exact validated arguments and derived
// properties to the ACTUAL native creator and complete retained record bundle.
// It is unwired experimental construction, not a fee-complete ingress endpoint.
// Raw property arguments are refused: only the validated profile derives them.
// The exclusive native lock covers validation, creation and record consumption.
// No ordinary dispatcher, factory or public ESDT route calls this method.
func (e *esdt) registerDRWACommittedToken(owner drwaCommittedRegistrationOwner,
	request drwaTokenCreation, profile, bodyDigest []byte) (err error) {
	e.mutExecution.Lock()
	defer e.mutExecution.Unlock()
	context, ok := e.eei.(*vmContext)
	if !ok || check.IfNil(owner) || len(request.properties) != 0 ||
		len(context.storageUpdate) != 0 || len(context.outputAccounts) != 0 ||
		len(context.output) != 0 || len(context.logs) != 0 {
		return errInvalidDRWARegistration
	}
	originalOutput, originalLogs := context.output, context.logs
	defer func() {
		if err != nil {
			// Native creation can succeed before OPEN consumption or the later
			// registry save fails. Keep native gas/message, discard all tentative
			// success output even when rollback itself poisons the T04 owner.
			context.CleanStorageUpdates()
			context.outputAccounts = make(map[string]*vmcommon.OutputAccount)
			context.output, context.logs = originalOutput, originalLogs
		}
	}()
	return owner.RegisterTokenForCommittedCreation(request.issuer, request.manager, request.family,
		profile, request.name, request.ticker, request.decimals, bodyDigest,
		func(accounts state.AccountsAdapter, issuer, manager, family, name, ticker []byte,
			decimals uint32, properties [][]byte) ([]byte, *vmcommon.VMOutput, error) {
			actual := drwaTokenCreation{issuer: issuer, manager: manager, family: family,
				name: name, ticker: ticker, decimals: decimals, properties: properties}
			journal := &drwaCreationJournal{accounts: accounts}
			createErr := e.registerDRWATokenLocked(journal, actual)
			return journal.identifier, journal.output, createErr
		})
}
