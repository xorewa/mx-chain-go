package systemSmartContracts

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/vm"
)

// SP2-34: the protected manager path and the public manager, ownership and
// conversion entry points of the metachain ESDT system contract, over the
// real contract and its execution context. The verified context is a fixture:
// its production form is the registration ingress's (SP2-38).

type qualSP234Admin struct {
	verifyErr, carryErr error
	manager             []byte
	verified, carried   int
	operation           string
	arguments           [][]byte
	onCarry             func()
}

func (a *qualSP234Admin) IsInterfaceNil() bool { return a == nil }
func (a *qualSP234Admin) VerifyManagerMutation(_, manager []byte, operation string, arguments [][]byte) error {
	a.verified++
	a.operation, a.arguments = operation, arguments
	if a.verifyErr != nil {
		return a.verifyErr
	}
	if !bytes.Equal(manager, a.manager) {
		return errors.New("not the reserved manager")
	}
	return nil
}
func (a *qualSP234Admin) CarryManagerEffect([]byte, string, [][]byte) error {
	a.carried++
	if a.onCarry != nil {
		a.onCarry()
	}
	return a.carryErr
}

var (
	qualSP234Token   = []byte("REGUL-0a1b2c")
	qualSP234Manager = bytes.Repeat([]byte{0xd0}, 32)
	qualSP234Holder  = bytes.Repeat([]byte{7}, 32)
)

// qualSP234Contract is the ESDT system contract over a context whose
// classifier answers regulated as told (nil: no DRWA classifier), holding one
// token of the given type owned by the manager.
func qualSP234Contract(t *testing.T, classifier vm.DRWATokenClassifier, tokenType string) (*esdt, *vmContext) {
	t.Helper()
	args := createMockArgumentsForESDT()
	contextArgs := createDefaultEeiArgs()
	if classifier != nil {
		contextArgs.DRWAClassifier = classifier
	}
	context, err := NewVMContext(contextArgs)
	require.NoError(t, err)
	context.SetSCAddress(core.ESDTSCAddress)
	args.Eei = context
	args.ESDTSCAddress = bytes.Clone(core.ESDTSCAddress)
	e, err := NewESDTSmartContract(args)
	require.NoError(t, err)
	require.NoError(t, e.saveToken(qualSP234Token, &ESDTDataV2{OwnerAddress: bytes.Clone(qualSP234Manager),
		TokenName: []byte("RegulatedToken"), TickerName: []byte("REGUL"), TokenType: []byte(tokenType), CanAddSpecialRoles: true,
		CanTransferNFTCreateRole: tokenType != core.FungibleESDT}))
	return e, context
}

func qualSP234Record(t *testing.T, e *esdt) *ESDTDataV2 {
	t.Helper()
	token, err := e.getExistingToken(qualSP234Token)
	require.NoError(t, err)
	return token
}

// Part A section 13 item 2: "the reserved DRWA_SYSTEM_MANAGER System-SC path
// invokes only the shared internal admin mutation after verified DRWA context".
func TestQualSP234ProtectedManagerRoleGrant(t *testing.T) {
	roles := map[string][]byte{core.FungibleESDT: []byte(core.ESDTRoleLocalMint), core.NonFungibleESDTv2: []byte(core.ESDTRoleNFTCreate),
		core.SemiFungibleESDT: []byte(core.ESDTRoleNFTAddQuantity), core.MetaESDT: []byte(core.ESDTRoleNFTAddQuantity),
		core.DynamicNFTESDT: []byte(core.ESDTRoleNFTUpdate), core.DynamicSFTESDT: []byte(core.ESDTRoleNFTUpdate),
		core.DynamicMetaESDT: []byte(core.ESDTRoleNFTUpdate)}
	for family, role := range roles {
		e, context := qualSP234Contract(t, &publicClassifier{regulated: true}, family)
		admin := &qualSP234Admin{manager: qualSP234Manager}
		admin.onCarry = func() {
			// The record is saved before the context carries the shard effect.
			require.Len(t, qualSP234Record(t, e).SpecialRoles, 1, family)
		}
		require.NoError(t, e.drwaManagerSetSpecialRole(admin, qualSP234Token, qualSP234Holder, [][]byte{role}), family)
		token := qualSP234Record(t, e)
		require.Len(t, token.SpecialRoles, 1, family)
		require.Equal(t, qualSP234Holder, token.SpecialRoles[0].Address)
		require.Equal(t, [][]byte{role}, token.SpecialRoles[0].Roles)
		require.Equal(t, qualSP234Manager, token.OwnerAddress, "the manager does not change")
		require.Equal(t, 1, admin.verified)
		require.Equal(t, 1, admin.carried)
		require.Equal(t, drwaManagerSetSpecialRoleName, admin.operation)
		require.Equal(t, [][]byte{qualSP234Token, qualSP234Holder, role}, admin.arguments)
		require.Empty(t, context.outputAccounts, "no native role fan-out for a regulated token")
		require.Empty(t, context.logs)
	}
}

// Every other caller and every other state: refused, with the record, the
// outputs and the messages as they were.
func TestQualSP234ProtectedManagerRefusals(t *testing.T) {
	mint := [][]byte{[]byte(core.ESDTRoleLocalMint)}
	fault := errors.New("selected fault")
	var typedNil *qualSP234Admin
	cases := []struct {
		name       string
		classifier vm.DRWATokenClassifier
		admin      drwaManagerContext
		token      []byte
		address    []byte
		roles      [][]byte
		prepare    func(e *esdt, context *vmContext)
	}{
		{"no verified context", &publicClassifier{regulated: true}, nil, qualSP234Token, qualSP234Holder, mint, nil},
		{"typed-nil context", &publicClassifier{regulated: true}, typedNil, qualSP234Token, qualSP234Holder, mint, nil},
		{"context refuses the mutation", &publicClassifier{regulated: true}, &qualSP234Admin{manager: qualSP234Manager, verifyErr: fault}, qualSP234Token, qualSP234Holder, mint, nil},
		{"token managed by another address than the reserved manager", &publicClassifier{regulated: true}, &qualSP234Admin{manager: bytes.Repeat([]byte{9}, 32)}, qualSP234Token, qualSP234Holder, mint, nil},
		{"the shard effect cannot be carried", &publicClassifier{regulated: true}, &qualSP234Admin{manager: qualSP234Manager, carryErr: fault}, qualSP234Token, qualSP234Holder, mint, nil},
		{"node without the DRWA classifier", nil, &qualSP234Admin{manager: qualSP234Manager}, qualSP234Token, qualSP234Holder, mint, nil},
		{"ordinary token", &publicClassifier{regulated: false}, &qualSP234Admin{manager: qualSP234Manager}, qualSP234Token, qualSP234Holder, mint, nil},
		{"classification unavailable", &publicClassifier{classifyErr: fault}, &qualSP234Admin{manager: qualSP234Manager}, qualSP234Token, qualSP234Holder, mint, nil},
		{"unknown token", &publicClassifier{regulated: true}, &qualSP234Admin{manager: qualSP234Manager}, []byte("OTHER-0a1b2c"), qualSP234Holder, mint, nil},
		{"not a token identifier", &publicClassifier{regulated: true}, &qualSP234Admin{manager: qualSP234Manager}, []byte("x"), qualSP234Holder, mint, nil},
		{"no roles", &publicClassifier{regulated: true}, &qualSP234Admin{manager: qualSP234Manager}, qualSP234Token, qualSP234Holder, nil, nil},
		{"invalid target address", &publicClassifier{regulated: true}, &qualSP234Admin{manager: qualSP234Manager}, qualSP234Token, []byte("short"), mint, nil},
		{"role of another family", &publicClassifier{regulated: true}, &qualSP234Admin{manager: qualSP234Manager}, qualSP234Token, qualSP234Holder, [][]byte{[]byte(core.ESDTRoleNFTCreate)}, nil},
		{"role already held", &publicClassifier{regulated: true}, &qualSP234Admin{manager: qualSP234Manager}, qualSP234Token, qualSP234Holder, mint, func(e *esdt, _ *vmContext) {
			token, _ := e.getExistingToken(qualSP234Token)
			token.SpecialRoles = []*ESDTRoles{{Address: qualSP234Holder, Roles: mint}}
			_ = e.saveToken(qualSP234Token, token)
		}},
		{"record without a manager", &publicClassifier{regulated: true}, &qualSP234Admin{}, qualSP234Token, qualSP234Holder, mint, func(e *esdt, _ *vmContext) {
			token, _ := e.getExistingToken(qualSP234Token)
			token.OwnerAddress = nil
			_ = e.saveToken(qualSP234Token, token)
		}},
		{"another contract's context", &publicClassifier{regulated: true}, &qualSP234Admin{manager: qualSP234Manager}, qualSP234Token, qualSP234Holder, mint, func(e *esdt, context *vmContext) {
			// The same record under the other contract's address: only the
			// address check stands between the context and a mutation there.
			context.SetSCAddress(vm.ValidatorSCAddress)
			_ = e.saveToken(qualSP234Token, &ESDTDataV2{OwnerAddress: bytes.Clone(qualSP234Manager), TokenType: []byte(core.FungibleESDT), CanAddSpecialRoles: true})
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, context := qualSP234Contract(t, c.classifier, core.FungibleESDT)
			if c.prepare != nil {
				c.prepare(e, context)
			}
			before := bytes.Clone(context.storageUpdate[string(core.ESDTSCAddress)][string(qualSP234Token)])
			message := context.returnMessage
			err := e.drwaManagerSetSpecialRole(c.admin, c.token, c.address, c.roles)
			require.ErrorIs(t, err, errDRWAManager)
			require.Equal(t, before, context.storageUpdate[string(core.ESDTSCAddress)][string(qualSP234Token)], "the record is as it was")
			if other := context.storageUpdate[string(vm.ValidatorSCAddress)][string(qualSP234Token)]; other != nil {
				record := &ESDTDataV2{}
				require.NoError(t, e.marshalizer.Unmarshal(record, other))
				require.Empty(t, record.SpecialRoles, "nothing was mutated under another contract")
			}
			require.Empty(t, context.storageUpdate[string(core.ESDTSCAddress)][string(c.token)+"x"])
			require.Equal(t, message, context.returnMessage)
			require.Empty(t, context.outputAccounts)
			require.Empty(t, context.logs)
		})
	}
	// An unknown token leaves no record overlay of its own.
	e, context := qualSP234Contract(t, &publicClassifier{regulated: true}, core.FungibleESDT)
	require.Error(t, e.drwaManagerSetSpecialRole(&qualSP234Admin{manager: qualSP234Manager}, []byte("OTHER-0a1b2c"), qualSP234Holder, mint))
	_, exists := context.storageUpdate[string(core.ESDTSCAddress)]["OTHER-0a1b2c"]
	require.False(t, exists)
	require.True(t, (*qualSP234Admin)(nil).IsInterfaceNil())
}

// qualSP234Public lists every manager, ownership and conversion entry point
// of the ESDT system contract with arguments that name the token.
func qualSP234Public() map[string][][]byte {
	other := bytes.Repeat([]byte{8}, 32)
	mint := []byte(core.ESDTRoleLocalMint)
	return map[string][][]byte{
		"transferOwnership":            {qualSP234Token, other},
		"controlChanges":               {qualSP234Token, []byte(upgradable), []byte("true")},
		"updateTokenID":                {qualSP234Token},
		"changeSFTToMetaESDT":          {qualSP234Token, {18}},
		"changeToDynamic":              {qualSP234Token},
		"changeToMultiShardCreate":     {qualSP234Token},
		"setSpecialRole":               {qualSP234Token, qualSP234Holder, mint},
		"unSetSpecialRole":             {qualSP234Token, qualSP234Holder, mint},
		"transferNFTCreateRole":        {qualSP234Token, qualSP234Holder, other},
		"stopNFTCreate":                {qualSP234Token},
		"sendAllTransferRoleAddresses": {qualSP234Token},
		"setBurnRoleGlobally":          {qualSP234Token},
		"unsetBurnRoleGlobally":        {qualSP234Token},
		"freeze":                       {qualSP234Token, qualSP234Holder},
		"unFreeze":                     {qualSP234Token, qualSP234Holder},
		"wipe":                         {qualSP234Token, qualSP234Holder},
		"freezeSingleNFT":              {qualSP234Token, {1}, qualSP234Holder},
		"unFreezeSingleNFT":            {qualSP234Token, {1}, qualSP234Holder},
		"wipeSingleNFT":                {qualSP234Token, {1}, qualSP234Holder},
		"pause":                        {qualSP234Token},
		"unPause":                      {qualSP234Token},
		"mint":                         {qualSP234Token, {7}},
		core.BuiltInFunctionESDTBurn:   {qualSP234Token, {7}},
	}
}

// "every public manager/transferOwnership attempt denies"; AR-27: "Public
// updateTokenID denies after registration both before and after activation".
// The denial reads the classification only, which a registration sets in its
// own block and nothing ever clears, so it is the same before and after
// activation. Every caller is tried, the token's manager address included.
func TestQualSP234EveryPublicManagerAndConversionEntryPointDeniesARegulatedToken(t *testing.T) {
	entries := qualSP234Public()
	require.Len(t, entries, 23)
	for function, arguments := range entries {
		require.True(t, drwaPublicTokenMutation(function), function)
		for _, family := range []string{core.FungibleESDT, core.NonFungibleESDTv2, core.SemiFungibleESDT, core.DynamicNFTESDT} {
			for name, caller := range map[string][]byte{"the manager address": qualSP234Manager, "the issuer": bytes.Repeat([]byte{1}, 32),
				"a role holder": qualSP234Holder, "the ESDT system contract": core.ESDTSCAddress} {
				e, context := qualSP234Contract(t, &publicClassifier{regulated: true}, family)
				before := bytes.Clone(context.storageUpdate[string(core.ESDTSCAddress)][string(qualSP234Token)])
				input := getDefaultVmInputForFunc(function, arguments)
				input.CallerAddr, input.RecipientAddr, input.GasProvided = caller, core.ESDTSCAddress, 100000
				code := e.Execute(input)
				label := function + " by " + name + " on " + family
				require.Equal(t, vmcommon.UserError, code, label)
				require.Equal(t, "DRWA public operation denied", context.returnMessage, label)
				require.Equal(t, before, context.storageUpdate[string(core.ESDTSCAddress)][string(qualSP234Token)], label)
				require.Empty(t, context.outputAccounts, label)
				require.Empty(t, context.logs, label)
			}
		}
	}
}

// "Ordinary unregulated tokens retain native permissionless behavior": every
// one of those entry points gives the same code, message, record, outputs and
// logs for an ordinary token with the DRWA classifier installed as on a
// contract without it.
func TestQualSP234OrdinaryTokenKeepsEveryNativeEntryPoint(t *testing.T) {
	reached := 0
	for function, arguments := range qualSP234Public() {
		for _, family := range []string{core.FungibleESDT, core.NonFungibleESDT, core.SemiFungibleESDT} {
			run := func(classifier vm.DRWATokenClassifier) (vmcommon.ReturnCode, string, []byte, int, int) {
				e, context := qualSP234Contract(t, classifier, family)
				token, _ := e.getExistingToken(qualSP234Token)
				token.Upgradable, token.CanChangeOwner, token.CanPause, token.CanFreeze, token.CanWipe = true, true, true, true, true
				require.NoError(t, e.saveToken(qualSP234Token, token))
				input := getDefaultVmInputForFunc(function, arguments)
				input.CallerAddr, input.RecipientAddr, input.GasProvided = qualSP234Manager, core.ESDTSCAddress, 100000
				code := e.Execute(input)
				return code, context.returnMessage, bytes.Clone(context.storageUpdate[string(core.ESDTSCAddress)][string(qualSP234Token)]),
					len(context.outputAccounts), len(context.logs)
			}
			code, message, record, outputs, logs := run(nil)
			gotCode, gotMessage, gotRecord, gotOutputs, gotLogs := run(&publicClassifier{regulated: false})
			label := function + " on " + family
			require.Equal(t, code, gotCode, label)
			require.Equal(t, message, gotMessage, label)
			require.Equal(t, record, gotRecord, label)
			require.Equal(t, outputs, gotOutputs, label)
			require.Equal(t, logs, gotLogs, label)
			require.NotEqual(t, "DRWA public operation denied", gotMessage, label)
			if code == vmcommon.Ok {
				reached++
			}
		}
	}
	require.Greater(t, reached, 10, "the native operations do run for an ordinary token")
}
