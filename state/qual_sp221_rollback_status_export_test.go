package state

// QualSP221Journalize appends a journal entry to the real store. Test only.
func (adb *AccountsDB) QualSP221Journalize(entry JournalEntry) {
	adb.mutOp.Lock()
	adb.journalize(entry)
	adb.mutOp.Unlock()
}

var _ RollbackStatusHandler = (*AccountsDB)(nil)
var _ RollbackStatusHandler = (*PeerAccountsDB)(nil)
