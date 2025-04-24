// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package state

import (
	"maps"
	"fmt"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

// journalEntry is a modification entry in the state change journal that can be
// reverted on demand.
type journalEntry interface {
	// revert undoes the changes introduced by this journal entry.
	revert(*StateDB)

	// dirtied returns the Ethereum address modified by this journal entry.
	dirtied() *common.Address

	// copy returns a deep-copied journal entry.
	copy() journalEntry

	toString() string
}

type logJournalEntry struct {
	entry journalEntry
	reverted bool
}

func (l logJournalEntry) toString() string {
	entryString := l.entry.toString()
	if entryString != "" {
		if l.reverted {
			return entryString + " reverted"
		} else {
			return entryString
		}
	} else {
		return ""
	}
}

func (l logJournalEntry) copy() logJournalEntry {
	return logJournalEntry{
			entry: l.entry.copy(),
			reverted: l.reverted,
	}
}

func (ch *logJournalEntry) logRevert(s* StateDB) {
	ch.reverted = true
}

// journal contains the list of state modifications applied since the last state
// commit. These are tracked to be able to be reverted in the case of an execution
// exception or request for reversal.
type journal struct {
	zombieEntries map[common.Address]int // Arbitrum: number of createZombieChange entries for each address

	entries []journalEntry         // Current changes tracked by the journal
	dirties map[common.Address]int // Dirty accounts and the number of changes

	logEntries []logJournalEntry
	logDirties map[common.Address]int
	txLogEntries [][]logJournalEntry
	logOffset int
}

// newJournal creates a new initialized journal.
func newJournal() *journal {
	return &journal{
		zombieEntries: make(map[common.Address]int),
		// TODO: don't get rid of it yet
		dirties: make(map[common.Address]int),
		logDirties: make(map[common.Address]int),
	}
}

// append inserts a new modification entry to the end of the change journal.
func (j *journal) append(entry journalEntry) {
	// got getstate logs, only add to logEntries and increment offset
	switch entry.(type) {
	case getStateObjectEntry, getStorageEntry:
		j.logEntries = append(j.logEntries, logJournalEntry{entry: entry, reverted: false})
		j.logOffset++
	default:
		j.entries = append(j.entries, entry)
		j.logEntries = append(j.logEntries, logJournalEntry{entry: entry, reverted: false})
		if addr := entry.dirtied(); addr != nil {
			j.dirties[*addr]++
			j.logDirties[*addr]++
			// Arbitrum: also track the number of zombie changes
			if isZombie(entry) {
				// TODO: what do we do with zombie entries
				j.zombieEntries[*addr]++
			}
		}
	}
}

func (j *journal) findReverseOffset(idx int, prev int) (offset int) {
	offset = prev
	for i := idx+prev; i >= 0; i-- {
		if offset < 0 {
			panic("went negative trying to change offset")
		}
		// skip reverted entries and getstate entries because they don't exist in the 
		// actual journal
		_, getobjectok := (j.logEntries[i].entry).(getStateObjectEntry)
		_, getstorageok := (j.logEntries[i].entry).(getStorageEntry)
		if j.logEntries[i].reverted == true || getobjectok || getstorageok {
			offset--
		} else {
			return offset
		}
	}
	// couldn't find a place where there's no reverted that means everything in the journal was reverted so the offset should actually be 0
	if offset != 0 {
		panic(fmt.Sprintf("Everything reverted, but offset isn't 0. Is %v", offset))
	}
	if offset == prev {
		panic("findReverseOffset was called on an element that isn't reverted because offset is the same.")
	}

	return offset
}

func numGets(logEntries []logJournalEntry) int {
	total := 0
	for _, entry := range logEntries {
		switch (entry.entry).(type) {
		case getStateObjectEntry, getStorageEntry:
			total++
		default:
		}
	}
	return total
}

func noGetReverted(logEntries []logJournalEntry) bool {
	// check that no Get is ever reverted, because that doesn't make sense
	for _, entry := range logEntries {
		switch (entry.entry).(type) {
		case getStateObjectEntry, getStorageEntry:
			if entry.reverted {
				return false
			}
		default:
		}
	}
	return true
}

// revert undoes a batch of journalled modifications along with any reverted
// dirty handling too.
func (j *journal) revert(statedb *StateDB, snapshot int) {
	fmt.Println("\n\nReverting\n\n")
	log.Info("Journal", "len", len(j.entries))
	log.Info("Log entries", "len", len(j.logEntries), "offset", j.logOffset)

	offset := j.logOffset
	for i := len(j.entries) - 1; i >= snapshot; i-- {
		// if the current logEntry is reverted loop until to find an offset that isn't
		_, getobjectok := (j.logEntries[i+offset].entry).(getStateObjectEntry)
		_, getstorageok := (j.logEntries[i+offset].entry).(getStorageEntry)

		if j.logEntries[i+offset].reverted == true || getobjectok || getstorageok {
			offset = j.findReverseOffset(i, offset)
			_, getobjectok = (j.logEntries[i+offset].entry).(getStateObjectEntry)
			_, getstorageok = (j.logEntries[i+offset].entry).(getStorageEntry)
			// NOTE: the below commented out conditional is no longer valid because you can reverse because of gets rather than revertes so i+offset+1 doesn't always have to be reverted.
			//if !(j.logEntries[i+offset].reverted == false && j.logEntries[i+offset+1].reverted == true) || getobjectok || getstorageok {
			if !(j.logEntries[i+offset].reverted == false) || getobjectok || getstorageok {
				log.Info("Computed", "offset", offset, "idx", i)
				log.Info("SPecial cases", "gets", numGets(j.logEntries), "noGetReverted", noGetReverted(j.logEntries))
				panic(fmt.Sprintf("Offset compute is off. j[i+offset] = %v, j[i+offset+1] = %v, isGetObject=%v, isGetStorage=%v", j.logEntries[i+offset].reverted, j.logEntries[i+offset+1].reverted, getobjectok, getstorageok))
			}
		}

		// Undo the changes made by the operation
		j.entries[i].revert(statedb)
		// in log entries just mark them reverted
		j.logEntries[i+offset].logRevert(statedb)

		if j.logEntries[i+offset].reverted == false {
			panic("logRevert not changed actual object")
		}
		j.logOffset++

		// Drop any dirty tracking induced by the change
		// NOTE: anything we need to do here? 
		//		it's probably important to track this information to sanity check
		//		the collected data.
		if addr := j.entries[i].dirtied(); addr != nil {
			j.logDirties[*addr]--
			if j.dirties[*addr]--; j.dirties[*addr] == 0 {
				if j.logDirties[*addr] != 0 {
					panic(fmt.Sprintf("The real journal has all dirties 0 for addr=%v, but ours is %v", *addr, j.logDirties[*addr]))
				}
				delete(j.dirties, *addr)
				delete(j.logDirties, *addr)

				// Revert zombieEntries tracking
				// NOTE: we don't track zombies in our log
				if isZombie(j.entries[i]) {
					if j.zombieEntries[*addr]--; j.zombieEntries[*addr] == 0 {
						delete(j.zombieEntries, *addr)
					}
				}
			}
		}
	}
	j.entries = j.entries[:snapshot]
	fmt.Println("\n\nafter revert\n\n")
	log.Info("Journal", "len", len(j.entries))
	log.Info("Log entries", "len", len(j.logEntries), "offset", j.logOffset)
}

// dirty explicitly sets an address to dirty, even if the change entries would
// otherwise suggest it as clean. This method is an ugly hack to handle the RIPEMD
// precompile consensus exception.
func (j *journal) dirty(addr common.Address) {
	j.dirties[addr]++
	j.logDirties[addr]++
}

// length returns the current number of entries in the journal.
func (j *journal) length() int {
	return len(j.entries)
}

func (j *journal) logLength() int {
	return len(j.logEntries)
}

// copy returns a deep-copied journal.
func (j *journal) copy() *journal {
	entries := make([]journalEntry, 0, j.length())
	logEntries := make([]logJournalEntry, 0, j.logLength())
	for i := 0; i < j.length(); i++ {
		entries = append(entries, j.entries[i].copy())
	}
	for i := 0; i < j.logLength(); i++ {
		logEntries = append(logEntries, j.logEntries[i].copy())
	}
	return &journal{
		zombieEntries: maps.Clone(j.zombieEntries),

		entries: entries,
		dirties: maps.Clone(j.dirties),
		logEntries: logEntries,
		logDirties: maps.Clone(j.logDirties),
		logOffset: j.logOffset,
	}
}

type (
	// Changes to the account trie.
	createObjectChange struct {
		account *common.Address
	}

	// Changes to the account trie without being marked as dirty.
	createZombieChange struct {
		account *common.Address
	}

	// createContractChange represents an account becoming a contract-account.
	// This event happens prior to executing initcode. The journal-event simply
	// manages the created-flag, in order to allow same-tx destruction.
	createContractChange struct {
		account common.Address
	}

	selfDestructChange struct {
		account     *common.Address
		prev        bool // whether account had already self-destructed
		prevbalance *uint256.Int
	}

	// Changes to individual accounts.
	balanceChange struct {
		account *common.Address
		prev    *uint256.Int
	}
	nonceChange struct {
		account *common.Address
		prev    uint64
	}
	storageChange struct {
		account   *common.Address
		key       common.Hash
		prevvalue *common.Hash
	}
	codeChange struct {
		account            *common.Address
		prevcode, prevhash []byte
	}

	// Changes to other state values.
	refundChange struct {
		prev uint64
	}
	addLogChange struct {
		txhash common.Hash
	}
	addPreimageChange struct {
		hash common.Hash
	}
	touchChange struct {
		account *common.Address
	}

	// Changes to the access list
	accessListAddAccountChange struct {
		address *common.Address
	}
	accessListAddSlotChange struct {
		address *common.Address
		slot    *common.Hash
	}

	// Changes to transient storage
	transientStorageChange struct {
		account       *common.Address
		key, prevalue common.Hash
	}

	getStateObjectEntry struct {
		account	*common.Address
	}

	getStorageEntry struct {
		account	*common.Address
		key		*common.Hash
		value	*common.Hash
	}
)

const ad = "addr=%v"
const adK = "addr=%v, key=%v"
const adKV = "addr=%v, key=%v, val=%v" 

func ap(addr *common.Address) string {
	if addr == nil {
		return fmt.Sprintf("addr=nil")
	} else {
		return fmt.Sprintf("addr=%v", *addr)
	}
}

func vp(val *common.Hash) string {
	if val == nil {
		return fmt.Sprintf("val=nil")
	} else {
		return fmt.Sprintf("val=%v", *val)
	}
}

func kp(key *common.Hash) string {
	if key == nil {
		return fmt.Sprintf("key=nil")
	} else {
		return fmt.Sprintf("key=%v", *key)
	}
}

func ak(addr *common.Address, key *common.Hash) string {
	return ap(addr) + ", " + kp(key)
}

func akv(addr *common.Address, key *common.Hash, val *common.Hash) string {
	return ap(addr) + ", " + kp(key) + ", " + vp(val)
}
	

// getStateObjectEntry
func (ch getStateObjectEntry) revert(s *StateDB) {
}

func (ch getStateObjectEntry) dirtied() *common.Address {
	return nil
}

func (ch getStateObjectEntry) copy() journalEntry {
	return getStateObjectEntry{
			account: ch.account,
	}
}

func (ch getStateObjectEntry) Account() *common.Address {
	return ch.account
}


func (ch getStateObjectEntry) toString() string {
	return "getStateObject(" + ap(ch.account) + ")"
}

// getStorageEntry
func (ch getStorageEntry) toString() string {
	return "getStorage(" + akv(ch.account, ch.key, ch.value) + ")"
}
func (ch getStorageEntry) Account() *common.Address {
	return ch.account
}

func (ch getStorageEntry) Key() *common.Hash {
	return ch.key
}

func (ch getStorageEntry) Value() *common.Hash {
	return ch.value
}

func (ch getStorageEntry) revert(s *StateDB) {
}

func (ch getStorageEntry) dirtied() *common.Address {
	return nil
}

func (ch getStorageEntry) copy() journalEntry {
	return getStorageEntry{
			account: ch.account,
			key: ch.key,
			value: ch.value,
	}
}

// createObjectChange
func (ch createObjectChange) toString() string {
	return "createObjectChange(" + ap(ch.account) + ")"
}

func (ch createObjectChange) revert(s *StateDB) {
	delete(s.stateObjects, *ch.account)
}

func (ch createObjectChange) dirtied() *common.Address {
	return ch.account
}

func (ch createObjectChange) copy() journalEntry {
	return createObjectChange{
		account: ch.account,
	}
}

// createContractChange
func (ch createContractChange) toString() string {
	return "createContract(" + ap(&ch.account) + ")"
}

func (ch createContractChange) revert(s *StateDB) {
	s.getStateObject(ch.account).newContract = false
}

func (ch createContractChange) dirtied() *common.Address {
	return nil
}

func (ch createContractChange) copy() journalEntry {
	return createContractChange{
		account: ch.account,
	}
}

// selfDestructChange
func (ch selfDestructChange) toString() string {
	return "selfDestruct(" + ap(ch.account) + ", prevbalance=" + ch.prevbalance.String() + ")" 
}

func (ch selfDestructChange) revert(s *StateDB) {
	obj := s.getStateObject(*ch.account)
	if obj != nil {
		obj.selfDestructed = ch.prev
		obj.setBalance(ch.prevbalance)
	}
}

func (ch selfDestructChange) dirtied() *common.Address {
	return ch.account
}

func (ch selfDestructChange) copy() journalEntry {
	return selfDestructChange{
		account:     ch.account,
		prev:        ch.prev,
		prevbalance: new(uint256.Int).Set(ch.prevbalance),
	}
}

var ripemd = common.HexToAddress("0000000000000000000000000000000000000003")

// touchChange
func (ch touchChange) toString() string {
	return "touchChange(" + ap(ch.account) + ")"
}

func (ch touchChange) revert(s *StateDB) {
}

func (ch touchChange) dirtied() *common.Address {
	return ch.account
}

func (ch touchChange) copy() journalEntry {
	return touchChange{
		account: ch.account,
	}
}

// balanceChange
func (ch balanceChange) toString() string {
	return "balanceChange(" + ap(ch.account) + ", prev=" + ch.prev.String() + ")"
}

func (ch balanceChange) revert(s *StateDB) {
	s.getStateObject(*ch.account).setBalance(ch.prev)
}

func (ch balanceChange) dirtied() *common.Address {
	return ch.account
}

func (ch balanceChange) copy() journalEntry {
	return balanceChange{
		account: ch.account,
		prev:    new(uint256.Int).Set(ch.prev),
	}
}

// nonceChange
func (ch nonceChange) toString() string {
	return "nonceChange(" + ap(ch.account) + fmt.Sprintf(", prev=%v)",ch.prev)
} 

func (ch nonceChange) revert(s *StateDB) {
	s.getStateObject(*ch.account).setNonce(ch.prev)
}

func (ch nonceChange) dirtied() *common.Address {
	return ch.account
}

func (ch nonceChange) copy() journalEntry {
	return nonceChange{
		account: ch.account,
		prev:    ch.prev,
	}
}

// codeChange
func (ch codeChange) toString() string {
	return ""
}

func (ch codeChange) revert(s *StateDB) {
	s.getStateObject(*ch.account).setCode(common.BytesToHash(ch.prevhash), ch.prevcode)
}

func (ch codeChange) dirtied() *common.Address {
	return ch.account
}

func (ch codeChange) copy() journalEntry {
	return codeChange{
		account:  ch.account,
		prevhash: common.CopyBytes(ch.prevhash),
		prevcode: common.CopyBytes(ch.prevcode),
	}
}

// storageCahnge
func (ch storageChange) toString() string {
	return "storageChange(" + akv(ch.account, &ch.key, ch.prevvalue) + ")"
}

func (ch storageChange) revert(s *StateDB) {
	s.getStateObject(*ch.account).setState(ch.key, ch.prevvalue)
}

func (ch storageChange) dirtied() *common.Address {
	return ch.account
}

func (ch storageChange) copy() journalEntry {
	return storageChange{
		account:   ch.account,
		key:       ch.key,
		prevvalue: ch.prevvalue,
	}
}

// transientStorageChange
func (ch transientStorageChange) toString() string {
	return ""
} 

func (ch transientStorageChange) revert(s *StateDB) {
	s.setTransientState(*ch.account, ch.key, ch.prevalue)
}

func (ch transientStorageChange) dirtied() *common.Address {
	return nil
}

func (ch transientStorageChange) copy() journalEntry {
	return transientStorageChange{
		account:  ch.account,
		key:      ch.key,
		prevalue: ch.prevalue,
	}
}

// refundChange
func (ch refundChange) toString() string {
	return ""
}

func (ch refundChange) revert(s *StateDB) {
	s.refund = ch.prev
}

func (ch refundChange) dirtied() *common.Address {
	return nil
}

func (ch refundChange) copy() journalEntry {
	return refundChange{
		prev: ch.prev,
	}
}

// addLogChange
func (ch addLogChange) toString() string {
	return ""
}

func (ch addLogChange) revert(s *StateDB) {
	logs := s.logs[ch.txhash]
	if len(logs) == 1 {
		delete(s.logs, ch.txhash)
	} else {
		s.logs[ch.txhash] = logs[:len(logs)-1]
	}
	s.logSize--
}

func (ch addLogChange) dirtied() *common.Address {
	return nil
}

func (ch addLogChange) copy() journalEntry {
	return addLogChange{
		txhash: ch.txhash,
	}
}

// addPreimageChange
func (ch addPreimageChange) toString() string {
	return ""
}

func (ch addPreimageChange) revert(s *StateDB) {
	delete(s.preimages, ch.hash)
}

func (ch addPreimageChange) dirtied() *common.Address {
	return nil
}

func (ch addPreimageChange) copy() journalEntry {
	return addPreimageChange{
		hash: ch.hash,
	}
}

// accessListAddAccountChange
func (ch accessListAddAccountChange) toString() string {
	return ""
}

func (ch accessListAddAccountChange) revert(s *StateDB) {
	/*
		One important invariant here, is that whenever a (addr, slot) is added, if the
		addr is not already present, the add causes two journal entries:
		- one for the address,
		- one for the (address,slot)
		Therefore, when unrolling the change, we can always blindly delete the
		(addr) at this point, since no storage adds can remain when come upon
		a single (addr) change.
	*/
	s.accessList.DeleteAddress(*ch.address)
}

func (ch accessListAddAccountChange) dirtied() *common.Address {
	return nil
}

func (ch accessListAddAccountChange) copy() journalEntry {
	return accessListAddAccountChange{
		address: ch.address,
	}
}

// accessListAddSlotChange
func (ch accessListAddSlotChange) toString() string {
	return ""
}

func (ch accessListAddSlotChange) revert(s *StateDB) {
	s.accessList.DeleteSlot(*ch.address, *ch.slot)
}

func (ch accessListAddSlotChange) dirtied() *common.Address {
	return nil
}

func (ch accessListAddSlotChange) copy() journalEntry {
	return accessListAddSlotChange{
		address: ch.address,
		slot:    ch.slot,
	}
}
