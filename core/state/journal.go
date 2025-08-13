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
	"fmt"
	"maps"
	"math/big"
	"slices"
	"sort"
	"bytes"
	"encoding/json"
	"strings"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
)

type revision struct {
	id           int
	journalIndex int

	// Arbitrum: track the total balance change across all accounts
	unexpectedBalanceDelta *big.Int
}

// journalEntry is a modification entry in the state change journal that can be
// reverted on demand.
type journalEntry interface {
	// revert undoes the changes introduced by this journal entry.
	revert(*StateDB)

	// dirtied returns the Ethereum address modified by this journal entry.
	dirtied() *common.Address

	// copy returns a deep-copied journal entry.
	copy() journalEntry

	deepCopy() journalEntry

	toString() string
	
	//MarshalJSON() ([]byte, error)
	//UnmarshalJSON(b []byte) error
}

type LogJournalEntry struct {
	Entry journalEntry
	Reverted bool
}


func (l LogJournalEntry) toString() string {
	entryString := l.Entry.toString()
	if entryString != "" {
		if l.Reverted {
			return entryString + " reverted"
		} else {
			return entryString + " confirmed"
		}
	} else {
		return ""
	}
}

func journalToString(l []journalEntry) string {
       var sb strings.Builder
       sb.WriteString("[\n")
       for i, item := range l {
               sb.WriteString(fmt.Sprintf("%d: %v", i, item.toString()))
               if i < len(l) - 1 {
                       sb.WriteString("\n")
               }
       }
       sb.WriteString("\n]")
       return sb.String()
}

func logJournalToString(j []LogJournalEntry) string {
       var sb strings.Builder
       for i, item := range j {
               sb.WriteString(fmt.Sprintf("%d: %v", i, item.toString()))
               if i < len(j) - 1 {
                       sb.WriteString("\n")
               }
       }
       sb.WriteString("\n]")
       return sb.String()
}


func copyLogJournal(l []LogJournalEntry) []LogJournalEntry {
	res := make([]LogJournalEntry, len(l))
	for i, entry := range l {
		res[i] = entry.copy()
	}
	return res
}

func copyLoggedJournals(l [][]LogJournalEntry) [][]LogJournalEntry {
	res := make([][]LogJournalEntry, len(l))
	for i, log := range l {
		res[i] = copyLogJournal(log)
	}
	return res
}

func addressCopy2d(l [][]common.Address) [][]common.Address {
	res := make([][]common.Address, len(l))
	for i, addrs := range l {
		entry := make([]common.Address, len(addrs))
		for j, a := range addrs {
			//entry[j] = make([]common.Address, len(a))
			//copy(entry[j], a.Bytes())
			entry[j].SetBytes(a.Bytes())	
		}
		res[i] = entry
	}
	return res
}


func (l LogJournalEntry) copy() LogJournalEntry {
	return LogJournalEntry{
			Entry: l.Entry.copy(),
			Reverted: l.Reverted,
	}
}

func (ch *LogJournalEntry) logRevert(s* StateDB) {
	ch.Reverted = true
}

// journal contains the list of state modifications applied since the last state
// commit. These are tracked to be able to be reverted in the case of an execution
// exception or request for reversal.
type journal struct {
	zombieEntries map[common.Address]int // Arbitrum: number of createZombieChange entries for each address

	entries []journalEntry         // Current changes tracked by the journal
	dirties map[common.Address]int // Dirty accounts and the number of changes

	validRevisions []revision
	nextRevisionId int
	// that the loggedOffset tells us how many entries in the 
	// journal correspond to our own getStateObject/getStorageEntry
	// entries or reverted entries that we keep in logged journals. 
	// entry journal[len(journal)-1] is either:
	//     * loggedJournal[len(journal)-1+offset] if it is not reverted
	//	   * or the highest entry before len(journal)-1+offset that is not reverted
	// these indices are only used to iterate through the journal (for revert)
	// or append and looking at the offset and the reverted entries makes it easy
	// to do
	logEntries []LogJournalEntry
	logDirties map[common.Address]int
	txLogEntries [][]LogJournalEntry
	logOffset int
	loggingFailure bool
	logState bool
}

// newJournal creates a new initialized journal.
func newJournal(loggingMode bool) *journal {
	return &journal{
		zombieEntries: make(map[common.Address]int),
		// TODO: don't get rid of it yet
		dirties: make(map[common.Address]int),
		logDirties: make(map[common.Address]int),
		logState: loggingMode,
	}
}

// reset clears the journal, after this operation the journal can be used anew.
// It is semantically similar to calling 'newJournal', but the underlying slices
// can be reused.
func (j *journal) reset() {
	j.entries = j.entries[:0]
	j.validRevisions = j.validRevisions[:0]
	clear(j.dirties)
	j.nextRevisionId = 0
}

// snapshot returns an identifier for the current revision of the state.
func (j *journal) snapshot(s *StateDB) int {
	id := j.nextRevisionId
	j.nextRevisionId++
	j.validRevisions = append(j.validRevisions, revision{id, j.length(), new(big.Int).Set(s.arbExtraData.unexpectedBalanceDelta)})
	return id
}

// revertToSnapshot reverts all state changes made since the given revision.
func (j *journal) revertToSnapshot(revid int, s *StateDB) {
	// Find the snapshot in the stack of valid snapshots.
	idx := sort.Search(len(j.validRevisions), func(i int) bool {
		return j.validRevisions[i].id >= revid
	})
	if idx == len(j.validRevisions) || j.validRevisions[idx].id != revid {
		panic(fmt.Errorf("revision id %v cannot be reverted", revid))
	}
	revision := j.validRevisions[idx]
	snapshot := revision.journalIndex
	s.arbExtraData.unexpectedBalanceDelta = new(big.Int).Set(revision.unexpectedBalanceDelta)

	// Replay the journal to undo changes and remove invalidated snapshots
	j.revert(s, snapshot)
	j.validRevisions = j.validRevisions[:idx]
}

// append inserts a new modification entry to the end of the change journal.
func (j *journal) append(entry journalEntry) {
	// got getstate logs, only add to logEntries and increment offset
	switch entry.(type) {
	case getStateObjectEntry, getStorageEntry, emptyDeleteEntry:
		if !j.loggingFailure {
			j.logEntries = append(j.logEntries, LogJournalEntry{Entry: entry.deepCopy(), Reverted: false})
			j.logOffset++
		}
	default:
		j.entries = append(j.entries, entry)
		j.logEntries = append(j.logEntries, LogJournalEntry{Entry: entry.deepCopy(), Reverted: false})
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

func (j *journal) findReverseOffset(idx int, prev int) (success bool, offset int) {
	offset = prev
	for i := idx+prev; i >= 0; i-- {
		if offset < 0 {
			//panic("findReverseOffset PANIC went negative trying to change offset")
			log.Error("findReverseOffset PANIC went negative trying to change offset")
			return false, offset
		}
		// skip reverted entries and getstate entries because they don't exist in the 
		// actual journal
		_, getobjectok := (j.logEntries[i].Entry).(getStateObjectEntry)
		_, getstorageok := (j.logEntries[i].Entry).(getStorageEntry)
		_, getemptyok := (j.logEntries[i].Entry).(emptyDeleteEntry)
		if j.logEntries[i].Reverted == true || getobjectok || getstorageok || getemptyok {
			offset--
		} else {
			log.Debug("Returning offset", fmt.Sprintf("log entry[%d+%d=%d", idx, offset, idx+offset), j.logEntries[i].toString())
			return true, offset
		}
	}
	// couldn't find a place where there's no reverted that means everything in the journal was reverted so the offset should actually be 0
	if offset != 0 {
		//panic(fmt.Sprintf("Everything reverted, but offset isn't 0. Is %v", offset))
		log.Error(fmt.Sprintf("Everything reverted, but offset isn't 0. Is %v", offset))
		return false, offset
	}
	if offset == prev {
		//panic("findReverseOffset was called on an element that isn't reverted because offset is the same.")
		log.Error("findReverseOffset was called on an element that isn't reverted because offset is the same.")
		return false, offset
	}

	return true, offset
}

func numGets(logEntries []LogJournalEntry) int {
	total := 0
	for _, entry := range logEntries {
		switch (entry.Entry).(type) {
		case getStateObjectEntry, getStorageEntry:
			total++
		default:
		}
	}
	return total
}

func noGetReverted(logEntries []LogJournalEntry) bool {
	// check that no Get is ever reverted, because that doesn't make sense
	for _, entry := range logEntries {
		switch (entry.Entry).(type) {
		case getStateObjectEntry, getStorageEntry:
			if entry.Reverted {
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
	var tempOffset int
	tempOffset = j.logOffset
    //var sb strings.Builder
    //if j.logState {
    //        //debug.PrintStack()
    //        log.Error(">>>>>> start reverting", "snapshot", snapshot, "len(journal)", len(j.entries))
    //        sb.WriteString("Logging failure? ")
    //        sb.WriteString(strconv.FormatBool(j.loggingFailure))
    //        sb.WriteString("\n")
    //        sb.WriteString("Num appends: ")
    //        sb.WriteString(strconv.Itoa(j.numAppends))
    //        sb.WriteString("\n")
    //        sb.WriteString("PRE DATA\n")
    //        sb.WriteString("Revert: preoffset: ")
    //        sb.WriteString(strconv.Itoa(j.logOffset))
    //        sb.WriteString("\n")
    //        sb.WriteString("Revert journal: ")
    //        sb.WriteString(journalToString(j.entries))
    //        sb.WriteString("\n")
    //        sb.WriteString("Revert logJournal: ")
    //        sb.WriteString(logJournalToString(j.logEntries))
    //        sb.WriteString("\n")
    //}
    log.Debug("Starting offset", "offset", tempOffset)
	for i := len(j.entries) - 1; i >= snapshot; i-- {
		if !j.loggingFailure {
			// if the current logEntry is reverted loop until to find an offset that isn't
			_, getobjectok := (j.logEntries[i+tempOffset].Entry).(getStateObjectEntry)
			_, getstorageok := (j.logEntries[i+tempOffset].Entry).(getStorageEntry)
			_, getemptyok := (j.logEntries[i+tempOffset].Entry).(emptyDeleteEntry)

			if j.logEntries[i+tempOffset].Reverted == true || getobjectok || getstorageok || getemptyok {
				success, offset := j.findReverseOffset(i, tempOffset)
				tempOffset = offset
				log.Debug("Revert", "returned oreverse offset", tempOffset)
				if success {
					_, getobjectok = (j.logEntries[i+tempOffset].Entry).(getStateObjectEntry)
					_, getstorageok = (j.logEntries[i+tempOffset].Entry).(getStorageEntry)
					_, getemptyok = (j.logEntries[i+tempOffset].Entry).(emptyDeleteEntry)
					// NOTE: the below commented out conditional is no longer valid because you can reverse because of gets rather than revertes so i+offset+1 doesn't always have to be reverted.
					//if !(j.logEntries[i+offset].reverted == false && j.logEntries[i+offset+1].reverted == true) || getobjectok || getstorageok {
					if !(j.logEntries[i+tempOffset].Reverted == false) || getobjectok || getstorageok || getemptyok {
						log.Debug("Computed", "offset", tempOffset, "idx", i)
						log.Debug("SPecial cases", "gets", numGets(j.logEntries), "noGetReverted", noGetReverted(j.logEntries))
						//panic(fmt.Sprintf("Offset compute is off. j[i+offset] = %v, j[i+offset+1] = %v, isGetObject=%v, isGetStorage=%v, isEmptyDelete=%v", j.logEntries[i+offset].Reverted, j.logEntries[i+offset+1].Reverted, getobjectok, getstorageok, getemptyok))
						log.Error(fmt.Sprintf("Offset compute is off. j[i+offset] = %v, j[i+offset+1] = %v, isGetObject=%v, isGetStorage=%v, isEmptyDelete=%v", j.logEntries[i+tempOffset].Reverted, j.logEntries[i+tempOffset+1].Reverted, getobjectok, getstorageok, getemptyok))
						j.loggingFailure = true
					}
				} else {
					j.loggingFailure = true	
				}
			}
		} 

		// Undo the changes made by the operation
		log.Debug("Reverting entry")
		j.entries[i].revert(statedb)
		log.Debug("Reverting", fmt.Sprintf("entry[%d]", i), j.entries[i].toString())
		switch tlog := (j.entries[i]).(type) {
		case createObjectChange:
			log.Debug("createObjectChange revert", "addr", tlog.account)
		}

		if !j.loggingFailure {
			// in log entries just mark them reverted
			j.logEntries[i+tempOffset].logRevert(statedb)
			log.Debug("Reverting", fmt.Sprintf("logEntry[%d+%d=%d]", i, tempOffset, i+tempOffset), j.logEntries[i+tempOffset].toString())
			if j.logEntries[i+tempOffset].Reverted == false {
				//panic("logRevert not changed actual object")
				log.Error("logRevert PANIC not changed actual object")
				j.loggingFailure = true
			}
			j.logOffset++
		} else {
			log.Debug("Journal revert logging failure")
		}

		// Drop any dirty tracking induced by the change
		// NOTE: anything we need to do here? 
		//		it's probably important to track this information to sanity check
		//		the collected data.
		if addr := j.entries[i].dirtied(); addr != nil {
			j.logDirties[*addr]--
			if j.dirties[*addr]--; j.dirties[*addr] == 0 {
				if !j.loggingFailure {
					if j.logDirties[*addr] != 0 {
						//panic(fmt.Sprintf("The real journal has all dirties 0 for addr=%v, but ours is %v", *addr, j.logDirties[*addr]))
						log.Error(fmt.Sprintf("The real journal has all dirties 0 for addr=%v, but ours is %v", *addr, j.logDirties[*addr]))
						j.loggingFailure = true
					}
				}
				delete(j.dirties, *addr)

				if !j.loggingFailure {
					delete(j.logDirties, *addr)
				}

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
    //if j.logState {
    //        sb.WriteString("POST DATA\n")
    //        sb.WriteString("Revert snapshot: ")
    //        sb.WriteString(strconv.Itoa(snapshot))
    //        sb.WriteString("\n")
    //        sb.WriteString("Num appends: ")
    //        sb.WriteString(strconv.Itoa(j.numAppends))
    //        sb.WriteString("\n")
    //        sb.WriteString("Post offset: ")
    //        sb.WriteString(strconv.Itoa(j.logOffset))
    //        sb.WriteString(" post journal: ")
    //        sb.WriteString(journalToString(j.entries))
    //        sb.WriteString("\n")
    //        sb.WriteString("Revert logjournal: ")
    //        sb.WriteString(logJournalToString(j.logEntries))
    //        //log.Info("Revert", "snapshot", snapshot, "post journal", journalToString(j.entries)

    //        //log.Info("Revert", "logJournal", logJournalToString(j.logEntries))
    //        fn := fmt.Sprintf("/home/admin/statedb-data/output-%v.txt", j.fnIdx)
    //        j.fnIdx++
    //        data := []byte(sb.String())
    //        err := os.WriteFile(fn, data, 0644)
    //        if err != nil {
    //                log.Error("Failed to write journals to file")
    //        }
    //        log.Info("dont reverting", "snapshot", snapshot)
    //}
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
	logEntries := make([]LogJournalEntry, 0, j.logLength())
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
		validRevisions: slices.Clone(j.validRevisions),
		nextRevisionId: j.nextRevisionId,
		logEntries: logEntries,
		logDirties: maps.Clone(j.logDirties),
		logOffset: j.logOffset,
		loggingFailure: j.loggingFailure,
	}
}

func (j *journal) logChange(txHash common.Hash) {
	j.append(addLogChange{txhash: txHash})
}

func (j *journal) createObject(addr common.Address) {
	j.append(createObjectChange{account: addr})
}

func (j *journal) createContract(addr common.Address) {
	j.append(createContractChange{account: addr})
}

func (j *journal) destruct(addr common.Address) {
	j.append(selfDestructChange{account: addr})
}

func (j *journal) storageChange(addr common.Address, key, prev, origin common.Hash, value common.Hash) {
	j.append(storageChange{
		account:   addr,
		key:       key,
		prevvalue: prev,
		origvalue: origin,
		newvalue: value,
	})
}

func (j *journal) transientStateChange(addr common.Address, key, prev common.Hash) {
	j.append(transientStorageChange{
		account:  addr,
		key:      key,
		prevalue: prev,
	})
}

func (j *journal) refundChange(previous uint64) {
	j.append(refundChange{prev: previous})
}

func (j *journal) balanceChange(addr common.Address, previous *uint256.Int) {
	j.append(balanceChange{
		account: addr,
		prev:    previous.Clone(),
	})
}

func (j *journal) setCode(address common.Address, prevCode []byte) {
	j.append(codeChange{
		account:  address,
		prevCode: prevCode,
	})
}

func (j *journal) nonceChange(address common.Address, prev uint64) {
	j.append(nonceChange{
		account: address,
		prev:    prev,
	})
}

func (j *journal) touchChange(address common.Address) {
	j.append(touchChange{
		account: address,
	})
	if address == ripemd {
		// Explicitly put it in the dirty-cache, which is otherwise generated from
		// flattened journals.
		j.dirty(address)
	}
}

func (j *journal) accessListAddAccount(addr common.Address) {
	j.append(accessListAddAccountChange{addr})
}

func (j *journal) accessListAddSlot(addr common.Address, slot common.Hash) {
	j.append(accessListAddSlotChange{
		address: addr,
		slot:    slot,
	})
}

func (j *journal) getState(addr common.Address) {
	j.append(getStateObjectEntry{
		account: addr,
	})
}

func (j *journal) emptyDelete(addr common.Address) {
	j.append(emptyDeleteEntry{
		account: addr,
	})
}

func (j *journal) getStorage(addr common.Address, key common.Hash, value common.Hash) {
	j.append(getStorageEntry{
		account: addr,
		key: key,
		value: value,
	})
}

type (
	// Changes to the account trie.
	createObjectChange struct {
		account common.Address
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
		account common.Address
	}

	// Changes to individual accounts.
	balanceChange struct {
		account common.Address
		prev    *uint256.Int
	}
	nonceChange struct {
		account common.Address
		prev    uint64
	}
	storageChange struct {
		account   common.Address
		key       common.Hash
		prevvalue common.Hash
		origvalue common.Hash
		newvalue common.Hash
	}
	codeChange struct {
		account  common.Address
		prevCode []byte
	}

	// Changes to other state values.
	refundChange struct {
		prev uint64
	}
	addLogChange struct {
		txhash common.Hash
	}
	touchChange struct {
		account common.Address
	}

	// Changes to the access list
	accessListAddAccountChange struct {
		address common.Address
	}
	accessListAddSlotChange struct {
		address common.Address
		slot    common.Hash
	}

	// Changes to transient storage
	transientStorageChange struct {
		account       common.Address
		key, prevalue common.Hash
	}

	getStateObjectEntry struct {
		account	common.Address
	}

	getStorageEntry struct {
		account	common.Address
		key		common.Hash
		value	common.Hash
	}

	emptyDeleteEntry struct {
		account common.Address
	}
)

const ad = "addr=%v"
const adK = "addr=%v, key=%v"
const adKV = "addr=%v, key=%v, val=%v" 

func ap(addr *common.Address) string {
	if addr == nil {
		return fmt.Sprintf("addr=nil")
	} else {
		//return fmt.Sprintf("addr=%v", *addr)
		return fmt.Sprintf("addr=%x...%x", (*addr)[:3], (*addr)[len(*addr)-3:])
	}
}

func vp(val *common.Hash) string {
	if val == nil {
		return fmt.Sprintf("val=nil")
	} else {
		//return fmt.Sprintf("val=%v", *val)
		return fmt.Sprintf("val=%x...%x", (*val)[:3], (*val)[len(*val)-3:])
	}
}

func kp(key *common.Hash) string {
	if key == nil {
		return fmt.Sprintf("key=nil")
	} else {
		//return fmt.Sprintf("key=%v", *key)
		return fmt.Sprintf("key=%x...%x", (*key)[:3], (*key)[len(*key)-3:])
	}
}

func ak(addr *common.Address, key *common.Hash) string {
	return ap(addr) + ", " + kp(key)
}

func akv(addr *common.Address, key *common.Hash, val *common.Hash) string {
	return ap(addr) + ", " + kp(key) + ", " + vp(val)
}

func akvp(addr *common.Address, key *common.Hash, prev *common.Hash, val *common.Hash) string {
	return ap(addr) + ", " + kp(key) + ", " + vp(prev) + ", " + vp(prev)
}

	
// emptyDeleteEntry
func (ch emptyDeleteEntry) revert(s *StateDB) {
}

func (ch emptyDeleteEntry) dirtied() *common.Address {
	return nil
}

func (ch emptyDeleteEntry) copy() journalEntry {
	return emptyDeleteEntry{
		account: ch.account,
	}
}

func (ch emptyDeleteEntry) deepCopy() journalEntry {
	var a common.Address
	a.SetBytes(ch.account[:])
	return emptyDeleteEntry{
		account: a,
	}
}

func (ch emptyDeleteEntry) Account() *common.Address {
	return &(ch.account)
}

func (ch emptyDeleteEntry) toString() string {
	return "emptyDeleteEntry(" + ap(&(ch.account)) + ")"
}

func (ch emptyDeleteEntry) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct{
		Account common.Address
	}{
		Account: ch.account,
	})
}

func (ch *emptyDeleteEntry) UnmarshalJSON(b []byte) error {
	a := &struct{
		Account common.Address
	}{}
	err := json.Unmarshal(b, a)
	ch.account = a.Account
	return err
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

func (ch getStateObjectEntry) deepCopy() journalEntry {
	var a common.Address
	a.SetBytes(ch.account[:])
	return getStateObjectEntry{
		account: a,
	}
}

func (ch getStateObjectEntry) Account() *common.Address {
	return &(ch.account)
}

func (ch getStateObjectEntry) toString() string {
	return "\tgetStateObject(" + ap(&(ch.account)) + ")"
}

func (ch getStateObjectEntry) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct{
		Account common.Address
	}{
		Account: ch.account,
	})
	//return json.Marshal(ch)
}

func (ch *getStateObjectEntry) UnmarshalJSON(b []byte) error {
	a := &struct{
		Account common.Address
	}{}
	err := json.Unmarshal(b, a)
	ch.account = a.Account
	return err
}


// getStorageEntry
func (ch getStorageEntry) toString() string {
	return "\tgetStorage(" + akv(&(ch.account), &(ch.key), &(ch.value)) + ")"
}
func (ch getStorageEntry) Account() *common.Address {
	return &(ch.account)
}

func (ch getStorageEntry) Key() *common.Hash {
	return &(ch.key)
}

func (ch getStorageEntry) Value() *common.Hash {
	return &(ch.value)
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

func (ch getStorageEntry) deepCopy() journalEntry {
	var a common.Address
	var k common.Hash
	var v common.Hash
	a.SetBytes((ch.account)[:])
	k.SetBytes((ch.key)[:])
	v.SetBytes((ch.value)[:])
	return getStorageEntry{
		account: a,
		key: k,
		value: v,
	}
}

func (ch getStorageEntry) MarshalJSON() ([]byte, error) {
	var a common.Address
	var k common.Hash
	var v common.Hash
	a.SetBytes(ch.account[:])
	k.SetBytes(ch.key[:])
	v.SetBytes(ch.value[:])
	return json.Marshal(&struct{
		Account common.Address
		Key common.Hash
		Value common.Hash
	}{
		Account: a,
		Key: k,
		Value: v,
	})
		
}
func (ch *getStorageEntry ) UnmarshalJSON(b []byte) error {
	a := &struct{
		Account common.Address
		Key common.Hash
		Value common.Hash
	}{}
	err := json.Unmarshal(b, a)
	ch.account = a.Account
	ch.key = a.Key
	ch.value = a.Value
	return err
}

// createObjectChange
func (ch createObjectChange) toString() string {
	return "createObjectChange(" + ap(&(ch.account)) + ")"
}

func (ch createObjectChange) revert(s *StateDB) {
	log.Debug("createObjectChange delete", "addr", ch.account)
	delete(s.stateObjects, ch.account)
}

func (ch createObjectChange) dirtied() *common.Address {
	return &ch.account
}

func (ch createObjectChange) copy() journalEntry {
	return createObjectChange{
		account: ch.account,
	}
}

func (ch createObjectChange) deepCopy() journalEntry {
	var a common.Address
	a.SetBytes(ch.account[:])
	return createObjectChange{
		account: a,
	}
}

func (ch createObjectChange) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct{
		Account common.Address
	}{
		Account: ch.account,
	})
}

func (ch *createObjectChange) UnmarshalJSON(b []byte) error {
	a := &struct{
		Account common.Address
	}{}
	err := json.Unmarshal(b, a)
	ch.account = a.Account
	return err
}


// createContractChange
func (ch createContractChange) toString() string {
	return "createContract(" + ap(&ch.account) + ")"
}

func (ch createContractChange) revert(s *StateDB) {
	//s.getStateObject(ch.account).newContract = false
	s.getStateObjectNoLog(ch.account).newContract = false
}

func (ch createContractChange) dirtied() *common.Address {
	return nil
}

func (ch createContractChange) copy() journalEntry {
	return createContractChange{
		account: ch.account,
	}
}

func (ch createContractChange) deepCopy() journalEntry {
	var a common.Address
	a.SetBytes(ch.account[:])
	return createContractChange{
		account: a,
	}
}

func (ch createContractChange) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct{
		Account common.Address
	}{
		Account: ch.account,
	})
}
func (ch *createContractChange) UnmarshalJSON(b []byte) error {
	a := &struct{
		Account common.Address
	}{}
	err := json.Unmarshal(b, a)
	ch.account = a.Account
	return err
}



// selfDestructChange
func (ch selfDestructChange) toString() string {
	return "selfDestruct(" + ap(&(ch.account)) + ")" 
}

func (ch selfDestructChange) revert(s *StateDB) {
	//obj := s.getStateObject(ch.account)
	obj := s.getStateObjectNoLog(ch.account)
	if obj != nil {
		obj.selfDestructed = false
	}
}

func (ch selfDestructChange) dirtied() *common.Address {
	return &ch.account
}

func (ch selfDestructChange) copy() journalEntry {
	return selfDestructChange{
		account: ch.account,
	}
}

func (ch selfDestructChange) deepCopy() journalEntry {
	var a common.Address
	a.SetBytes(ch.account[:])
	//pb := ch.prevbalance.Clone()
	return selfDestructChange{
		account: a,
		//prev: ch.prev,
		//prevbalance: pb,
	}
}

func (ch selfDestructChange) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct{
		Account common.Address
		//Prev bool
		//PrevBalance uint256.Int
	}{
		Account: ch.account,
		//Prev: ch.prev,
		//PrevBalance: *(ch.prevbalance),
	})
}

func (ch *selfDestructChange) UnmarshalJSON(b []byte) error {
	a := &struct{
		Account common.Address
		//Prev bool
		//PrevBalance uint256.Int
	}{}

	err := json.Unmarshal(b, a)
	ch.account = a.Account
	//ch.prev = a.Prev
	//ch.prevbalance = &(a.PrevBalance)
	return err
}



var ripemd = common.HexToAddress("0000000000000000000000000000000000000003")

// touchChange
func (ch touchChange) toString() string {
	return "touchChange(" + ap(&(ch.account)) + ")"
}

func (ch touchChange) revert(s *StateDB) {
}

func (ch touchChange) dirtied() *common.Address {
	return &ch.account
}

func (ch touchChange) copy() journalEntry {
	return touchChange{
		account: ch.account,
	}
}

func (ch touchChange) deepCopy() journalEntry {
	var a common.Address
	a.SetBytes(ch.account[:])
	return touchChange{
		account: a,
	}
}

func (ch touchChange) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct{
		Account common.Address
	}{
		Account: ch.account,
	})
}
func (ch *touchChange) UnmarshalJSON(b []byte) error {
	a := &struct{
		Account common.Address
	}{}
	err := json.Unmarshal(b, a)
	ch.account = a.Account
	return err
}



// balanceChange
func (ch balanceChange) toString() string {
	return "balanceChange(" + ap(&(ch.account)) + ", prev=" + ch.prev.String() + ")"
}

func (ch balanceChange) revert(s *StateDB) {
	//s.getStateObject(ch.account).setBalance(ch.prev)
	s.getStateObjectNoLog(ch.account).setBalance(ch.prev)
}

func (ch balanceChange) dirtied() *common.Address {
	return &ch.account
}

func (ch balanceChange) copy() journalEntry {
	return balanceChange{
		account: ch.account,
		prev:    new(uint256.Int).Set(ch.prev),
	}
}

func (ch balanceChange) deepCopy() journalEntry {
	var a common.Address
	a.SetBytes(ch.account[:])
	return balanceChange{
		account: a,
		prev: ch.prev.Clone(),
	}
}

func (ch balanceChange) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct{
		Account common.Address
		Prev uint256.Int
	}{
		Account: ch.account,
		Prev: *(ch.prev),
	})
}
func (ch *balanceChange) UnmarshalJSON(b []byte) error {
	a := &struct{
		Account common.Address
		Prev uint256.Int
	}{}
	err := json.Unmarshal(b, a)
	ch.account = a.Account
	ch.prev = &(a.Prev)
	return err
}


// nonceChange
func (ch nonceChange) toString() string {
	return "nonceChange(" + ap(&(ch.account)) + fmt.Sprintf(", prev=%v)",ch.prev)
} 

func (ch nonceChange) revert(s *StateDB) {
	//s.getStateObject(ch.account).setNonce(ch.prev)
	s.getStateObjectNoLog(ch.account).setNonce(ch.prev)
}

func (ch nonceChange) dirtied() *common.Address {
	return &ch.account
}

func (ch nonceChange) copy() journalEntry {
	return nonceChange{
		account: ch.account,
		prev:    ch.prev,
	}
}

func (ch nonceChange) deepCopy() journalEntry {
	var a common.Address
	a.SetBytes(ch.account[:])
	return nonceChange{
		account: a,
		prev: ch.prev,
	}
}

func (ch nonceChange) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct{
		Account common.Address
		Prev uint64
	}{
		Account: ch.account,
		Prev: ch.prev,
	})
}
func (ch *nonceChange) UnmarshalJSON(b []byte) error {
	a := &struct{
		Account common.Address
		Prev uint64
	}{}
	err := json.Unmarshal(b, a)
	ch.account = a.Account
	ch.prev = a.Prev
	return err
}


// codeChange
func (ch codeChange) toString() string {
	return "codeChange(" + ap(&(ch.account)) + ")"
}

func (ch codeChange) revert(s *StateDB) {
	//s.getStateObject(ch.account).setCode(crypto.Keccak256Hash(ch.prevCode), ch.prevCode)
	s.getStateObjectNoLog(ch.account).setCode(crypto.Keccak256Hash(ch.prevCode), ch.prevCode)
}

func (ch codeChange) dirtied() *common.Address {
	return &ch.account
}

func (ch codeChange) copy() journalEntry {
	return codeChange{
		account:  ch.account,
		prevCode: ch.prevCode,
	}
}

func (ch codeChange) deepCopy() journalEntry {
	var a common.Address
	a.SetBytes(ch.account[:])
	return codeChange{
		account: a,
		prevCode: bytes.Clone(ch.prevCode),
		//prevhash: bytes.Clone(ch.prevhash),
	}
}


func (ch codeChange) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct{
		Account common.Address
		PrevCode []byte
	}{
		Account: ch.account,
		PrevCode: bytes.Clone(ch.prevCode),
		//Prevhash: common.BytesToHash(common.CopyBytes(ch.prevhash)),
	})
		
}
func (ch *codeChange) UnmarshalJSON(b []byte) error {
	a := &struct{
		Account common.Address
		PrevCode []byte
	}{}
	err := json.Unmarshal(b, a)
	ch.account = a.Account
	//ch.prevhash = common.CopyBytes(a.Prevhash[:])
	ch.prevCode = bytes.Clone(a.PrevCode)
	return err
}


// storageCahnge
func (ch storageChange) toString() string {
	return "storageChange(" + akvp(&(ch.account), &(ch.key), &(ch.prevvalue), &(ch.origvalue)) + ")"
}

func (ch storageChange) revert(s *StateDB) {
	//s.getStateObject(ch.account).setState(ch.key, ch.prevvalue, ch.origvalue)
	s.getStateObjectNoLog(ch.account).setState(ch.key, ch.prevvalue, ch.origvalue)
}

func (ch storageChange) dirtied() *common.Address {
	return &ch.account
}

func (ch storageChange) copy() journalEntry {
	return storageChange{
		account:   ch.account,
		key:       ch.key,
		prevvalue: ch.prevvalue,
		origvalue: ch.origvalue,
		newvalue: ch.newvalue,
	}
}

func (ch storageChange) deepCopy() journalEntry {
	var a common.Address
	var k common.Hash
	var p common.Hash
	var o common.Hash
	var n common.Hash
	a.SetBytes(ch.account[:])
	k.SetBytes(ch.key[:])
	p.SetBytes(ch.prevvalue[:])
	o.SetBytes(ch.origvalue[:])
	n.SetBytes(ch.newvalue[:])
	//if ch.prevvalue == nil {
	//	p = p.SetBytes(nil)
	//} else {
	//	p = new(common.Hash)		
	//	p.SetBytes(ch.prevvalue[:])
	//}
	return storageChange{
		account: a,
		key: k,
		prevvalue: p,
		origvalue: o,
		newvalue: n,
	}
}


func (ch storageChange) MarshalJSON() ([]byte, error) {
	//var p common.Hash
	//if ch.prevvalue != nil {
	//	p.SetBytes(ch.prevvalue[:])
	//}
	return json.Marshal(&struct{
		Account common.Address
		Key common.Hash
		Prevalue common.Hash
		Origvalue common.Hash
		Newvalue common.Hash
	}{
		Account: ch.account,
		Key: ch.key,
		Prevalue: ch.prevvalue,
		Origvalue: ch.origvalue,
		Newvalue: ch.newvalue,
	})
}
func (ch *storageChange) UnmarshalJSON(b []byte) error {
	a := &struct{
		Account common.Address
		Key common.Hash
		Prevvalue common.Hash
		Origvalue common.Hash
		Newvalue common.Hash
	}{}
	err := json.Unmarshal(b, a)
	ch.account = a.Account
	ch.key = a.Key
	ch.prevvalue = a.Prevvalue
	ch.origvalue = a.Origvalue
	ch.newvalue = a.Newvalue
	return err
}


// transientStorageChange
func (ch transientStorageChange) toString() string {
	return "transientStorageChange(" + ap(&(ch.account)) + ")"
} 

func (ch transientStorageChange) revert(s *StateDB) {
	s.setTransientState(ch.account, ch.key, ch.prevalue)
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

func (ch transientStorageChange) deepCopy() journalEntry {
	var a common.Address
	var k common.Hash
	var p common.Hash
	a.SetBytes(ch.account[:])
	k.SetBytes(ch.key[:])
	p.SetBytes(ch.prevalue[:])
	return transientStorageChange{
		account: a,
		key: k,
		prevalue: p,
	}
}

func (ch transientStorageChange) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct{
		Account common.Address
		Key common.Hash
		Prevalue common.Hash
	}{
		Account: ch.account,
		Key: ch.key,
		Prevalue: ch.prevalue,
	})
}
func (ch *transientStorageChange) UnmarshalJSON(b []byte) error {
	a := &struct{
		Account common.Address
		Key common.Hash
		Prevalue common.Hash
	}{}
	err := json.Unmarshal(b, a)
	ch.account = a.Account
	ch.key.SetBytes(a.Key[:])
	ch.prevalue.SetBytes(a.Prevalue[:])
	return err
}


// refundChange
func (ch refundChange) toString() string {
	return "refundChange()"
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

func (ch refundChange) deepCopy() journalEntry {
	return refundChange{
		prev: ch.prev,
	}
}

func (ch refundChange) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct{
		Prev uint64
	}{
		Prev: ch.prev,
	})
}

func (ch *refundChange) UnmarshalJSON(b []byte) error {
	a := &struct{
		Prev uint64
	}{}
	err := json.Unmarshal(b, a)
	ch.prev = a.Prev
	return err
}


// addLogChange
func (ch addLogChange) toString() string {
	return "addLogChange()"
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

func (ch addLogChange) deepCopy() journalEntry {
	var h common.Hash
	h.SetBytes(ch.txhash[:])
	return addLogChange{
		txhash: h,
	}
}

func (ch addLogChange) MarshalJSON() ([]byte, error) {
	var h common.Hash
	h.SetBytes(ch.txhash[:])
	return json.Marshal(&struct{
		Txhash common.Hash
	}{
		Txhash: h,
	})	
}

func (ch *addLogChange) UnmarshalJSON(b []byte) error {
	a := &struct{
		Txhash common.Hash
	}{}
	err := json.Unmarshal(b, a)
	ch.txhash.SetBytes(a.Txhash[:])
	return err
}


// addPreimageChange
//func (ch addPreimageChange) toString() string {
//	return ""
//}
//
//func (ch addPreimageChange) dirtied() *common.Address {
//	return nil
//}
//
//func (ch addPreimageChange) revert(s *StateDB) {
//	delete(s.preimages, ch.hash)
//}
//
//func (ch addPreimageChange) copy() journalEntry {
//	return addPreimageChange{
//		hash: ch.hash,
//	}
//}
//
//func (ch addPreimageChange) deepCopy() journalEntry {
//	var h common.Hash
//	h.SetBytes(ch.hash[:])
//	return addPreimageChange{
//		hash: h,
//	}
//}
//
//func (ch addPreimageChange) MarshalJSON() ([]byte, error) {
//	return json.Marshal(ch)
//}
//
//func (ch *addPreimageChange) UnmarshalJSON(b []byte) error {
//	a := &struct{
//		Hash common.Hash
//	}{}
//	err := json.Unmarshal(b, a)
//	ch.hash = a.Hash
//	return err
//}


// accessListAddAccountChange
func (ch accessListAddAccountChange) toString() string {
	return "accessListAddAccountChange()"
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
	s.accessList.DeleteAddress(ch.address)
}

func (ch accessListAddAccountChange) dirtied() *common.Address {
	return nil
}

func (ch accessListAddAccountChange) copy() journalEntry {
	return accessListAddAccountChange{
		address: ch.address,
	}
}

func (ch accessListAddAccountChange) deepCopy() journalEntry {
	var a common.Address
	a.SetBytes(ch.address[:])
	return accessListAddAccountChange{
		address: a,
	}
}

func (ch accessListAddAccountChange) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct{
		Address common.Address
	}{
		Address: ch.address,
	})
}

func (ch *accessListAddAccountChange) UnmarshalJSON(b []byte) error {
	a := &struct{
		Address common.Address
	}{}
	err := json.Unmarshal(b, a)
	ch.address = a.Address
	return err
}


// accessListAddSlotChange
func (ch accessListAddSlotChange) toString() string {
	return "accessListAddSlotChange()"
}

func (ch accessListAddSlotChange) revert(s *StateDB) {
	s.accessList.DeleteSlot(ch.address, ch.slot)
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

func (ch accessListAddSlotChange) deepCopy() journalEntry {
	var a common.Address
	var s common.Hash
	a.SetBytes(ch.address[:])
	s.SetBytes(ch.slot[:])
	return accessListAddSlotChange{
		address: a,
		slot: s,
	}
}

func (ch accessListAddSlotChange) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct{
		Address common.Address
		Slot common.Hash
	}{
		Address: ch.address,
		Slot: ch.slot,
	})
}

func (ch *accessListAddSlotChange) UnmarshalJSON(b []byte) error {
	a := &struct{
		Address common.Address
		Slot common.Hash
	}{}
	err := json.Unmarshal(b, a)
	ch.address = a.Address
	ch.slot = a.Slot
	return err
}

