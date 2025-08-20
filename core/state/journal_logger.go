package state

import (   
	"fmt"
    "encoding/json"
	"slices"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

type Set map[common.Address]bool
//type Set[K comparable] = map[K]bool

/// Journal stuff

type generic struct {
    Type string `json:"type"`
    Data json.RawMessage `json:"data"`
	Reverted bool
}

var createObjectChangeS string = "createObjectChange"
var createZombieChangeS string = "createZombieChange"
var createContractChangeS string = "createContractChange"
var selfDestructChangeS string = "selfDestructChange"
var balanceChangeS string = "balanceChange"
var nonceChangeS string = "nonceChange"
var storageChangeS string = "storageChange"
var codeChangeS string = "codeChange"
var refundChangeS string = "refundChange"
var addLogChangeS string = "addLogChange"
var touchChangeS string = "touchChange"
var accessListAddAccountChangeS string = "accessListAddAccountChange"
var accessListAddSlotChangeS string = "accessListAddSlotChange"
var transientStorageChangeS string = "transientStorageChange"
var getStateObjectEntryS string = "getStateObjectEntry"
var getStorageEntryS string = "getStorageEntryS"
var wasmActivationS string = "wasmActivation"
var CacheWasmS string = "CacheWasm"
var EvictWasmS string = "EvictWasm"


func (l LogJournalEntry) MarshalJSON() ([]byte, error) { switch entry := (l.Entry).(type) {
    case createObjectChange:
        d, err := entry.MarshalJSON()
        if err == nil {
            return json.Marshal(&generic{
                Type: createObjectChangeS,
                Data: d,
				Reverted: l.Reverted,
            })
        } else {
            //panic(err)
			return nil, err
        }
    case createZombieChange:
        d, err := entry.MarshalJSON()
        if err == nil {
            return json.Marshal(&generic{
                Type: createZombieChangeS,
                Data: d,
				Reverted: l.Reverted,
            })
        } else {
            //panic(err)
			return nil, err
        }
    case createContractChange:
        d, err := entry.MarshalJSON()
        if err == nil {
            return json.Marshal(&generic{
                Type: createContractChangeS,
                Data: d,
				Reverted: l.Reverted,
            })
        } else {
            //panic(err)
			return nil, err
        }
        return entry.MarshalJSON()
    case selfDestructChange:
        d, err := entry.MarshalJSON()
        if err == nil {
            return json.Marshal(&generic{
                Type: selfDestructChangeS,
                Data: d,
				Reverted: l.Reverted,
            })
        } else {
            //panic(err)
			return nil, err
        }
        return entry.MarshalJSON()
    case balanceChange:
        d, err := entry.MarshalJSON()
        if err == nil {
            return json.Marshal(&generic{
                Type: balanceChangeS,
                Data: d,
				Reverted: l.Reverted,
            })
        } else {
            //panic(err)
			return nil, err
        }
        return entry.MarshalJSON()
    case nonceChange:
        d, err := entry.MarshalJSON()
        if err == nil {
            return json.Marshal(&generic{
                Type: nonceChangeS,
                Data: d,
				Reverted: l.Reverted,
            })
        } else {
            //panic(err)
			return nil, err
        }
        return entry.MarshalJSON()
    case storageChange:
        d, err := entry.MarshalJSON()
        if err == nil {
            return json.Marshal(&generic{
                Type: storageChangeS,
                Data: d,
				Reverted: l.Reverted,
            })
        } else {
            //panic(err)
			return nil, err
        }
        return entry.MarshalJSON()
    case codeChange:
        d, err := entry.MarshalJSON()
        if err == nil {
            return json.Marshal(&generic{
                Type: codeChangeS,
                Data: d,
				Reverted: l.Reverted,
            })
        } else {
            //panic(err)
			return nil, err
        }
        return entry.MarshalJSON()
    case refundChange:
        d, err := entry.MarshalJSON()
        if err == nil {
            return json.Marshal(&generic{
                Type: refundChangeS,
                Data: d,
				Reverted: l.Reverted,
            })
        } else {
            //panic(err)
			return nil, err
        }
        return entry.MarshalJSON()
    case addLogChange:
        d, err := entry.MarshalJSON()
        if err == nil {
            return json.Marshal(&generic{
                Type: addLogChangeS,
                Data: d,
				Reverted: l.Reverted,
            })
        } else {
            //panic(err)
			return nil, err
        }
        return entry.MarshalJSON()
    case touchChange:
        d, err := entry.MarshalJSON()
        if err == nil {
            return json.Marshal(&generic{
                Type: touchChangeS,
                Data: d,
				Reverted: l.Reverted,
            })
        } else {
            //panic(err)
			return nil, err
        }
        return entry.MarshalJSON()
    case accessListAddAccountChange:
        d, err := entry.MarshalJSON()
        if err == nil {
            return json.Marshal(&generic{
                Type: accessListAddAccountChangeS,
                Data: d,
				Reverted: l.Reverted,
            })
        } else {
            //panic(err)
			return nil, err
        }
        return entry.MarshalJSON()
    case accessListAddSlotChange:
        d, err := entry.MarshalJSON()
        if err == nil {
            return json.Marshal(&generic{
                Type: accessListAddSlotChangeS,
                Data: d,
				Reverted: l.Reverted,
            })
        } else {
            //panic(err)
			return nil, err
        }
        return entry.MarshalJSON()
    case transientStorageChange:
        d, err := entry.MarshalJSON()
        if err == nil {
            return json.Marshal(&generic{
                Type: transientStorageChangeS,
                Data: d,
				Reverted: l.Reverted,
            })
        } else {
            //panic(err)
			return nil, err
        }
        return entry.MarshalJSON()
    case getStateObjectEntry:
        d, err := entry.MarshalJSON()
        if err == nil {
            return json.Marshal(&generic{
                Type: getStateObjectEntryS,
                Data: d,
				Reverted: l.Reverted,
            })
        } else {
            //panic(err)
			return nil, err
        }
        return entry.MarshalJSON()
    case getStorageEntry:
        d, err := entry.MarshalJSON()
        if err == nil {
            return json.Marshal(&generic{
                Type: getStorageEntryS,
                Data: d,
				Reverted: l.Reverted,
            })
        } else {
            //panic(err)
			return nil, err
        }
        return entry.MarshalJSON()
    case wasmActivation:
        d, err := entry.MarshalJSON()
        if err == nil {
            return json.Marshal(&generic{
                Type: wasmActivationS,
                Data: d,
				Reverted: l.Reverted,
            })
        } else {
            //panic(err)
			return nil, err
        }
        return entry.MarshalJSON()
    case CacheWasm:
        d, err := entry.MarshalJSON()
        if err == nil {
            return json.Marshal(&generic{
                Type: CacheWasmS,
                Data: d,
				Reverted: l.Reverted,
            })
        } else {
            //panic(err)
			return nil, err
        }
        return entry.MarshalJSON()
    case EvictWasm:
        d, err := entry.MarshalJSON()
        if err == nil {
            return json.Marshal(&generic{
                Type: EvictWasmS,
                Data: d,
				Reverted: l.Reverted,
            })
        } else {
            //panic(err)
			return nil, err
        }
        return entry.MarshalJSON()
    default:
        return nil, nil
    }
}

func (l *LogJournalEntry) UnmarshalJSON(b []byte) error {
    var out generic
    if err := json.Unmarshal(b, &out); err != nil {
        //panic(err)
		return err
    }

    //switch entry := (l.Entry).(type) {
    switch out.Type {
    case createObjectChangeS:
        var res createObjectChange
        if err := res.UnmarshalJSON(out.Data); err != nil {
            //panic(err)
			return err
        }
        l.Entry = res	
		l.Reverted = out.Reverted
    case createZombieChangeS:
        var res createZombieChange
        if err := res.UnmarshalJSON(out.Data); err != nil {
            //panic(err)
			return err
        }
        l.Entry = res
		l.Reverted = out.Reverted
    case createContractChangeS:
        var res createContractChange
        if err := res.UnmarshalJSON(out.Data); err != nil {
            //panic(err)
			return err
        }
        l.Entry = res
		l.Reverted = out.Reverted
    case selfDestructChangeS:
        var res selfDestructChange
        if err := res.UnmarshalJSON(out.Data); err != nil {
            //panic(err)
			return err
        }
        l.Entry = res
		l.Reverted = out.Reverted
    case balanceChangeS:
        var res balanceChange
        if err := res.UnmarshalJSON(out.Data); err != nil {
            //panic(err)
			return err
        }
        l.Entry = res
		l.Reverted = out.Reverted
    case nonceChangeS:
        var res nonceChange
        if err := res.UnmarshalJSON(out.Data); err != nil {
            //panic(err)
			return err
        }
        l.Entry = res
		l.Reverted = out.Reverted
    case storageChangeS:
        var res storageChange
        if err := res.UnmarshalJSON(out.Data); err != nil {
            //panic(err)
			return err
        }
        l.Entry = res
		l.Reverted = out.Reverted
    case codeChangeS:
        var res codeChange
        if err := res.UnmarshalJSON(out.Data); err != nil {
            //panic(err)
			return err
        }
        l.Entry = res
		l.Reverted = out.Reverted
    case refundChangeS:
        var res refundChange
        if err := res.UnmarshalJSON(out.Data); err != nil {
            //panic(err)
			return err
        }
        l.Entry = res
		l.Reverted = out.Reverted
    case addLogChangeS:
        var res addLogChange
        if err := res.UnmarshalJSON(out.Data); err != nil {
            //panic(err)
			return err
        }
        l.Entry = res
		l.Reverted = out.Reverted
    case touchChangeS:
        var res touchChange
        if err := res.UnmarshalJSON(out.Data); err != nil {
            //panic(err)
			return err
        }
        l.Entry = res
		l.Reverted = out.Reverted
    case accessListAddAccountChangeS:
        var res accessListAddAccountChange
        if err := res.UnmarshalJSON(out.Data); err != nil {
            //panic(err)
			return err
        }
        l.Entry = res
		l.Reverted = out.Reverted
    case accessListAddSlotChangeS:
        var res accessListAddSlotChange
        if err := res.UnmarshalJSON(out.Data); err != nil {
            //panic(err)
			return err
        }
        l.Entry = res
		l.Reverted = out.Reverted
    case transientStorageChangeS:
        var res transientStorageChange
        if err := res.UnmarshalJSON(out.Data); err != nil {
            //panic(err)
			return err
        }
        l.Entry = res
		l.Reverted = out.Reverted
    case getStateObjectEntryS:
        var res getStateObjectEntry
        if err := res.UnmarshalJSON(out.Data); err != nil {
            //panic(err)
			return err
        }
        l.Entry = res
		l.Reverted = out.Reverted
    case getStorageEntryS:
        var res getStorageEntry
        if err := res.UnmarshalJSON(out.Data); err != nil {
            //panic(err)
			return err
        }
        l.Entry = res
		l.Reverted = out.Reverted
    case wasmActivationS:
        var res wasmActivation
        if err := res.UnmarshalJSON(out.Data); err != nil {
            //panic(err)
			return err
        }
        l.Entry = res
		l.Reverted = out.Reverted
    case CacheWasmS:
        var res CacheWasm
        if err := res.UnmarshalJSON(out.Data); err != nil {
            //panic(err)
			return err
        }
        l.Entry = res
		l.Reverted = out.Reverted
    case EvictWasmS:
        var res EvictWasm
        if err := res.UnmarshalJSON(out.Data); err != nil {
            //panic(err)
			return err
        }
        l.Entry = res
		l.Reverted = out.Reverted
    default:
        return nil
    }
    return nil
}


func GetCreatedAccountsHashed(j [][]LogJournalEntry) map[common.Hash]bool {
	m := GetCreatedAccounts(j)
	out := make(map[common.Hash]bool)
	for k := range m {
		hashK := common.BytesToHash(trie.PublicHashKey(k.Bytes()))
		out[hashK] = true
	}
	return out
}

func GetCreatedKeys(j [][]LogJournalEntry) map[KeyKey]bool {
	finalSet := make(map[KeyKey]bool)
	var zeroVal common.Hash
	zeroVal.SetBytes(nil)

	//targeta := common.HexToAddress("0x52Aa899454998Be5b000Ad077a46Bbe360F4e497")
	//targetk := common.HexToHash("0xd943cec1dfc617bf9515058376abfab0217f98cce018735f02efd4abd3453ad8")

	for _, jn := range j {
		for _, e := range jn {
			switch entry := (e.Entry).(type) {
			case storageChange:
				if e.Reverted {
					continue
				}

				// if the storage slot goes from 0 to non-0 it was created
				//if entry.prevvalue.Cmp(zeroVal) == 0 || entry.newvalue.Cmp(zeroVal) != 0 {
				if entry.origvalue.Cmp(zeroVal) == 0 && entry.newvalue.Cmp(zeroVal) != 0 {
					// a storage slot went from not 0 to 0
					//if entry.account.Cmp(targeta) == 0 && entry.key.Cmp(targetk) == 0 {
					//	log.Debug("Created key", "addr", entry.account, "key", entry.key, "orgvalue", entry.origvalue, "prevalue", entry.prevvalue, "newvalue", entry.newvalue)
					//}
					finalSet[KeyKey{entry.account, entry.key}] = true
				} else if entry.origvalue.Cmp(zeroVal) == 0 {
					// implies orig was 0 and the newval is also 0 so it is no longer "created"
					if _, ok := finalSet[KeyKey{entry.account, entry.key}]; ok {
						delete(finalSet, KeyKey{entry.account, entry.key})
					}
				} else {
					// otherwise it's still 0
					//log.Debug("Storage sot not set", "addr", entry.account, "key", entry.key)
				}
			default:
			}
		}
	}
	return finalSet
}

// opposite of the above where it logs storage slot going
// from non-zero to zero
func GetDeletedKeys(j [][]LogJournalEntry) map[KeyKey]bool {
	finalSet := make(map[KeyKey]bool)
	for _, jn := range j {
		for _, e := range jn {
			switch entry := (e.Entry).(type) {
			case storageChange:
				var zeroVal common.Hash
				zeroVal.SetBytes(nil)

				//if entry.prevvalue.Cmp(zeroVal) != 0 || entry.newvalue.Cmp(zeroVal) == 0 {
				if entry.origvalue.Cmp(zeroVal) != 0 || entry.newvalue.Cmp(zeroVal) == 0 {
					// if the old value had something and the new one is set to 0
					log.Debug("Deleted key", "addr", entry.account, "key", entry.key)
					finalSet[KeyKey{entry.account, entry.key}] = true
				} else if entry.origvalue.Cmp(zeroVal) != 0 {
					if _, ok := finalSet[KeyKey{entry.account, entry.key}]; ok {
						delete(finalSet, KeyKey{entry.account, entry.key})
					}
				} else {
					log.Debug("Storage change not set to 0", "addr", entry.account, "key", entry.key)
				}
			default:
			}
		}
	}
	return finalSet
}


// given a journal return all the storage trie keys that were queried
// and returned 0 and are never set. This let's us validate that our collected
// data is capturing all keys and we can validate a transition from a prelog to
// a post log
func GetKeysAlwaysZero(j [][]LogJournalEntry) map[KeyKey]bool {
	finalSet := make(map[KeyKey]bool)
	for _, jn := range j {
		for _, e := range jn {
			switch entry := (e.Entry).(type) {
			case getStorageEntry:
				k := KeyKey{entry.account, entry.key}
				// we want to check what the return value was
				//if (common.Hash{}).Cmp(entry.value) == 0 {
				if entry.value.Cmp(common.Hash{}) == 0 {
					var zeroVal common.Hash
					zeroVal.SetBytes(nil)
					if entry.value.Cmp(zeroVal) != 0 {
						panic("comparison error")
					}
					finalSet[k] = true
				} else {
					_, exists := finalSet[k]
					if exists {
						// this means the account went from zero to not-zero so remove it
						delete(finalSet, k)
					}
				}
			case storageChange:
				var zeroVal common.Hash
				zeroVal.SetBytes(nil)

				k := KeyKey{entry.account, entry.key}
				if entry.prevvalue.Cmp(zeroVal) != 0 && entry.newvalue.Cmp(zeroVal) == 0 {
					// if the old value had something and the new one is set to 0
					if entry.newvalue.Cmp(common.Hash{}) != 0 {
						panic("comparison error")
					}
					//log.Debug("Deleted key", "addr", entry.account, "key", entry.key)
					//finalSet[k] = true
				} else {
					// implcit in this condition is that prevvalue and newvalue can't be
					// the same thing, therefore here it's clear that newvalue != 0
					_, exists := finalSet[k]
					if !exists {
						// it's changed to zero
						delete(finalSet, k)
					}
					//log.Debug("Storage change not set to 0", "addr", entry.account, "key", entry.key)
				}
			default:
			}
		}
	}
	return finalSet
}

// The emptys list holds all the accounts that were empty at the end of the corresponding 
// journal. This function should go through that list and filter out the ones that are 
// created again in the future and eventually commited into the trie. The function returns
// the real set of accounts deleted because they were empty and no longer exist.
// IMPORTANT: we need to make sure that this function only deals with empty deletes
// and nothing else or we might end up double counting things that are in the other
// maps of the log like createdAndDeleted or real deletes/creates
func GetEmptyDeletes(emptys [][]common.Address, l [][]LogJournalEntry) Set {
	if len(emptys) != len(l) {
		panic(fmt.Sprintf("Unequal number of journals. emtpys=%v, journal=%v", len(emptys), len(l)))
	}

	// the real empty set will be used by "empty" lists
	// that need to check whether this was empty deleted in a perviou
	// "empty" list
	realEmptys := make(Set)
	
	for i := 0; i < len(emptys); i++ {
		// use a temporary map because we want realEmptys to only be
		// the empty deletes in previous lists so we can search and delete
		// them if we see a createObjectChange in this list 
		emptyDeletesThisRound := make(Set)
		// We have to go in lock step with the corresponding journal
		// for each "empty" list. First get all the empties in this
		// list, then go through the journal. If we see a createObjectChange
		// for a 
		for _, addr := range emptys[i] {
			_, ok := emptyDeletesThisRound[addr]
			if ok {
				// should be seeing this twice!!
				panic(fmt.Sprintf("Two empty deletes in the same list: %v", addr))
			}
			// since emptys are processed at the END of the logging, 
			// they can only be invalidated by future "empty" lists
			emptyDeletesThisRound[addr] = true
		}

		// now go through the journal and see if there are any in realEmptys
		// that need to be deleted. We don't care about the selfDestructs
		// that occur because they aren't deletions due to being empty
		for _, e := range l[i] {
			switch entry := (e.Entry).(type) {
			case createObjectChange:
				// if this is a create for something empty in this round then ignore it
				if _, thisRound := emptyDeletesThisRound[entry.account]; thisRound {
					continue
				}
				// if this account was empty deleted in a previous iteration (i.e.
				// it is in realEmptys, then remove it from there it exists
				if _, deleted := realEmptys[entry.account]; deleted {
					delete(realEmptys, entry.account)
				}
			}
		}

		// put these deletes into the final set
		for addr := range emptyDeletesThisRound {
			realEmptys[addr] = true
		}
	}
	
	return realEmptys
}

func PrintLogJournal(j []LogJournalEntry) {
	for _, e := range j {
		fmt.Println(e.toString())
	}
}

func PrintJournal(j []journalEntry) {
	for _, e := range j {
		fmt.Println(e.toString())
	}
}

func PrintLogJournals(j [][]LogJournalEntry) {
	for _, journ := range j {
		PrintLogJournal(journ)
		//for _, e := range journ {
		//	fmt.Println(e.Entry.toString())
		//}
	}
}


// Determine which accounts were created in this transaction. We 
// need to be careful to check for create changes that were reverted.
func GetCreatedAccounts(j [][]LogJournalEntry) Set {
	accountsCreated := make(Set)
	for _, jn := range j {
		for _, e := range jn {
			switch entry := (e.Entry).(type) {
			case createObjectChange:
				// A create object change should be added to the map 
				// only if this entry wasn't reverted. 
				if e.Reverted {
					continue
				}
				// check that it wasn't created previously, that's anomalous
				_, ok := accountsCreated[entry.account]
				if ok {
					log.Error("Two un-reverted createObject changes to the same account", "addr", entry.account)
					panic("err")
				}
				accountsCreated[entry.account] = true
			case selfDestructChange:
				// it is important to only look at the selfDestructs that have a corresponding
				// createObjectChange, becaused we only care about created accounts
				// if the selfDestruct was reverted, then whereever the original
				// create change is, whether itself reverted or now, we leave it
				// alone.
				if e.Reverted {
					continue
				}

				_, createdInThisJournal := accountsCreated[entry.account]

				if createdInThisJournal {
					// just remove it from the accountsCreatedSet if it's there
					delete(accountsCreated, entry.account)
					continue
				} 
				// if it wasn't created in this set of journals then we don't really care
			default: continue
			}
		}

	}
	return accountsCreated
}

// Gets only the accounts that existed before this set of journals (i.e.
// are in the trie). Ignore the ones created here and deleted here because
// those don't change the trie.
func GetDeletedAccounts(j [][]LogJournalEntry) Set {
	// need the set of created accounts to filter them out of the 
	// accounts the function returns
	createdAccounts := GetCreatedAccounts(j)
	deletedAccounts := make(Set)
	// We don't care about the selfDestructs
	// that occur because they aren't deletions due to being empty
	for _, jn := range j {
		for _, e := range jn {
			switch entry := (e.Entry).(type) {
			case selfDestructChange:
				// We only care about this selfDestruct if it wasn't reverted
				// and it was for an account NOT created in this set of 
				// journals.
				_, wasCreated := createdAccounts[entry.account]
				_, alreadyDeleted := deletedAccounts[entry.account]
				if !wasCreated && !e.Reverted {
					if alreadyDeleted {
						panic(fmt.Sprintf("Two deletes to this same account: %v", entry.account))
					}
					deletedAccounts[entry.account] = true
				}					
			default:
			}
		}
	}
	return deletedAccounts
}


func isAccount(addr common.Address, rawNode []byte) bool {
	test := new(types.StateAccount)
	err := rlp.DecodeBytes(rawNode, test)
	if err != nil {
		log.Error("Couldn't decode state account in createObjectChange prelog", "addr", addr)
		return false
	}
	return true
}

func createObjectChangeAccess(addr common.Address, trieVal []byte, accounts map[common.Address][]common.Hash, accountNodes map[common.Hash][]byte) []common.Hash {
	pathHashes, _ := accounts[addr]
	rawNodeHash := pathHashes[0]
	rawNode, exists := accountNodes[rawNodeHash]
	if !exists {
		log.Error("account has path but no raw node", "addr", addr, "hash", rawNodeHash)
		panic("pre log error")
	}

	if !isAccount(addr, rawNode) {
		log.Error("Couldn't decode state account in createObjectChange prelog", "addr", addr)
		panic("pre log eror")
	}

	if trieVal != nil {
		// this means that this was deleted at some point in the future
		// but we do the same thing as before
		log.Error("Trie get of this didn't give a nil result", "addr", addr, "v", trieVal)
		panic("prelog error")
	}

	// shouldn't do any accesses for this
	return nil
}

func createContractChangeAccess(addr common.Address, trieVal []byte, accounts map[common.Address][]common.Hash, accountNodes map[common.Hash][]byte) []common.Hash {
	pathHashes, _ := accounts[addr]
	
	if len(pathHashes) == 1 {
		// same as createObjectChange above
		rawNodeHash := pathHashes[0]
		rawNode, exists := accountNodes[rawNodeHash]
		if !exists { 
			log.Error("createContractCahnge account path but no raw node", "addr", addr, "hash", rawNodeHash)
			panic("pre log error")
		} 

		if !isAccount(addr, rawNode) {
			log.Error("createContractChange couldn't decode account", "addr", addr, "hash", rawNodeHash)
			panic("pre log error")
		}

		if trieVal != nil {
			// this means that this was deleted at some point in the future
			// but we do the same thing as before
			//log.Info("Addr was deleted or is empty", "addr", addr)
			log.Error("createContractChange trie get of this didn't give a nil result", "addr", addr, "v", trieVal)
			panic("pre log error")
		}
		return nil
	} else if len(pathHashes) == 0 {
		log.Error("createContractChange not nill return ad no pathHashes", "addr", addr)
		panic("pre log error")
	} else { 
		if trieVal == nil {
			log.Error("createContract change v is nil but in trie", "addr", addr)
			panic("pre log error")
		}
		// log these accesses
		return copyReverse(pathHashes)
	}
}

func getStateObjectEntryAccess(addr common.Address, accounts map[common.Address][]common.Hash, accountNodes map[common.Hash][]byte) []common.Hash {
	pathHashes, _ := accounts[addr]
	return copyReverse(pathHashes)
}

func getStorageEntryAccess(addr common.Address, key common.Hash, keys map[KeyKey][]common.Hash, keyNodes map[common.Hash][]byte) []common.Hash {
	pathHashes, _ := keys[KeyKey{addr, key}]
	return copyReverse(pathHashes)
}

// This function iterates through all of the journals in the block, and goes
// through them in reverse order. Every key's path is stored in reverse order as
// the order of accesses. A key whose path shares nodes that have already been
// touched ignores those nodes and only stores the unique nodes.
func OrderAccesses(journals [][]LogJournalEntry, root common.Hash, accounts map[common.Address][]common.Hash, accountNodes map[common.Hash][]byte, keys map[KeyKey][]common.Hash, keyNodes map[common.Hash][]byte, t *trie.ValidatorTrie) []common.Hash {
	accesses := []common.Hash{}

	for i := len(journals)-1 ; i >= 0 ; i-- {
		journ := journals[i]
		for j := len(journ)-1 ; j >= 0 ; j-- {
			lentry := journ[j]
			switch logEntry := (lentry.Entry).(type) {
			case createObjectChange:
				// there is no trie entry here, only the get request should log the trie
				// here we only log the hash of this node
				addr := logEntry.account
				pathHashes, exists := accounts[addr]
				if !exists || len(pathHashes) != 1 {
					log.Error("Create change not in accounts", "addr", addr, "len", len(pathHashes))
					panic("Pre log error")
				}

				v, _ := t.GetWithPath(addr.Bytes())
				access := createObjectChangeAccess(addr, v, accounts, accountNodes)
				accesses = append(accesses, access...)

				log.Debug("createObjectEntry", "addr", addr)
			case createContractChange:
				// the same as above 
				addr := logEntry.account
				// the account must exist and the same as above
				_, exists := accounts[addr]
				if !exists {
					log.Error("create contract change doesn't exist", "addr", addr)
					panic("pre log error")
				}
				
				v, _ := t.GetWithPath(addr.Bytes())
				access := createContractChangeAccess(addr, v, accounts, accountNodes)
				accesses = append(accesses, access...)
				log.Debug("Create contract entry", "addr", addr)
			case getStateObjectEntry:
				// here we do everything and log it, this will give you a path even if the key doesn't exist
				addr := logEntry.account
				pathHashes, exists := accounts[addr]

				if len(pathHashes) == 0 || !exists {
					log.Error("Bad data for getStateObjectEntry", "addr", addr, "paths", len(pathHashes), "exists", exists)
					panic("prelog error")
				}
				access := getStateObjectEntryAccess(addr, accounts, accountNodes)
				accesses = append(accesses, access...)
			case getStorageEntry:
				// same as above but with KeyKey type
				addr := logEntry.account
				key := logEntry.key
				pathHashes, exists := keys[KeyKey{addr, key}]
				if !exists || len(pathHashes) == 0 {
					log.Error("bad data for getStorageEntry", "addr", addr, "paths", len(pathHashes), "exists", exists)
					panic("prelog error")
				}

				access := getStorageEntryAccess(addr, key, keys, keyNodes)
				accesses = append(accesses, access...)
			case storageChange:
				// for the preLog, storage changes don't matter beyong the trie nodes needed
				// to get the value before changing it, the only thing is if the value was 0 before
				// if it is a new storage entry, then there should be only one thing 
				addr := logEntry.account
				key := logEntry.key
				prevvalue := logEntry.prevvalue
				newvalue := logEntry.newvalue

				access := storageChangeAccess(addr, key, prevvalue, newvalue, keys, keyNodes)
				accesses = append(accesses, access...)
				//log.Info("storageChange")
			}
		}
	}
	return accesses
}

func storageChangeAccess(addr common.Address, key common.Hash, prevvalue common.Hash, newvalue common.Hash, keys map[KeyKey][]common.Hash, keyNodes map[common.Hash][]byte) []common.Hash {
	var zeroVal common.Hash
	zeroVal.SetBytes(nil)
	if prevvalue.Cmp(zeroVal) == 0 {
		pathHashes, _ := keys[KeyKey{addr, key}]
		if len(pathHashes) != 1 {
			log.Error("storage change rom nil and path isn't 1", "addr", addr, "key", key, "len", len(pathHashes))
			panic("pre log error")
		}
		// in this case though, there's nothing really to report
		return nil
	} else {
		// in this case, there is a get request that's already logged the whole path down
		return nil
	}
}

func copyReverse[T any](l []T) []T {
	ret := make([]T, len(l))
	copy(ret, l)
	slices.Reverse(ret)
	return ret
}

