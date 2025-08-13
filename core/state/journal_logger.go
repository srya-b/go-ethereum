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
	for _, jn := range j {
		for _, e := range jn {
			switch entry := (e.Entry).(type) {
			case storageChange:
				var zeroVal common.Hash
				zeroVal.SetBytes(nil)

				if entry.prevvalue.Cmp(zeroVal) == 0 || entry.newvalue.Cmp(zeroVal) != 0 {
					// a storage slot went from not 0 to 0
					log.Debug("Deleted key", "addr", entry.account, "key", entry.key)
					finalSet[KeyKey{entry.account, entry.key}] = true
				} else {
					log.Debug("Storage sot not set", "addr", entry.account, "key", entry.key)
				}
			default:
			}
		}
	}
	return finalSet
}


func GetDeletedKeys(j [][]LogJournalEntry) map[KeyKey]bool {
	finalSet := make(map[KeyKey]bool)
	for _, jn := range j {
		for _, e := range jn {
			switch entry := (e.Entry).(type) {
			case storageChange:
				var zeroVal common.Hash
				zeroVal.SetBytes(nil)

				if entry.prevvalue.Cmp(zeroVal) != 0 || entry.newvalue.Cmp(zeroVal) == 0 {
					// if the old value had something and the new one is set to 0
					log.Debug("Deleted key", "addr", entry.account, "key", entry.key)
					finalSet[KeyKey{entry.account, entry.key}] = true
				} else {
					log.Debug("Storage change not set to 0", "addr", entry.account, "key", entry.key)
				}
			default:
			}
		}
	}
	return finalSet
}

func GetDeletedAccounts(j [][]LogJournalEntry) map[common.Address]bool {
	finalSet := make(map[common.Address]bool)
	for _, jn := range j {
		for _, e := range jn {
			switch entry := (e.Entry).(type) {
			case createObjectChange:
				// if it is created again after destruct then log that
				_, ok := finalSet[entry.account]
				if ok {
					delete(finalSet, entry.account)
				}
			case selfDestructChange:
				finalSet[entry.account] = true
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
					log.Debug("Deleted key", "addr", entry.account, "key", entry.key)
					//finalSet[k] = true
				} else {
					// implcit in this condition is that prevvalue and newvalue can't be
					// the same thing, therefore here it's clear that newvalue != 0
					_, exists := finalSet[k]
					if !exists {
						// it's changed to zero
						delete(finalSet, k)
					}
					log.Debug("Storage change not set to 0", "addr", entry.account, "key", entry.key)
				}
			default:
			}
		}
	}
	return finalSet
}

func GetEmptyDeletes(emptys [][]common.Address, l [][]LogJournalEntry) map[common.Address]bool {
	if len(emptys) != len(l) {
		panic(fmt.Sprintf("Unequal number of journals. emtpys=%v, journal=%v", len(emptys), len(l)))
	}

	finalSet := make(map[common.Address]bool)
	for i := 0; i < len(emptys); i++ {
		cleared := make(map[common.Address]bool)
		// if there is an empty then we don't need to scan this journal
		for _, addr := range emptys[i] {
			if _, ok := finalSet[addr]; ok {
				panic(fmt.Sprintf("Double empty delete address %v", addr))
			}
			// which are deleted
			cleared[addr] = true
		}

		// iterate over the journal and ignore deletes
		for _, e := range l[i] {
			switch entry := (e.Entry).(type) {
			case createObjectChange:
				// if this is already in created then ignore it it is eventually deleted
				addr := entry.account
				if _, ok := cleared[addr]; ok {
					continue
				}
				if _, ok := finalSet[addr]; ok {
					// remove it
					delete(finalSet, addr)
				}
			default:
			}
		}
		
		// move cleared into finalSet
		for addr := range cleared {
			finalSet[addr] = true
		}
	}		
	return finalSet
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

func GetCreatedAccounts(j [][]LogJournalEntry) map[common.Address]bool {
	finalSet := make(map[common.Address]bool)
	for _, jn := range j {
		accountsCreated := make(map[common.Address]bool)
		accountsDeleted := make(map[common.Address]bool)
		for _, e := range jn {
			switch entry := (e.Entry).(type) {
			case createObjectChange:
				accountsCreated[entry.account] = true
			case selfDestructChange:
				_, ok := accountsCreated[entry.account]
				if ok {
					log.Debug("Deleting an account created in the same transaction", "addr", entry.account)
				}
				_, ok = finalSet[entry.account]
				if ok {
					log.Debug("Deleting an existing account", "addr", entry.account)
				}
				accountsDeleted[entry.account] = true
			default: continue
			}
		}
		for addr := range accountsCreated {
			finalSet[addr] = true
		}
		for addr := range accountsDeleted {
			_, ok := finalSet[addr]
			if !ok {
				log.Error("Detleding account not created", "addr", addr)
			} else {
				delete(finalSet, addr)
			}
		}
	}
	return finalSet
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
