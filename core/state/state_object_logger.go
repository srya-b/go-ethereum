package state

import (
    "fmt"
    "time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

func (s *stateObject) TryToGetTrie() {
    if s.trie == nil {
        log.Info("[Check] Trie is nil")
        tr := s.getPrefetchedTrie()
        if tr != nil {
            log.Info("[Check] prefetcher got a trie")
        } else {
            _, err := s.getTrieCustom()
            if err != nil {
                log.Error("[Check] Couldn't even get Trie", "Addr", s.address, "root", s.data.Root, "originStorage", s.originStorage, "dirty", s.dirtyStorage, "pending", s.pendingStorage)
                //panic(err)
            }
        }
    } else {
        log.Info("[Check] Trie exists", "itsHash", s.trie.Hash())
    }
}


func (s *stateObject) IsRootShortOrNil() bool {
	tr := s.getPrefetchedTrie()
	if tr != nil {
		// Prefetcher returned a live trie, swap it out for the current one
		//s.trie = tr
        return tr.IsRootShortOrNil()
	} else {
		// Fetcher not running or empty trie, fallback to the database trie
		var err error
		tr, err = s.getTrieCustom()
		if err != nil {
			s.db.setError(err)
            log.Error("Couldn't even get Trie", "Addr", s.address, "root", s.data.Root, "originStorage", s.originStorage, "dirty", s.dirtyStorage, "pending", s.pendingStorage)
			panic(err)
		}
        return tr.IsRootShortOrNil()
	}
    //return tr.IsRootShortOrNil()
}

func (s *stateObject) getTrieCustom() (Trie, error) {
    if s.trie == nil {
		tr, err := s.db.db.OpenStorageTrie(s.db.originalRoot, s.address, s.data.Root, s.db.trie)
		if err != nil {
			return nil, err
		}
        return tr, nil
	}
	return s.trie, nil
}

func (s *stateObject) GetStateLogged(key common.Hash) (bool, common.Hash, []common.Hash, [][]byte) {
	success, value, _, pathHashes, rawNodesOnPath, _ := s.getStateLogged(key)
	return success, value, pathHashes, rawNodesOnPath
}

// getState retrieves a value from the account storage trie and also returns if
// the slot is already dirty or not.
func (s *stateObject) getStateLogged(key common.Hash) (bool, common.Hash, common.Hash, []common.Hash, [][]byte, bool) {
	// If we have a dirty value for this state entry, return it
    // if the entry is dirty, then we return this only and no trie accesses are done.
    // The function calling this should interpret this as a live access because no
    // path information is given
    success, storageHash, pathHashes, rawNodesOnPath := s.GetCommittedStateLogged(key)
    if !success {
        return false, common.Hash{}, common.Hash{}, nil, nil, true
    }
	value, dirty := s.dirtyStorage[key]
	if dirty {
        //log.Info("getState dirty", "value", value, "key", key)
		return true, value, storageHash, nil, nil, true
	}
	// Otherwise return the entry's original value
    //storageHash, pathHashes, rawNodesOnPath := s.true, GetCommittedStateLogged(key)
    //log.Info("getState return", "key", key, "value", storageHash, "paths", len(pathHashes), "raw", len(rawNodesOnPath))
	return true, storageHash, storageHash, pathHashes, rawNodesOnPath, false
}

//func (s *stateObject) GetTrieStateLogged(key common.Hash) (common.Hash, []common.Hash, [][]byte) {
func (s *stateObject) GetTrieStateLogged(key common.Hash) (bool, common.Hash, []common.Hash, [][]byte) {
	if _, destructed := s.db.stateObjectsDestruct[s.address]; destructed {
		return true, common.Hash{}, nil, nil
	}
	var (
		//enc   []byte
		err   error
		value common.Hash
	)

    var tr Trie
    if s.trie == nil {
        log.Info("Trie to get prefetched trie")
	    tr = s.getPrefetchedTrie()
	    if tr == nil {
	    	// Fetcher not running or empty trie, fallback to the database trie
	    	var err error
	    	tr, err = s.getTrieCustom()
	    	if err != nil {
                log.Error("GetCommittedState getTrie error", "addr", s.address, "key", key, "root", s.data.Root) //"paths", len(pathHashes), "raw", len(rawNodesOnPath))
                log.Info("Error", "e", err)
                //panic(err)
	    		//s.db.setError(err)
                return false, common.Hash{}, nil, nil
	    		//return common.Hash{}, nil, nil
	    	}
	    }
    } else {
        tr = s.trie
    }
    log.Info("Get storage logged")
	val, pathHashes, rawNodesOnPath, err := tr.GetStorageLogged(s.address, key.Bytes())
    log.Info("Return")

	if err != nil {
        log.Info("[trielogged] GetTrieState getstorageerror", "addr", s.address, "key", key, "root", s.data.Root) //"paths", len(pathHashes), "raw", len(rawNodesOnPath))
        //panic(fmt.Sprintf("Err on get addr=%v, key=%v", s.address, key))
        log.Error(fmt.Sprintf("Err on get addr=%v, key=%v", s.address, key))
		//s.db.setError(err)
		return false, common.Hash{}, nil, nil
	}

	value.SetBytes(val[:])
	return true, value, pathHashes, rawNodesOnPath
}

func (s *stateObject) GetTrieStateLoggedPostUpdate(key common.Hash) (bool, common.Hash, []common.Hash, [][]byte) {
	if _, destructed := s.db.stateObjectsDestruct[s.address]; destructed {
		return true, common.Hash{}, nil, nil
	}
	var (
		//enc   []byte
		err   error
		value common.Hash
	)


    var tr Trie
    if s.trie == nil {
	    tr = s.getPrefetchedTrie()
	    if tr == nil {
	    	// Fetcher not running or empty trie, fallback to the database trie
	    	var err error
	    	tr, err = s.getTrieCustom()
	    	if err != nil {
                log.Info("[post] GetTrieState getTrie error", "addr", s.address, "key", key, "root", s.data.Root)
                log.Info("Error", "e", err)
                //panic(err)
	    		//s.db.setError(err)
	    		return false, common.Hash{}, nil, nil
	    	}
	    }
    } else {
        tr = s.trie
    }

	val, pathHashes, rawNodesOnPath, err := tr.GetStorageLogged(s.address, key.Bytes())

	if err != nil {
        log.Info("[post] GetTrieState getstorageerror", "addr", s.address, "key", key, "root", s.data.Root)
        //panic(fmt.Sprintf("Err on get addr=%v, key=%v", s.address, key))
        log.Error(fmt.Sprintf("Err on get addr=%v, key=%v", s.address, key))
		//s.db.setError(err)
		return false, common.Hash{}, nil, nil
	}
	value.SetBytes(val[:])
	//s.originStorage[key] = value
	return true, value, pathHashes, rawNodesOnPath
}

// GetCommittedState retrieves a value from the committed account storage trie.
// TODO: rebase
func (s *stateObject) GetCommittedStateLogged(key common.Hash) (bool, common.Hash, []common.Hash, [][]byte) {
	// If we have a pending write or clean cached, return that
    // NOTE: being in pending means we've already seen this key, and it was "finalised"
    // and it was moved from dirty to pending but not committed so don't need anything
    // extra here
	if value, pending := s.pendingStorage[key]; pending {
		return true, value, nil, nil
	}
    // NOTE: this means that it was read from the trie once and is unchanged
    // so we already have the trie path, don't need to save it again we can look
    // it up in previous data
	if value, cached := s.originStorage[key]; cached {
		return true, value, nil, nil
	}
	// If the object was destructed in *this* block (and potentially resurrected),
	// the storage has been cleared out, and we should *not* consult the previous
	// database about any storage values. The only possible alternatives are:

	//   1) resurrect happened, and new slot values were set -- those should
	//      have been handles via pendingStorage above.
	//   2) we don't have new values, and can deliver empty response back
    // TODO: what to do here
	if _, destructed := s.db.stateObjectsDestruct[s.address]; destructed {
        //s.originStorage[key] = common.Hash{}
		return true, common.Hash{}, nil, nil
	}
    s.db.StorageLoaded++
	start := time.Now()
    value, pathHashes, rawNodesOnPath, err := s.db.reader.StorageFromTrie(s.address, key)
	if err != nil {
        //panic(err)
		//s.db.setError(err)
        log.Error("GetCommittedState PANIC", "err", err)
		return false, common.Hash{}, nil, nil
	}
	s.db.StorageReads += time.Since(start)
    if s.db.prefetcher != nil && s.data.Root != types.EmptyRootHash {
        if err = s.db.prefetcher.prefetch(s.addrHash, s.origin.Root, s.address, nil, []common.Hash{key}, true); err != nil {
            log.Error("[CommittedStateLogged] Failed to prefetch storage slot.", "addr", s.address, "key", key, "err", err)
           }
    }
	s.originStorage[key] = value
    return true, value, pathHashes, rawNodesOnPath
}

// prior to SetState being called, GetState was first called so we already logged the path
// we want to log how the storage location changed, for this it would be useful to 
// store the previous value of the valueNode, log the current value of the valueNode 
// and the raw valueNode.
// TODO: the caller should asser that the prevHash received is in the current dictionary
// TODO: rebase
//func (s *stateObject) SetStateLogged(key, value common.Hash)  (bool, common.Hash, []common.Hash, [][]byte) {
//	// If the new value is the same as old, don't set. Otherwise, track only the
//	// dirty changes, supporting reverting all of it back to no change.
//    // we only care to have these variables to assert that they are nil if dirty
//	success, prev, origin, pathHashes, rawNodesOnPath, _ := s.getStateLogged(key)
//    if !success {
//        log.Error("SetStateLogged: getStateLogged PANIC")
//        return false, nil, nil, nil
//    }
//        
//	if prev == value {
//        // in a call to SetStateLogged, we've only called GetState on the accout not in the stateobject
//        // TODO: if prev == value == nil: nothing is happening
//        return prev, pathHashes, rawNodesOnPath
//        // TODO: do we say that it's dirty?
//	}
//
//    // setState doesn't do anything but update the live storage, nothing special to be done
//    s.db.journal.storageChange(s.address, key, prev, origin, value)
//	s.setState(key, value, origin)
//    return true, prev, pathHashes, rawNodesOnPath
//	//return types.EmptyCodeHash, types.EmptyCodeHash, nil
//}

// SetBalance sets the balance for the object, and returns the previous balance.
//func (s *stateObject) AddBalanceLogged(amount *uint256.Int, reason tracing.BalanceChangeReason) {
func (s *stateObject) AddBalanceLogged(amount *uint256.Int) uint256.Int {
	// EIP161: We must check emptiness for the objects such that the account
	// clearing (0,0,0 objects) can take effect.
	if amount.IsZero() {
		if s.empty() {
			s.touch()
		}
        return *(s.Balance())
	}
    return s.SetBalance(new(uint256.Int).Add(s.Balance(), amount))
}

func (s *stateObject) SetBalanceLogged(amount *uint256.Int) uint256.Int {
    prev := *s.data.Balance
    s.db.journal.balanceChange(s.address, s.data.Balance)
	s.setBalance(amount)
    return prev
}

