package trie

import (
	"os"
	"bytes"
	_"errors"
	"fmt"
	"math/rand"
	"encoding/binary"
	"strconv"
	"time"
	"sync"
	_"reflect"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	_"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-ethereum/rlp"
)

type CacheUpdate struct {
	NodesAccessed []common.Hash
	NodesChanged []common.Hash
	NodesAdded []common.Hash
	NodesDeleted []common.Hash
}

// store nodes
type ValidatorTrie struct {
	Root node
    Nodes map[common.Hash][]byte
	NodesChangedAndLost map[common.Hash][]byte
	NodesChangedAndLostPrefix map[common.Hash][]byte
	LostNodePrevHash map[common.Hash][]byte
	LostNodePrevHashPrefix map[common.Hash][]byte
	Pathmap map[string]common.Hash
	Mutex *sync.RWMutex
	NumDeletes int
	TrieKeys map[common.Hash][]byte
	KeyToHash map[common.Hash]common.Hash
	LastUpdate *CacheUpdate
}


func pathToTypes(origRoot node, path []int, preimages map[common.Hash][]byte) []string {
	if len(path) == 0 {
		return []string{}
	} else {
		switch n:= origRoot.(type) {
		case valueNode:
			r := []string{"valueNode"}
			rest := path[1:]  // path[0] assumed -1
			trieRoot, _, _ := getStorageTrie(n, preimages)	
			r = append(r, pathToTypes(trieRoot, rest, preimages)...)
			return r
		case *shortNode:
			return append([]string{"shortNode"}, pathToTypes(n.Val, path, preimages)...)
		case *fullNode:
			r := []string{"fullNode"}
			nextidx := path[0]
			rest := path[1:]
			r = append(r, pathToTypes(n.Children[nextidx], rest, preimages)...)
			return r
		case hashNode:
			// we only get here if the path allows it (i think)
			next, exists := NodeFromHashNode(n, preimages)
			r := []string{"hashNode"}
			if exists {
				r = append(r, pathToTypes(next, path, preimages)...)
			}
			return r
		default: panic("some other ode tf")
		}
	}
}

// remove origNode from the ValidatorTrie Nodes map and add newNode
func (t *ValidatorTrie) UpdateNodePreimage(origNode node, newNode node, newPreimages map[common.Hash][]byte) bool {
	// check that origNode is in the current trie
	origHash := HashNode(origNode)
	//log.Info("[UpdateNodePreImage] origHash.", "origHash", origHash)
	_, ok := t.Nodes[origHash]
	if !ok { 
		log.Info("\n\n**********************************************\n*************************************\ndoesn't exist", "orig", origHash)
		panic("duh")
		return false 
	}

	// check new node is in new preimages
	newHash := HashNode(newNode)
	//log.Info("[UpdateNodePreImage] newHash", "newHash", newHash)
	newNodeBytes, ok := newPreimages[newHash]
	if !ok { 
		log.Info("\n\n**********************************************\n*************************************\ndoesn't exist", "new", newHash)
		panic("duh")
		return false
	}

	log.Info("Replacing hashs", "old", origHash, "new", newHash)

	delete(t.Nodes, origHash)
	t.Nodes[newHash] = newNodeBytes
	return true	
}

func (t *ValidatorTrie) deleteRecursively(origRoot node, storage bool) int {
	switch n := origRoot.(type) {
	case valueNode:
		if storage {
			storageTrie, _, exists := getStorageTrie(n, t.Nodes)
			if exists {
				// child should be a fullNode or a hashNode
				switch child := storageTrie.(type) {
				case *fullNode:	
					// straight to fullNode do nothing else 
					return t.deleteRecursively(child, false)
				default: panic(fmt.Sprintf("Shouldn't be anything else. storageTrieRoopt(%T) = %v", storageTrie, storageTrie))
				}
			} else {
				// trie doesn't exist so just return the shortNode will delete
				return 0
			}
		} else { 	// we're in a storage trie so do nothing the shortNode will delete
			return 0
		}
	case *shortNode:
		// do something if there's a hashNode, otherwise just recurse
		return t.deleteRecursively(n.Val, storage)
	case *fullNode:
		// all children are hashNodes so delete them ALL
		r := 0
		for _, child := range(&n.Children) {
			if child != nil {
				r = r + t.deleteRecursively(child, storage)
			}
		}
		return r
	case hashNode:
		c, exists := NodeFromHashNode(n, t.Nodes)
		if exists {
			r := t.deleteRecursively(c, storage)
			_, exists := t.Nodes[common.BytesToHash(n)]
			if exists {
				delete(t.Nodes, common.BytesToHash(n))
				r = r + 1
			}
			return r
		} else {
			return 0
		}
	default: panic("shouldn't be deleting a valueNode, they don't exist like that")
	}
}

func (t *ValidatorTrie) deleteRecursivelyPrefix(origRoot node, prefix []byte, storage bool) int {
	switch n := origRoot.(type) {
	case valueNode:
		prefixH := common.BytesToHash(HashTrieKey(prefix))
		delete(t.TrieKeys, prefixH)
		t.LastUpdate.RecordDelete(prefix)
		if storage {
			storageTrie, _, exists := getStorageTrie(n, t.Nodes)
			if exists {
				// child should be a fullNode or a hashNode
				switch child := storageTrie.(type) {
				case *fullNode:	
					// straight to fullNode do nothing else 
					r := t.deleteRecursivelyPrefix(child, append(prefix, byte(1)), false)
					// delete the fullNode path
					delete(t.TrieKeys, common.BytesToHash(append(prefix, byte(1))))
					t.LastUpdate.RecordDelete(append(prefix, byte(1)))
					return r+1
				default: panic(fmt.Sprintf("Shouldn't be anything else. storageTrieRoopt(%T) = %v", storageTrie, storageTrie))
				}
			} else {
				// trie doesn't exist so just return the shortNode will delete
				return 1
			}
		} else { 	// we're in a storage trie so do nothing the shortNode will delete
			return 1
		}
	case *shortNode:
		// the hashNode pointing to this will delete it
		return t.deleteRecursivelyPrefix(n.Val, append(prefix, (n.Key)...), storage)
	case *fullNode:
		// all children are hashNodes so delete them ALL
		r := 0
		for i, child := range(&n.Children) {
			if child != nil {
				r = r + t.deleteRecursivelyPrefix(child, append(prefix, byte(i)), storage)
			}
		}
		return r
	case hashNode:
		c, exists := DecodeNodeFromPrefix(prefix, t.TrieKeys)
		if exists {
			r := t.deleteRecursivelyPrefix(c, prefix, storage)
			prefixH := common.BytesToHash(HashTrieKey(prefix))
			_, exists := t.TrieKeys[prefixH]
			if exists {
				delete(t.TrieKeys, prefixH)
				t.LastUpdate.RecordDelete(prefix)
				r = r + 1
			}
			return r
		} else {
			return 0
		}
	default: panic("shouldn't be deleting a valueNode, they don't exist like that")
	}
}

func traverseOddShortnode(origNode node, preimages map[common.Hash][]byte) []string {
	switch n := origNode.(type) {
	case valueNode: return []string{"value"}
	case *shortNode: return append([]string{"shortNode"}, traverseOddShortnode(n.Val, preimages)...)
	case *fullNode:
		r := whichNodesExist(n, preimages)
		numNotNil := 0
		for i := range(&n.Children) {
			if n.Children[i] != nil {
				numNotNil = numNotNil + 1
			}
		}
		//log.Info("fullnode", "node", n)
		return []string{fmt.Sprintf("fullNode (%d, %d)", len(r), numNotNil)}
	case hashNode:
		raw, exists := preimages[common.BytesToHash(n)]	
		if exists {
			actualNode, err := decodeNode(nil, raw)
			//actualNode, err := decodeNode(n, raw)
			if err != nil {
				panic("Failed to decode node from hashNode in addSubTrie")
			}
			return append([]string{"hashNode"}, traverseOddShortnode(actualNode, preimages)...)
		} else {
			return []string{"hashNode"}
		}
	default: panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// ASSUMPTION: shortNode children are always valueNodes
func sanityCheckShortNode(n *shortNode, preimages map[common.Hash][]byte) bool {
	switch (n.Val).(type) {
	case valueNode: return true
	case *fullNode: panic("fullNode directChild of shortNode")
	default: 
		traverseOddShortnode(n, preimages)
		//log.Info("sanityCheck paths", "path", p)
		return false
	}
}

// ASSUMPTION: fullNode children are always hashNodes or nil
func sanityCheckFullNode(n *fullNode) bool {
	for i,child := range(&n.Children) {
		if child != nil {
			switch (child).(type) {
			case valueNode, *fullNode:
				log.Info("Child of fullNode isn't a hashNode.", "node", HashNode(n), "idx", i)
				return false
			default: continue
			}
		}
	}
	return true
}

// return a list of indices of fullNode children which exist in the validator trie
func whichNodesExist(n *fullNode, preimages map[common.Hash][]byte) []int {
	r := []int{}
	for i, child := range &n.Children {
		if child != nil {
			switch n := (child).(type) {
			case hashNode:
				_, exists := preimages[common.BytesToHash(n)]
				if exists {
					r = append(r, i)
				}
			case *shortNode:
				r = append(r, i)
			default: panic(fmt.Sprintf("full nnode child=%v type=%T", n, n))
			}
		}
	}
	return r
}

func (t *ValidatorTrie) WhichNodesExist(n *fullNode) []int {
	return whichNodesExist(n, t.Nodes)
}


// check if two fullNodes have the same children
func SameChildren(n1 node, n2 node) bool {
	// only applies to fullNodes
	fn1, ok1 := n1.(*fullNode)
	fn2, ok2 := n2.(*fullNode)
	if !ok1 || !ok2 {
		panic("Can only compare fullNodes")
	}
	for i := range(&fn1.Children) {
		c1 := fn1.Children[i]
		c2 := fn2.Children[i]
		if c1 != nil && c2 != nil {
			if !(bytes.Equal(c1.(hashNode), c2.(hashNode))) {
				return false
			}
		} else if c1 != nil { 
			return false
		} else if c2 != nil { 
			return false 
		}
	}
	return true
}

func (t *ValidatorTrie) AddSubTrie(n node, preimages map[common.Hash][]byte) bool {
	return t.AddSubTrieFlag(n, preimages, false)
}

func (t *ValidatorTrie) AddStorageSubTrie(n node, preimages map[common.Hash][]byte) bool {
	return t.AddSubTrieFlag(n, preimages, true)
}


// add the subtrie starting ate `n` to the ValidatorTrie, called by `UpdateTrie` when a new branch
// is expanded in a new input
func (t *ValidatorTrie) AddSubTrieFlag(n node, preimages map[common.Hash][]byte, storage bool) bool {
	//log.Info("[ add ]", "n", n)
	target := common.HexToHash("26d33bcfea2608883d226c265acc749dd0807a5b089c46f307c338ce2ee31c03")
	switch n := n.(type) {
	case valueNode: 
		//panic("[AddSubTrie] never reach valueNode")
		//TODO: return true because we can reach here since shortNode.Val might not be a value
		//return true, the hashNode of the shortNode parent of this valueNode will be saved
		if storage {
			return true
		} else {
			storageTrie, acc, exists := getStorageTrie(n, preimages)
			//target := common.HexToHash("3b44b8c856a5f7ad22d92bb8a05b9a1d3cde48edaebdd4b73d229ad01709f7cc")
			//if target == acc.Root && exists {
			//	panic("we found it and exists addtrie")
			//}
			if exists {
				t.Nodes[acc.Root] = preimages[acc.Root]
				return t.AddStorageSubTrie(storageTrie, preimages)
			}
		}
		return true
	case *shortNode: 
		nh := HashNode(n)
		if nh == target {
			log.Info("Taret addition", "n", nh)
		}
		sanityCheckShortNode(n, preimages)
		//if !b { panic(fmt.Sprintf("[AddTrie] shortNode child isn't valueNode: %v", n.Val)) }
		return t.AddSubTrieFlag(n.Val, preimages, storage)
		//return true	// nothing to do tese aways lead to valueNodes
	case *fullNode:
		nh := HashNode(n)
		if nh == target {
			log.Info("Taret addition", "n", nh)
		}
		ok := sanityCheckFullNode(n)
		if !ok {
			panic(fmt.Sprintf("Failed to check fullNode. node=%v", n))
		}
		//log.Info("[AddTrie] adding a fullNode")
		res := true
		for _, child := range &n.Children {
			if child != nil {
				//log.Info("Trying child", "idx", i)
				r := t.AddSubTrieFlag(child, preimages, storage)
				if !r {
					res = false
				}
			}
		}
		return res
	case hashNode:
		if common.BytesToHash(n) == target {
			log.Info("[Hashnode] Taret addition", "n", n)
		}
		// only the hashNodes are saved to the Nodes map because
		// all nodes appear from hashNodes in the input we received 
		// see `sanityCheck...` functions
		realHash := common.BytesToHash(n)
		actualNodeRaw, exists := preimages[realHash]
		//log.Info("[AddTrie] hashNode exists", "hashNode", realHash)
		if exists {
			actualNode, err := decodeNode(nil, actualNodeRaw)
			//actualNode, err := decodeNode(realHash.Bytes(), actualNodeRaw)
			if err != nil {
				panic("Failed to decode node from hashNode in addSubTrie")
			}
			// add the hash to the trie
			t.Nodes[realHash] = preimages[realHash]
			return t.AddSubTrieFlag(actualNode, preimages, storage)
		} else {
			return true
		}
	default: panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

func (t *ValidatorTrie) AddSubTriePrefix(n node, prefix []byte, path []int, preimages map[common.Hash][]byte) bool {
	return t.AddSubTrieFlagPrefix(n, prefix, path, preimages, false)
}

func (t *ValidatorTrie) AddStorageSubTriePrefix(n node, prefix []byte, path []int, preimages map[common.Hash][]byte) bool {
	return t.AddSubTrieFlagPrefix(n, prefix, path, preimages, true)
}
// add the subtrie starting ate `n` to the ValidatorTrie, called by `UpdateTrie` when a new branch
// is expanded in a new input
func (t *ValidatorTrie) AddSubTrieFlagPrefix(n node, prefix []byte, path []int, preimages map[common.Hash][]byte, storage bool) bool {
	thisRoundKey := common.BytesToHash(HashTrieKey(prefix))
	//target := common.HexToHash("6a442855f44454c96c388b49ecbcc0d5d3a4599ac47b682b7bfd4b4a4443ac7a")
	target := common.HexToHash("855b1a4b41022ffa4dec392c7631cb2f8a9a0f1f5096c4b39eb0b18af2c83273")
	target2 := common.HexToHash("810062af9708664e564721bd7acc63fcb4e7a9b36eea16b0d4fa8a7da9a43097")
	//target := common.HexToHash("a03461e311e97202d37d1c6a5e8a1574999772717c662eb2428867a009e01f95")
	if thisRoundKey == target {
		log.Info("Here's the diff node AddSubTrie", "h", target, "prefix", fmt.Sprintf("%x", prefix), "node type", fmt.Sprintf("%T", n), "path", path)
		log.Info("the Node", "n", n)
	} else if thisRoundKey == target2 {
		log.Info("Here's the diff node AddSubTrie", "h", target2, "prefix", fmt.Sprintf("%x", prefix), "node type", fmt.Sprintf("%T", n), "path", path)
		log.Info("the Node", "n", n)
	}
	switch n := n.(type) {
	case valueNode: 
		if target == thisRoundKey {
			log.Info("It's a valueNode")
		}
		// add the valueNodes now too
		vnPrefixH := common.BytesToHash(HashTrieKey(prefix))
		t.TrieKeys[vnPrefixH] = n
		t.LastUpdate.KeyAdd(prefix)
		t.LastUpdate.AddAccess(prefix)
		if storage {
			return true
		} else {
			storageTrie, acc, exists := getStorageTrie(n, preimages)
			if exists {
				key := append(prefix, byte(1))
				keyH := HashTrieKey(append(prefix, byte(1)))
				//t.TrieKeys[common.BytesToHash(keyH)] = t.Nodes[acc.Root]
				t.TrieKeys[common.BytesToHash(keyH)] = preimages[acc.Root]
				t.LastUpdate.KeyAdd(key)
				t.LastUpdate.AddAccess(key)
				//if common.BytesToHash(keyH) == target {
				//	log.Info("\t\t adding the hash here", "path", path)
				//}
				return t.AddStorageSubTriePrefix(storageTrie, append(prefix, byte(1)), append(path, -1), preimages) 
			}
		}
		return true
	case *shortNode:
		if target == thisRoundKey {
			log.Info("It's a short Node")
		}
		// recurse here only	
		return t.AddSubTrieFlagPrefix(n.Val, append(prefix, (n.Key)...), path, preimages, storage) 
	case *fullNode:
		if target == thisRoundKey {
			log.Info("It's a fullNode")
		}
		// don't do anything here we should only be adding at the hashNode since we have to look up hashes
		//prefixKey := common.BytesToHash(HashTrieKey(prefix))
		//log.Info("[AddPrefix] full node", "prefix", prefixKey, "h", HashNode(n))
		res := true
		for i, child := range &n.Children {
			if child != nil {
				//if storage && (i == 1 || i == 15) {
				//	log.Info("[AddPrefix] idx", "i", i)
				//}
				//log.Info("adding from fullNode", "prefix", fmt.Sprintf("%x", prefix), "next byte", byte(i))
				r := t.AddSubTrieFlagPrefix(child, append(prefix, byte(i)), append(path, i), preimages, storage)
				if !r { res = false }
			}
		}
		return res
	case hashNode:
		// add to the trie here because we can get the raw bytes
		realHash := common.BytesToHash(n)
		actualNodeRaw, exists := preimages[realHash]
		//log.Info("[AddTrie] hashNode exists", "hashNode", realHash)
		if exists {
			actualNode, err := decodeNode(nil, actualNodeRaw)
			//actualNode, err := decodeNode(realHash.Bytes(), actualNodeRaw)
			if err != nil {
				panic("Failed to decode node from hashNode in addSubTrie")
			}
			// add the hash to the trie
			prefixH := HashTrieKey(prefix)
			//log.Info("Adding key", "p", common.BytesToHash(prefixH), "path", path)
			//log.Info("Adding prefix", "p", fmt.Sprintf("%x",prefix))
			t.TrieKeys[common.BytesToHash(prefixH)] = actualNodeRaw
			t.LastUpdate.KeyAdd(prefix)
			t.LastUpdate.AddAccess(prefix)
			return t.AddSubTrieFlagPrefix(actualNode, prefix, path, preimages, storage)
		} else {
			return true
		}
	default: panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}



// Safe update trie function (locks)
func (t *ValidatorTrie) TrieUpdate(newRoot node, preimages map[common.Hash][]byte) bool {
	t.Mutex.Lock()
	r := t.TrieUpdateUnsafe(newRoot, preimages)
	t.Mutex.Unlock()
	return r
}

func (t *ValidatorTrie) TrieUpdateUnsafe(newRoot node, preimages map[common.Hash][]byte) bool {
	return t.UpdateTrie(newRoot, t.Root, preimages, []int{}, true)
}

func (t *ValidatorTrie) TrieUpdatePrefix(newRoot node, preimages map[common.Hash][]byte) bool {
	t.Mutex.Lock()
	r := t.TrieUpdatePrefixUnsafe(newRoot, preimages)
	t.Mutex.Unlock()
	return r
}

func (t *ValidatorTrie) TrieUpdatePrefixUnsafe(newRoot node, preimages map[common.Hash][]byte) bool {
	r := t.UpdateTriePrefix(newRoot, t.Root, []byte{}, []byte{}, preimages, []int{}, true)
	// if the root has changed update it in the TrieKeys
	oldRootHash := HashNode(t.Root)
	newRootHash := HashNode(newRoot)
	if oldRootHash != newRootHash {
		rootPrefixKey := common.BytesToHash(HashTrieKey([]byte{}))
		log.Info("Updateiong the root", "old", oldRootHash, "new", newRootHash, "prefix", rootPrefixKey)
		t.TrieKeys[rootPrefixKey] = preimages[newRootHash]
	}
	return r
}


func getStorageTrie(n valueNode, preimages map[common.Hash][]byte) (node, *types.StateAccount, bool) {
	acc := new(types.StateAccount)
	err := rlp.DecodeBytes(n, acc)
	if err != nil { 
		//log.Info("decode storage", "node", n)
		return nilValueNode, acc, false
	}

	storageTrieRootRaw, exists := preimages[acc.Root]
	if exists {
		storageTrieRoot, err := decodeNode(nil, storageTrieRootRaw)
		//storageTrieRoot, err := decodeNode(acc.Root.Bytes(), storageTrieRootRaw)
		if err != nil { panic(err) }
		return storageTrieRoot, acc, true
	} else {
		return nilValueNode, acc, false
	}
}

func getStorageTriePrefix(n valueNode, key []byte, keymap map[common.Hash][]byte) (node, *types.StateAccount, bool) {
	acc := new(types.StateAccount)
	err := rlp.DecodeBytes(n, acc)
	if err != nil { 
		//log.Info("decode storage", "node", n)
		return nil, acc, false
	}

	h := HashTrieKey(append(key, byte(1)))
	storageTrieRootRaw, exists := keymap[common.BytesToHash(h)]
	if exists {
		storageTrieRoot, err := decodeNode(nil, storageTrieRootRaw)
		if err != nil { 
			log.Info("raw", "r", storageTrieRootRaw, "prefix", key, "key", fmt.Sprintf("%x", common.BytesToHash(h)))
			panic(err)
		}
		return storageTrieRoot, acc, true
	} else {
		return nil, acc, false
	}
}	

func shortNodeReplaceFull(oldn *fullNode, newn *shortNode, preimages map[common.Hash][]byte) bool {
	// check that full node had 2 children and one of them is the current short node key/value pair
	fnchildren := numChildrenOfFn(oldn, preimages)
	log.Info("fullNode replaced", "numchildren", fnchildren)

	// check that the short node that replaces it is DIRECT child of it
	// TODO: direct child isn't necessary
	log.Info("[fn->sn]", "newsn", newn)
	weFoundIt := false
	for i,child := range &oldn.Children {
		if child != nil {
			childhn, ok := child.(hashNode)
			if !ok { panic(fmt.Sprintf("not a hash node: %v", child)) }
			childHash := common.BytesToHash(childhn)
			raw, exists := preimages[childHash]
			if exists {
				newNode, err := decodeNode(nil, raw)
				//newNode, err := decodeNode(childHash.Bytes(), raw)
				if err != nil { panic(err) }
				switch n := newNode.(type) {
				case *shortNode:
					snhash := HashNode(n)
					newsnhash := HashNode(newn)
					log.Info("[fn->sn]", "idx", i, "child", newNode)
					if bytes.Equal(snhash.Bytes(), newsnhash.Bytes()) {
						weFoundIt = true
					} 
				default:
					log.Info("[fn->sn]", "default", child)
				}
			}
		}
	}
	return weFoundIt
}

// NOTE: helper for updateTrie
// ASSUME: only called for valueNodes that differ
func (t *ValidatorTrie) valueNodeRootChanged(oldn valueNode, newn valueNode, preimages map[common.Hash][]byte) bool {
	_, oldAcc, _ := getStorageTrie(oldn, t.Nodes)
	_, newAcc, _ := getStorageTrie(newn, preimages)
	sameNode := bytes.Equal(oldAcc.Root.Bytes(), newAcc.Root.Bytes())

	if !sameNode {
		return true
	} else {
		return false
	}
}

func (t *ValidatorTrie) valueNodeDeetsChanged(oldn valueNode, newn valueNode, preimages map[common.Hash][]byte) bool {
	_, oldAcc, _ := getStorageTrie(oldn, t.Nodes)
	_, newAcc, _ := getStorageTrie(newn, preimages)
	sameCodeHash := bytes.Equal(oldAcc.CodeHash, newAcc.CodeHash)
	if (oldAcc.Nonce < newAcc.Nonce) || (oldAcc.Balance != newAcc.Balance) || !sameCodeHash {
		return true
	} else {
		return false	
	}
}

func (t *ValidatorTrie) ValueNodeExists(n node, key []byte, pos int, path []int) bool {
	switch n := n.(type) {
	case valueNode:
		if pos >= len(key) {
			return true
		} else {
			log.Info("valueNode", "pos", pos, "len(key)", len(key), "path", path)
			return false 
		}
	case *shortNode:
		if len(key)-pos >= len(n.Key) {
			if !bytes.Equal(key[pos:pos+len(n.Key)], n.Key) {
				log.Info("key not the same as n.Key")
				return false
			} else {
				return t.ValueNodeExists(n.Val, key, pos+len(n.Key), path)
			}
		} else {
			log.Info("more of the key consumed than afvailable")
			return false
		}
	case *fullNode:
		nextIdx := key[pos]
		child := n.Children[nextIdx]
		if child != nil {
			log.Info("fuillNode", "key[:pos+1]", fmt.Sprintf("%x",key[:pos+1]), "nextidx", nextIdx, "path", path)
			log.Info("child", "h", child.(hashNode))
			next, err := DecodeNodeFromPrefix(key[:pos+1], t.TrieKeys)
			if !err {
				log.Info("error decoding next node fullNode")
				return false
			} else {
				return t.ValueNodeExists(next, key, pos+1, append(path, int(nextIdx)))
			}
		} else {
			log.Info("Intended child = nil")
			return false
		}
		//for i, child := range &n.Children {
		//	if child != nil {
		//		return t.ValueNodeExists(child, append(prefix, byte(i)), key)
		//	}
		//}
	case hashNode:
		panic("donn't ever get to hashNode")
	default: panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

func (t *ValidatorTrie) GetShortNodeChild(n *shortNode) (valueNode, bool) {
	switch c := (n.Val).(type) {
	case valueNode:
		return c, true
	case hashNode: return nil, false
	default: panic(fmt.Sprintf("shortNode child can't be of type %T", (n.Val))) 
	}
}

// key is the key in the shortNode that survived
func (t *ValidatorTrie) DeletedFullNodeChild(n *fullNode, prefix []byte, key []byte) (common.Hash, bool) {
	log.Info("deleted node", "n", n)
	r := []common.Hash{}
	
	// it could be the case that the node didn't exist before bt was still deleted
	matchlen := prefixLen(prefix, key)
	if matchlen != len(prefix) { panic("prefix isn't a prefix of key") }

	savedIdx := key[len(prefix)]
	log.Info("Saved idx", "idx", savedIdx)
	notSavedIdx := -1
	for i, child := range &n.Children {
		if child != nil && i != int(savedIdx) {
			notSavedIdx = i
			snChildPrefix := append(prefix, byte(i))
			childNode, err := DecodeNodeFromPrefix(snChildPrefix, t.TrieKeys)
			snChild, decodeErr := childNode.(*shortNode)
			if !err {
				if decodeErr {
					panic("Child isn't a short node")
				}

				// LAST UPDATE: delete the short Node and the valueNode from the cache
				vnPrefix := append(snChildPrefix, (snChild.Key)...)
				log.Info("[Delete] found a node to delete", "p", common.BytesToHash(HashTrieKey(vnPrefix)))
				r = append(r, common.BytesToHash(HashTrieKey(vnPrefix)))
			}
		} else if i == int(savedIdx) {
			snChildPrefix := append(prefix, byte(i))
			childNode, err := DecodeNodeFromPrefix(snChildPrefix, t.TrieKeys)
			log.Info("saved node in delted", "err", err, "child", childNode)
		}
	}
	if notSavedIdx == -1 || len(r) > 1 {
		log.Info("err", "notSavedIdx", notSavedIdx, "len(r)", len(r))
		panic("shit")
	} else {
		if len(r) == 1 {
			return r[0], true
		} else {
			return common.BytesToHash(HashTrieKey([]byte{})), false
		}
	}
	//totNotNil := 0
	//foundSaved := false
	//_, e := t.TrieKeys(common.BytesToHash(HashTrieKey(prefix)))
	//if !e {
	//	panic("the node itself doesn't exist")
	//}
	//for i, child := range &n.Children {
	//	if child != nil {
	//		totNotNil = totNotNil + 1
	//		snChildPrefix := append(prefix, byte(i))
	//		childNode, err := DecodeNodeFromPrefix(snChildPrefix, t.TrieKeys)
	//		snChild, decodeErr := childNode.(*shortNode)
	//		if !err {
	//			if decodeErr {
	//				panic("Child isn't a short node")
	//			}
	//			// is this the deleted one?
	//			vnPrefix := append(snChildPrefix, (snChild.Key)...)
	//			if len(vnPrefix) != len(key) {
	//				panic("Sommething screwey we arrived at different lengths")
	//			}
	//			if !bytes.Equal(vnPrefix, key) {
	//				// this is NOT the saved one
	//				r = append(r, common.Hash(HashTrieKey(vnPrefix)))
	//			} else {
	//				// this is the saved one, at least we found it
	//				foundSaved = true
	//			}
	//		}
	//	}
	//}
	//if foundSaved && len(r) == 1 {
	//	return r[0], true
	//} else {
	//	log.Info("res", "len(r)", len(r), "foundSaved", foundSaved)
	//	return common.BytesToHash(HashTrieKey([]byte{})), false
	//}
}

func ShortNodeToFullNode(oldSnKey []byte, vnKey []byte) ([]byte, []byte) {
	matchlen := prefixLen(oldSnKey, vnKey)
	if matchlen != len(oldSnKey) {
		panic("short node key isn't a prefix of the vnKey")
	}
	// vnKey[:matchlen] = oldSnKey
	fnIdx := vnKey[matchlen]
	newSnKey := append(oldSnKey, fnIdx)
	newSnExtKey := vnKey[matchlen+1:]
	return newSnKey, newSnExtKey
}

func ValueNodeToFullNode(prefix []byte, oldSnKey []byte, newSnKey []byte, valNodeKey []byte) ([]byte, []byte) {
	matchlen := prefixLen(oldSnKey, newSnKey)
	if matchlen != len(newSnKey) {
		panic(fmt.Sprintf("New sn key should be a prefix of oldSnkey: old=%x, new=%x", oldSnKey, newSnKey))
	}

	prefixMatchLen := prefixLen(prefix, valNodeKey)
	if prefixMatchLen != len(prefix) {
		panic("wrong")
	}
	
	if !bytes.Equal( append(newSnKey, oldSnKey[matchlen]), valNodeKey[prefixMatchLen:prefixMatchLen+matchlen+1]) {
		panic(fmt.Sprintf("matchlen = %v\n newSnKey = %x\n oldSnKey[matchlen] = %x\n valNodeKey = %x", matchlen, newSnKey, oldSnKey[matchlen], valNodeKey))
	}

	// the updates snPrefix should be valNodeKey[matchlen]
	log.Info("matchlen", "n", fmt.Sprintf("%x", valNodeKey[matchlen-1:matchlen+2]))
	fnIdx := oldSnKey[matchlen]
	log.Info("fnidx", "n", fnIdx)
	rSnKey := append(prefix, newSnKey...)
	rSnKey = append(rSnKey, fnIdx)
	rSnExtKey := valNodeKey[prefixMatchLen+matchlen+1:]
	return rSnKey, rSnExtKey
}

func LeadsToFullNode(n hashNode, preimages map[common.Hash][]byte, key []byte) (*fullNode, bool) {
	raw, exists := preimages[common.BytesToHash(n)]
	if !exists {
		log.Info("[LeadsToFullNode] hashNode not in preimages")
		return nil, false
	}

	// decode the fullNode
	nextNode, err := decodeNode(nil, raw)
	if err != nil {
		log.Info("[LeadsToFullNode] can't decode raw node")
		return nil, false
	}

	switch fn := nextNode.(type) {
	case *fullNode: return fn, true
	default: 
		log.Info("[LeadsToFullNode] doesn't decode to a fullnode", "type", fmt.Sprintf("%T",fn))
		return nil, false
	}
}

func (t *ValidatorTrie) UpdateTriePrefix(newRoot node, oldRoot node, oldPrefix []byte, newPrefix []byte, preimages map[common.Hash][]byte, path []int, storage bool) bool {
	thisRoundNewKey := common.BytesToHash(HashTrieKey(newPrefix))
	thisRoundOldKey := common.BytesToHash(HashTrieKey(oldPrefix))
	//target := common.HexToHash("6a442855f44454c96c388b49ecbcc0d5d3a4599ac47b682b7bfd4b4a4443ac7a")
	target := common.HexToHash("43855364b4a20a9c6d82e9096e6c742b31d63166d4fdf8cc57056f7e1b5b4540")
	if thisRoundNewKey == target {
		log.Info("Here's the diff node new key", "h", target)
	} else if target == thisRoundOldKey {
		log.Info("Here's the diff node old key", "h", target)
	}
	switch n := newRoot.(type) {
	case valueNode:
		// always add access to this prefix
		// LAST UPDATE
		t.LastUpdate.AddAccess(oldPrefix)
		switch oldn := oldRoot.(type) {
		case valueNode:
			prefixesEqual := bytes.Equal(oldPrefix, newPrefix)
			if !prefixesEqual {
				panic("value node prefixes not equal")
			}

			// TODO: update the valueNode if it's different
			if !bytes.Equal(n, oldn) {
				prefixH := common.BytesToHash(HashTrieKey(oldPrefix))
				t.TrieKeys[prefixH] = n
				// LAST UPDATE: edited
				t.LastUpdate.RecordChange(oldPrefix)
			}

			if storage {
				// TODO: t.Nodes isn't being updated
				//oldStorageTrie, oldAcc, oldexists := getStorageTriePrefix(oldn, append(newPrefix, byte(1)), t.TrieKeys)
				oldStorageTrie, oldAcc, oldexists := getStorageTriePrefix(oldn, newPrefix, t.TrieKeys)
				newStorageTrie, newAcc, newexists := getStorageTrie(n, preimages)
				newHKey := common.BytesToHash(HashTrieKey(append(newPrefix, byte(1))))
				oldHKey := common.BytesToHash(HashTrieKey(append(oldPrefix, byte(1))))
				if oldexists && newexists {
					r := t.UpdateTriePrefix(newStorageTrie, oldStorageTrie, append(oldPrefix, byte(1)), append(newPrefix, byte(1)), preimages, append(path, -1), false)
					// if the nodes aren't the same we need to update the map here because they have no hash nodes
					oldfnHash := HashNode(oldStorageTrie)
					newfnHash := HashNode(newStorageTrie)
					if oldfnHash != newfnHash {
						log.Info("Storage trie roots are different", "old", oldfnHash, "new", newfnHash)
						_, rootExists := preimages[newfnHash]
						if !rootExists {
							log.Info("Couldn't find the new root in preimages", "h", newfnHash)
							panic("couldn't get raw new root")
						} else {
							t.TrieKeys[newHKey] = preimages[newAcc.Root]
							// LAST UPDATE: TODO: do we need to update here? the fulNode should record it itself
							//t.LastUpdate.RecordChange(append(oldPrefix, byte(1)))
						}
					}
					return r
				} else if oldexists && !newexists {
					// if they aren't the same node, treat it like a missing update in fullNode
					sameNode := bytes.Equal(oldAcc.Root.Bytes(), newAcc.Root.Bytes())
					if !sameNode {
						log.Info("[value node] old -> !new lost", "hold", oldAcc.Root, "hnew", newAcc.Root, "prefix", oldHKey, "path", path)
						t.NodesChangedAndLostPrefix[newHKey] = t.TrieKeys[oldHKey]
						delete(t.TrieKeys, oldHKey)
						panic("storage root hash lost")
					} else {
						log.Info("An access with the new not existins is a WEIRD thing to happen", "prefix", oldHKey, "path", path)
						// LAST UPDATE: this is an access of the valueNode only, we already recorded it
					}
					return true
				} else if !oldexists && newexists {
					// check for a changed node without its data
					oldState, exists := t.NodesChangedAndLost[oldAcc.Root]
					sameNode := bytes.Equal(oldAcc.Root.Bytes(), newAcc.Root.Bytes())
					if exists {
						log.Info("[value node] !old -> new found", "hold", oldAcc.Root, "hnew", newAcc.Root, "prefix", oldHKey, "path", path)
						// our assumption is that a detail in the valueNde chaned and NOT the root
						t.TrieKeys[oldHKey] = t.NodesChangedAndLostPrefix[oldHKey]
						oldStorageTrie, _ := decodeNode(nil, oldState)
						delete(t.NodesChangedAndLostPrefix, oldHKey)
						// DEBUG
						rootChanged := t.valueNodeRootChanged(oldn, n, preimages)
						deetsChanged := t.valueNodeDeetsChanged(oldn, n, preimages)
						// the root can change this time but the deets MUST be different
						if !deetsChanged {
							log.Info("value node reciver", "rootChanged", rootChanged, "deetsChanged", deetsChanged)
							panic("nothng changed")
						}
						// DEBUG
						return t.UpdateTriePrefix(newStorageTrie, oldStorageTrie, append(oldPrefix, byte(1)), append(newPrefix, byte(1)), preimages, append(path, -1), false)
					} else if !sameNode {
						log.Info("!old and new and !sameNode so add", "prefix", oldHKey, "path", path, "oldRoot", oldAcc.Root, "newRoot", newAcc.Root, "storagePrefix", common.BytesToHash(HashTrieKey(append(oldPrefix, byte(1)))), "oldp", oldPrefix, "newp", newPrefix)
						//log.Info("same prefixes", "b", prefixesEqual)
						//log.Info("node", "n", newStorageTrie)
						//log.Info("oldnode", "n", oldStorageTrie)
						//toAdd := common.BytesToHash(HashTrieKey(append(oldPrefix, byte(1))))
						//raw, e := t.TrieKeys[toAdd]
						//if e {
						//	weirdN, _ := decodeNode(nil, raw)
						//	log.Info("old weird node", "n", weirdN)
						//	log.Info("storage root", "n", newStorageTrie)
						//	log.Info("Adding node that already exists", "prefixH", toAdd)
						//	panic("")
						//}
						r := t.AddStorageSubTriePrefix(newStorageTrie, append(oldPrefix, byte(1)), append(path, -1), preimages)
						// add to the map
						log.Info("adding to map")
						_, exists := preimages[newAcc.Root]
						if !exists {
							log.Info("Storage root not in preimages", "h", newAcc.Root)
						} 
						t.TrieKeys[common.BytesToHash(HashTrieKey(append(oldPrefix, byte(1))))] = preimages[newAcc.Root]
						// LAST UPDATE: must record the storage Root here since it would be added in addsubtrieprefix
						t.LastUpdate.AddAccess(append(oldPrefix, byte(1)))
						//t.LastUpdate.RecordChange(append(oldPrefix, byte(1)))
						t.LastUpdate.KeyAdd(append(oldPrefix, byte(1)))
						return r
					} else {
						log.Info("!old and new and IS sameNode so add", "prefix", oldHKey, "path", path)
						r := t.AddStorageSubTriePrefix(newStorageTrie, append(oldPrefix, byte(1)), append(path, -1), preimages)
						toAdd := common.BytesToHash(HashTrieKey(append(oldPrefix, byte(1))))
						_, e := t.TrieKeys[toAdd]
						if e {
							log.Info("Adding node that already exists", "prefixH", toAdd)
							panic("")
						}
						t.TrieKeys[common.BytesToHash(HashTrieKey(append(oldPrefix, byte(1))))] = preimages[newAcc.Root]
						// LAST UPDATE: must record the storage Root here since it would be added in addsubtrieprefix
						t.LastUpdate.AddAccess(append(oldPrefix, byte(1)))
						//t.LastUpdate.RecordChange(append(oldPrefix, byte(1)))
						t.LastUpdate.KeyAdd(append(oldPrefix, byte(1)))
						return r
					}
				} else {
					// !oldExists && !newExists: if the nodes aren't the same painc
					sameNode := bytes.Equal(oldAcc.Root.Bytes(), newAcc.Root.Bytes())
					if !sameNode {
						panic(fmt.Sprintf("Neither exists. Old=%v, new=%v", oldn, n))
					} else {
						// no access to a valueNode wen it doesn't exist so we save it as an old thing
						log.Info("just an access of a valueNod, nothing to do", "prefix", oldHKey, "path", path)
						return true
					}
				}
			} else {
				return true
			}
		case *fullNode:
			panic("unhandled case fullNode -> valueNode")
			return true
		default:
			panic("Default transiution failyure into valueNode")
			return true
		}
	case *shortNode:
		// LAST UPDATE
		t.LastUpdate.AddAccess(oldPrefix)
		currKey := common.BytesToHash(HashTrieKey(newPrefix))
		if currKey == target {
			log.Info("Here's teh diff in short node")
			panic("")
		}
		switch oldn := oldRoot.(type) {
		case *shortNode:
			keysEqual := bytes.Equal(n.Key, oldn.Key)
			//log.Info("short node", "prefix", oldPrefix, "newprefix", newPrefix, "old", oldn.Key, "new", n.Key)
			//log.Info("appended", "new", append(newPrefix, (n.Key)...), "old", append(oldPrefix, (oldn.Key)...))
			if !keysEqual {
				log.Info("short node -> short node keys aren't ehs ame", "oldk", oldn.Key, "newk", n.Key, "prefix", currKey, "path", path)
				t.LastUpdate.RecordChange(oldPrefix)
			}
			hnNew, hnNewOk := (n.Val).(hashNode)
			hnOld, hnOldOk := (oldn.Val).(hashNode)
			vnNew, vnNewOk := (n.Val).(valueNode)
			_, vnOldOk := (oldn.Val).(valueNode)
			prefixH := common.BytesToHash(HashTrieKey(append(oldPrefix, (oldn.Key)...)))
			if (vnNewOk && vnOldOk) {
				//log.Info("perfix", "p", newPrefix)
				log.Info("both children valueNode", "prefix", currKey, "path", path, "oldh", HashNode(oldn), "newh", HashNode(n))
				rr := t.UpdateTriePrefix(n.Val, oldn.Val, append(oldPrefix, (oldn.Key)...), append(newPrefix, (n.Key)...), preimages, path, storage)
				// TODO: removed this it's done in the valueNode case
				//if !bytes.Equal(vnOld, vnNew) {
				//	t.TrieKeys[prefixH] = vnNew
				//}
				return rr
			} else if (hnNewOk && vnOldOk) {
				// valueNode -> hash Node insert
				// we expec the shortNode key to get smaller
				if keysEqual {
					panic("valuenode -> hashnode insertion but keys are the same")
				} else {
					log.Info("short node key trimmed because valueNode -> hashNode", "prefix", currKey, "path", path)
					// ASSUME: the valueNode is still there so the key should remain in the map
					// the shortNode key in the map is the same what has changed 
					//panic("keys aren't the same")
				}
				// don't delete anything the shortNode will be replaced
				// the next node after
				// old Node still exists
				oldVnKey := append(oldPrefix, (oldn.Key)...)
				oldVnKeyHash := common.BytesToHash(HashTrieKey(oldVnKey))

				// we need to delete the valueNode
				_, exists := t.TrieKeys[oldVnKeyHash]
				//var castAsValNode valueNode = prevRaw
				//log.Info("Casted node", "n", castAsValNode)
				//log.Info("Are they the same", "b", bytes.Equal(vnOld, castAsValNode))
				//log.Info("valNode", "n", oldn.Val)
				//log.Info("prevraw", "n", fmt.Sprintf("%x", prevRaw))
				//log.Info("xprint valNode", "n", fmt.Sprintf("%x", oldn.Val))
				//if !bytes.Equal(rawOldVn, nodeToBytes(oldn.Val)) {
				//	log.Info("Not equal", "rawOldVn", fmt.Sprintf("%x", rawOldVn), "oldN.Val", fmt.Sprintf("%x",nodeToBytes(oldn.Val)))
				//	panic("The raw valuenode and the value node encoded in the old short node aren't the same")
				//}
				delete(t.TrieKeys, oldVnKeyHash)

				// Add the subTrie
				r := t.AddSubTriePrefix(hnNew, append(oldPrefix, (n.Key)...), path, preimages)
				// LAST UPDATE: above will already add the fullNode of the new hashNode
				// valueNode key remains we onlyt have additions here
				// the current shortNode was changed but that was already recorded

				// assert that the valueNode doesn't still exist 
				// ASSUME: the hashNode leads to a fullNode with only 2 children one of them should be oldn.Val
				_, exists = t.TrieKeys[oldVnKeyHash]
				if exists {
					panic("old vn readded")
				}

				// assert that the next node is a fullNode
				newFn, b := LeadsToFullNode(hnNew, preimages, append(oldPrefix, (n.Key)...))
				if !b {
					panic("the vluenode wasn't replaced by a fullNode")
				}
				log.Info("New ful node", "n", newFn)
		
				numNotNil := numNilChildren(newFn, t.TrieKeys)
				if numNotNil != 2 {
					panic(fmt.Sprintf("Full node has %v non-nill children", numNotNil))
				}

				// create a new shortNode and valueNode
				log.Info("prefix", "k", fmt.Sprintf("%x", oldPrefix))
				log.Info("oldn.Key", "k", fmt.Sprintf("%x",oldn.Key))
				log.Info("newn.Key", "k", fmt.Sprintf("%x",n.Key))
				insertSnKey, insertSnExtKey := ValueNodeToFullNode(oldPrefix, oldn.Key, n.Key, oldVnKey)
				log.Info("inserSnKey", "k", fmt.Sprintf("%x", insertSnKey))
				log.Info("insertSnExtKey", "k", fmt.Sprintf("%x", insertSnExtKey))
				newSn := &shortNode{hexToCompact(insertSnExtKey), oldn.Val, nodeFlag{dirty: false}}

				//newSnRawBytes := nodeToBytes(newSn)
				newSnRawBytes, errEncode := rlp.EncodeToBytes(newSn)
				if errEncode != nil {
					panic(errEncode)
				}

				insertSnKeyHash := common.BytesToHash(HashTrieKey(insertSnKey))
				t.TrieKeys[insertSnKeyHash] = newSnRawBytes
				// LAST UPDATE: this is a new node that was added
				t.LastUpdate.KeyAdd(insertSnKey)
				t.LastUpdate.AddAccess(insertSnKey)

				newVnKey := append(insertSnKey, insertSnExtKey...)
				newVnKeyHash := common.BytesToHash(HashTrieKey(newVnKey))

				if !bytes.Equal(newVnKey, oldVnKey) {
					log.Info("Not equal", "newvnnkey", fmt.Sprintf("%x", newVnKey), "oldk", fmt.Sprintf("%x", oldVnKey))
					panic("not equal")
				}
				var insertVn valueNode = (oldn.Val).(valueNode)
				t.TrieKeys[newVnKeyHash] = insertVn
				// LAST UPDATE: this node was accessed so we record it
				t.LastUpdate.AddAccess(newVnKey)

				b = t.ValueNodeExists(newFn, newVnKey, len(oldPrefix) + len(n.Key), path)
				if !b {
					panic("the replaced valueNode wasn't found")
				}

				//temp := t.TrieKeys[prefixH]
				//delete(t.TrieKeys, prefixH)
				//r := t.AddSubTriePrefix(hnNew, append(oldPrefix, (n.Key)...), path, preimages)
				//_, exists := t.TrieKeys[prefixH]
				//if !exists {
				//	t.TrieKeys[prefixH] = temp
				//} 
				return r
				//return t.AddSubTriePrefix(hnNew, append(oldPrefix, (oldn.Key)...), path, preimages)
			} else if (vnNewOk && hnOldOk) {
				// hashNode -> valueNode: stuff was deleted
				// prefix remains this way becayse M[prefix+key] = DecodeNode(hashNode)
				if keysEqual {
					panic("valuenode -> hashnode insertion but keys are the same")
				} else {
					log.Info("[vnnew hnold] short node key trimmed because valueNode -> hashNode", "prefix", currKey, "path", path)
				}
				d := t.deleteRecursivelyPrefix(hnOld, oldPrefix, storage)
				log.Info("hashnode -> valueNode", "d", d)
				// the previous valueNode was deleted and now we're adding it again
				t.TrieKeys[prefixH] = vnNew
				// LAST UPDATE: the key of the new valueNode is the same as before so we don't have to record this as an access
				// the shortNode changed but it was already 
				// check if this prefix was deleted in the recursive call
				idx := -1
				for i, x := range t.LastUpdate.NodesDeleted {
					if x == prefixH {
						idx = i
						break
					}
				}
				//contained := slice.Index(t.LastUpdate.NodesDeleted, prefixH)
				//if contained != -1 {
				if idx != -1 {
					panic("the non-deleted node was incluided in recursive delete")
					// then we need to remove it from deleted
					//slice.Delete(t.LastUpdate.NodesDeleted, contained, contained+1)
					// we do this because it still sticks around
				}
				return true
			} else if (hnNewOk && hnOldOk) {
				// both hashNodes
				_, newExists := preimages[common.BytesToHash(hnNew)]
				_, oldExists := t.TrieKeys[common.BytesToHash(HashTrieKey(append(newPrefix, (n.Key)...)))]
				if oldExists && newExists {
					// cotinue to update the trie
					log.Info("[short node] Both hash nodes and both exist", "old", hnOld, "new", hnNew, "prefix", currKey, "path", path)
					// LAST UPDATE: will take care of itself
					return t.UpdateTriePrefix(hnNew, hnOld, append(oldPrefix, (oldn.Key)...), append(newPrefix, (n.Key)...), preimages, path, storage)
				} else if oldExists && !newExists { // TODO: and !sameNode?
					newHKey := common.BytesToHash(HashTrieKey(append(newPrefix, (n.Key)...)))
					oldHKey := common.BytesToHash(HashTrieKey(append(oldPrefix, (oldn.Key)...)))
					log.Info("[short node] lost hash node", "hold", hnOld, "hnew", hnNew, "prefix", currKey, "path", path)
					t.NodesChangedAndLostPrefix[newHKey] = t.TrieKeys[oldHKey]
					panic("lost hashnode from shortnode")
					delete(t.TrieKeys, oldHKey)
					var oldBytes []byte = hnOld
					t.LostNodePrevHashPrefix[common.BytesToHash(hnNew)] = oldBytes
					// LAST UPDATE: record this access
					t.LastUpdate.AddAccess(append(newPrefix, (n.Key)...))
					t.LastUpdate.RecordChange(append(newPrefix, (n.Key)...))
					return true
				} else if !oldExists && newExists {
					oldHKey := common.BytesToHash(HashTrieKey(append(oldPrefix, (oldn.Key)...)))
					oldDeadChild, exists := t.NodesChangedAndLostPrefix[oldHKey]
					if exists {
						t.TrieKeys[oldHKey] = oldDeadChild
						delete(t.NodesChangedAndLostPrefix, oldHKey)
						log.Info("[short node] Accessed lost node", "hold", hnOld, "hnew", hnNew, "prefix", currKey, "path", path)
						rr := t.UpdateTriePrefix(hnNew, hnOld, append(oldPrefix, (oldn.Key)...), append(newPrefix, (n.Key)...), preimages, path, storage)
						return rr
					} else {
						log.Info("!oldExists and new Exists add", "prefix", currKey, "path", path)
						return t.AddSubTriePrefix(hnNew, append(newPrefix, (n.Key)...), path, preimages)
					}
					// LAST UPDATE: the function calls take care of everything
				} else {
					sameNode := bytes.Equal(hnOld, hnNew)
					if !sameNode {
						oldHKey := common.BytesToHash(HashTrieKey(append(oldPrefix, (oldn.Key)...)))
						newHKey := common.BytesToHash(HashTrieKey(append(newPrefix, (n.Key)...)))
						_, exists := t.NodesChangedAndLostPrefix[oldHKey]
						if exists { 
							log.Info("short node translate", "prefix", currKey, "path", path)
							t.NodesChangedAndLostPrefix[newHKey] = t.NodesChangedAndLostPrefix[oldHKey]
							delete(t.NodesChangedAndLost, oldHKey)
							panic("!oldEsists and !newExists another lost change")
							// LAST UPDATE: this is at least and access and a change
							t.LastUpdate.AddAccess(append(newPrefix, (n.Key)...))
							t.LastUpdate.RecordChange(append(newPrefix, (n.Key)...))
							return true
						} else {
							//panic(fmt.Sprintf("neither exists. old=%v, new=%v", hnOld, hnNew))
							// TODO: what to do here
							return true
						}	
					} else {
						log.Info("neither exist and same node")
						return true
					}
				}
			} else {
				panic(fmt.Sprintf("\n\tOld shortnode value (%T) changed to non-VN/HN (%T)", oldn.Val, n.Val))
			}
		case *fullNode:
			// LAST UPDATE: TODO: we let the hashNode case do this 
			t.LastUpdate.RecordChange(oldPrefix)
			//panic("fullNode -> shortNode")
			//[1 14 0 9 14 8 -1 9 13 1 13 8]
			// This is a deletion but the hashNode case will do this so just recurse
			// fullNode -> shortNode
			_, isVn := t.GetShortNodeChild(n)
			if isVn {
				// this is a delete the valueNode with key (oldPrefix + n.Key) is the one that was saved
				// the other was dropped
				testPrefix := append(oldPrefix, byte(14))
				//testPrefix2 := append(testPrefix, byte(14))
				log.Info("oldPRefix", "p", fmt.Sprintf("%x", testPrefix), "h", common.BytesToHash(HashTrieKey(testPrefix)))
				log.Info("new short node", "k", fmt.Sprintf("%x", n.Key))
				//log.Info("finalPrefix", "p", fmt.Sprintf("%x", testPrefix2), "h", common.BytesToHash(HashTrieKey(testPrefix2)))
				d, b := t.DeletedFullNodeChild(oldn, oldPrefix, append(oldPrefix, (n.Key)...))
				log.Info("Deleted node", "d", d, "b", b)
				if b {
					// delete that hash from the map
					delete(t.TrieKeys, d)
					// LAST UPDATE: record this deletion
					t.LastUpdate.NodesDeleted = append(t.LastUpdate.NodesDeleted, d)
					return true
				}
				// LAST UPDATE: the valueNode survived with teh same prefix hash
				// the shortNode that is here now is a new node with the same prefix as fullNode so we only record it as a change
				// TODO: the reason is that the shortNode key changed even though the valueNode is the one that stays the say key
			} else {
				panic("unexpected transformation")
			}
			return true
		default:
			panic("short node node from either shortNode or fullNode")
		}
	case *fullNode:
		// LASTUPDATE
		t.LastUpdate.AddAccess(oldPrefix)
		currNewKey := common.BytesToHash(HashTrieKey(newPrefix))
		switch oldn := oldRoot.(type) {
		case *fullNode:
			// now process the updates to the trie
			allGoodRecursion := true
			for i := range &n.Children {
				oldC := oldn.Children[i]
				newC := n.Children[i]
				oldHKey := common.BytesToHash(HashTrieKey(append(oldPrefix, byte(i))))
				newHKey := common.BytesToHash(HashTrieKey(append(newPrefix, byte(i))))
				if oldHKey != newHKey {
					//log.Info("Full node", "child", i, "new append", append(newPrefix, byte(i)), "old append", append(oldPrefix, byte(i)))
					log.Info("full node keys not the same", "old", oldPrefix, "new", newPrefix)
					//log.Info("Prefix", "common length", prefixLen(oldPrefix, newPrefix), "len(old)", len(oldPrefix), "len(new)", len(newPrefix))
					panic("Keys differ")
				}

				// If both nodes aren't nil then find differences to update with
				if oldC != nil && newC != nil {
					_, oldExists := t.TrieKeys[oldHKey]
					_, newExists := preimages[common.BytesToHash(newC.(hashNode))]
					sameNode := (bytes.Equal(oldC.(hashNode), newC.(hashNode)))
					if !sameNode {		// DEBUG statement
						log.Info("FullNode children differ.", "idx", i, "path", path, "currPrefix", currNewKey)
						//log.Info("FullNode children differ.", "idx", i, "old", oldPrefix, "new", newPrefix, "path", path, "parent", HashNode(n))
						log.Info("Do they exist?", "old", oldExists, "new", newExists)
					}

					if newExists && !oldExists {
						// check if this prefix exists
						oldraw, exists := t.NodesChangedAndLostPrefix[oldHKey]
						if exists {	
							log.Info("It's a lost node", "prefix", currNewKey, "path", path)
							prevHash, _ := t.LostNodePrevHashPrefix[common.BytesToHash(oldC.(hashNode))]
							t.TrieKeys[oldHKey] = oldraw
							delete(t.NodesChangedAndLostPrefix, oldHKey)
							delete(t.LostNodePrevHashPrefix, common.BytesToHash(oldC.(hashNode)))
							// finally we found it, now proceed with this as the node
							// act like this is the hashNode and go forward
							var newHn hashNode = prevHash 
							if bytes.Equal(oldPrefix, []byte{}) && i == 2 {
								log.Info("found this node again")
								nc, _ := NodeFromHashNode(HashNode(newC).Bytes(), preimages)
								log.Info("Node", "n", nc)
								switch nc := nc.(type) {
								case *fullNode:
									log.Info("Node is fulle node")
									cnode, _ := NodeFromHashNode(HashNode(nc.Children[5]).Bytes(), preimages)
									log.Info("cnode", "n", cnode)
							        switch n5 := cnode.(type) {
							        case *fullNode:
							        	n57, _ := NodeFromHashNode(HashNode(n5.Children[7]).Bytes(), preimages)
							        	log.Info("new: cnode [2, 5, 7]", "n", n57)
							            switch nn57 := n57.(type) {
							            case *fullNode:
							            	n576, _ := NodeFromHashNode(HashNode(nn57.Children[6]).Bytes(), preimages)
							            	log.Info("new: cnode [2, 5, 7, 6]", "n", n576)
									        switch nn576 := n576.(type) {
									        case *fullNode:
									        	n576_14, _ := NodeFromHashNode(HashNode(nn576.Children[14]).Bytes(), preimages)
									        	log.Info("cnode [2, 5, 7, 6, 14]", "n", n576_14)
									        default: log.Info("Something else")
									        }
							            default:
							            }
							        default:
							        }
								case *shortNode: 
									log.Info("it's a shortnode before")
								default:
								}
								panic("panic")
							}
							// LAST UPDATE: do nothing because the update call takes care of it
							allGoodRecursion = allGoodRecursion && t.UpdateTriePrefix(newC, newHn, append(oldPrefix, byte(i)), append(newPrefix, byte(i)), preimages, append(path, i), storage)
						} else {
							log.Info("new and not old Adding a subtrie", "idx", i, "path", path, "prefix", currNewKey)
							r := t.AddSubTriePrefix(newC, append(oldPrefix, byte(i)), append(path, i), preimages)
							// LAST UPDATE: do nothing the add call does it for you
							allGoodRecursion = allGoodRecursion && r
						}
					} else if (oldExists && !newExists) && !sameNode {
						log.Info("We lost a node", "path", path, "prefix", currNewKey, "idx", i)
						log.Info("Prefix", "p", bytes.Equal(oldPrefix, []byte{}))
						t.NodesChangedAndLostPrefix[newHKey] = t.TrieKeys[oldHKey]
						delete(t.TrieKeys, oldHKey)
						nc, _ := NodeFromHashNode(HashNode(oldC).Bytes(), t.Nodes)
						log.Info("The lost node:", "n", nc)
						switch nc := nc.(type) {
						case *fullNode:
							log.Info("Node is fulle node")
							cnode, _ := NodeFromHashNode(HashNode(nc.Children[5]).Bytes(), t.Nodes)
							log.Info("cnode", "n", cnode)
							switch n5 := cnode.(type) {
							case *fullNode:
								n57, _ := NodeFromHashNode(HashNode(n5.Children[7]).Bytes(), t.Nodes)
								log.Info("cnode [2, 5, 7]", "n", n57)
							    switch nn57 := n57.(type) {
							    case *fullNode:
							    	n576, _ := NodeFromHashNode(HashNode(nn57.Children[6]).Bytes(), t.Nodes)
							    	log.Info("cnode [2, 5, 7, 6]", "n", n576)
									switch nn576 := n576.(type) {
									case *fullNode:
										n576_14, _ := NodeFromHashNode(HashNode(nn576.Children[14]).Bytes(), t.Nodes)
										log.Info("cnode [2, 5, 7, 6, 14]", "n", n576_14)
									default: log.Info("Something else")
									}
							    default:
							    }
							default:
							}
						case *shortNode: 
							log.Info("it's a shortnode before")
						default:
						}
						//panic("full node children: oldExists and !newExists")
						//t.NodesChangedAndLostPrefix[newHKey] = t.TrieKeys[oldHKey]
						//delete(t.TrieKeys, oldHKey)
						// LAST UPDATE: this node was changed byt other wise just an access
						t.LastUpdate.AddAccess(append(oldPrefix, byte(i)))
						t.LastUpdate.RecordChange(append(oldPrefix, byte(i)))
						
						var oldBytes []byte = oldC.(hashNode)
						t.LostNodePrevHashPrefix[common.BytesToHash(newC.(hashNode))] = oldBytes

					} else if (!oldExists && !newExists) && !sameNode {
						_, exists := t.NodesChangedAndLostPrefix[oldHKey]
						if exists {
							// since we use the prefix hash as the key nothing changes
							// so you do nothing
							log.Info("translation of a node", "path", path, "prefix", currNewKey, "idx", i)
							t.LostNodePrevHashPrefix[common.BytesToHash(newC.(hashNode))] = t.LostNodePrevHash[common.BytesToHash(oldC.(hashNode))]
							delete(t.LostNodePrevHashPrefix, common.BytesToHash(oldC.(hashNode)))
							// LAST UPDATE: a translation is an access and a change
							t.LastUpdate.AddAccess(append(oldPrefix, byte(i)))
							t.LastUpdate.RecordChange(append(oldPrefix, byte(i)))
						}

					} else if (oldExists && newExists) {
						log.Info("both exist, just recurse", "prefix", currNewKey, "path", path, "idx", i)
						//log.Info("prefixes", "oldPrefix", fmt.Sprintf("%x",oldPrefix), "newPrefix", fmt.Sprintf("%x", newPrefix))
						allGoodRecursion = allGoodRecursion && t.UpdateTriePrefix(newC, oldC, append(oldPrefix, byte(i)), append(newPrefix, byte(i)), preimages, append(path, i), storage) 
						// LAST UPDATE: do nothing 
						//log.Info("Finished child", "i", i, "newC", common.BytesToHash(newC.(hashNode)), "oldC", common.BytesToHash(oldC.(hashNode)), "oldParent", HashNode(oldn), "newParent", HashNode(n))
					}
				} else if oldC == nil && newC != nil {
					// a new subTrie
					log.Info("old nil, new not nil Adding a subtrie", "idx", i, "path", path, "prefix", currNewKey)
					r := t.AddSubTriePrefix(newC, append(newPrefix, byte(i)), append(path, i), preimages)
					// LAST UPDATE: do nothing the add takes care of everything
					allGoodRecursion = allGoodRecursion && r
				} else if oldC != nil && newC == nil {
					// this is a deletion
					if !storage {
						tn, _ := DecodeNodeFromPrefix(append(oldPrefix, byte(i)), t.TrieKeys)
						d := t.deleteRecursivelyPrefix(oldC, append(oldPrefix, byte(i)), storage)
						// LAST UPDATE: do nothing the recursive call adds the required to NodesDeleted
						log.Info("Deletion from trie.", "numDeleted", d, "oldchild", tn, "path", path, "prefix", currNewKey)
						allGoodRecursion = allGoodRecursion && true
					} else {
						tn, _ := DecodeNodeFromPrefix(append(oldPrefix, byte(i)), t.TrieKeys)
						panic(fmt.Sprintf("A child went from not nil to nil, what is happeneing. Prefix=%x, oldChild = %v", oldPrefix, tn))
					}
				} else {
					allGoodRecursion = allGoodRecursion && true
				}
			}
			// TODO: possibly only dol this at the hashNode
			//if allGoodRecursion {
			//	oldfnHash := HashNode(oldfn)
			//	newfnHash := HashNode(n)
			//	if oldfnHash != newfnHash {
			//		// the prefix remains the same but we update the raw node that it points to
			//}
			return allGoodRecursion

		case *shortNode:
			// LAST UPDATE: TODO we let the hashNode case record the change
			// short node turns into a full node means there was an extension
			// the current short Node will be deleted and the new prefixes will be added
			// short node turns into a full node, look for the `prefix` the new trie
			t.LastUpdate.RecordChange(oldPrefix)
			_, isVn := t.GetShortNodeChild(oldn)
			if !isVn {
				log.Info("Short node whose value was not a valueNode was replaced by a fullNode")
				panic("short -> full")
			}
	
			// valueNode key remains the same but the shortNode key changes and has to be updated
			prefixH := HashTrieKey(oldPrefix)
			shortNodeKeyHash := common.BytesToHash(prefixH)
			valNodeKey := append(oldPrefix, (oldn.Key)...)
			valNodeKeyHash := common.BytesToHash(HashTrieKey(valNodeKey))
			tempVNode, vexists := t.TrieKeys[valNodeKeyHash]
			if !vexists {
				panic("vnode couldn't b e found something is wrong")
			}
			log.Info("VNOde in sNode", "n", fmt.Sprintf("%x", nodeToBytes(oldn.Val)))
			log.Info("Vnode in triekeys", "n", fmt.Sprintf("%x", tempVNode))
			accFromSn := new(types.StateAccount)
			err := rlp.DecodeBytes(nodeToBytes(oldn.Val), accFromSn)
			if err != nil {
				log.Info("Account from short node", "acc", accFromSn)
			}
			accFromTrie := new(types.StateAccount)
			var tempNode valueNode = tempVNode
			err = rlp.DecodeBytes(tempNode, accFromTrie)
			if err != nil {
				log.Info("Account from trie", "acc", accFromTrie)
			}
	//acc := new(types.StateAccount)
	//err := rlp.DecodeBytes(n, acc)
	//if err != nil { 
	//	//log.Info("decode storage", "node", n)
	//	return nil, acc, false
	//}
			//if !bytes.Equal(tempVNode, nodeToBytes(oldn.Val)) {
			//	panic("the value node stored isn't the same as encoded in the old short Node")
			//}
			_, sexists := t.TrieKeys[shortNodeKeyHash]
			if !sexists {
				panic("short noude could't be found")
			}
			delete(t.TrieKeys, valNodeKeyHash)
			delete(t.TrieKeys, shortNodeKeyHash)
			log.Info("Deleted short node", "keyhash", shortNodeKeyHash, "key", oldPrefix)
			log.Info("Delete value node", "keyhash", valNodeKeyHash, "key", valNodeKey)
		
			// TODO: beta
			t.LastUpdate.RecordDelete(valNodeKey)

			//r := t.AddSubTriePrefix(hashArbitraryNode(n), oldPrefix, path, preimages)
			r := t.AddSubTriePrefix(n, oldPrefix, path, preimages)
			_, vNodeReadded := t.TrieKeys[valNodeKeyHash]
			if !vNodeReadded {
				// there is no short node either and we need to figure out if the 
				// check that if the shortNode is a direct child of this fullNode by checking the hash
				log.Info("Val node NOT readded")
				newSnKey, newSnExtKey := ShortNodeToFullNode(oldPrefix, valNodeKey)
				//log.Info("oldPRefix  ", "k", fmt.Sprintf("%x",oldPrefix))
				//log.Info("valNodeKey ", "k", fmt.Sprintf("%x",valNodeKey))
				//log.Info("newSnKey   ", "k", fmt.Sprintf("%x",newSnKey))
				//log.Info("newSnExtKey", "k", fmt.Sprintf("%x",newSnExtKey))
				newSn := &shortNode{hexToCompact(newSnExtKey), oldn.Val, nodeFlag{dirty: false}}
				//newSnRawBytes := nodeToBytes(newSn)
				newSnRawBytes, errEncode := rlp.EncodeToBytes(newSn)
				if errEncode != nil {
					panic(errEncode)
				}
				//log.Info("old sn bytes", "n", fmt.Sprintf("%x",oldsnraw))
				// DEBUG: attempt to encode the old short node
				//tryEncSn, _ := rlp.EncodeToBytes(oldn)
				//log.Info("Old sn enc", "n", fmt.Sprintf("%x",tryEncSn))
				//log.Info("Compacted", "n", fmt.Sprintf("%x", hexToCompact(tryEncSn)))
				
				//// get raw from TrieKeys and confirm it decodes to oldn
				//reconstOldn, _ := decodeNode(nil, oldsnraw)
				//log.Info("compare old nodes", "oldn", oldn, "reconstoldn", reconstOldn)

				//// try to encode the oldn in a way that matches oldsnraw
				//log.Info("oldsnraw", "b", oldsnraw)
				//oldK := oldn.Key
				//oldn.Key = hexToCompact(oldK)
				//try1 := nodeToBytes(oldn)
				//try2, _ := rlp.EncodeToBytes(oldn)
				//log.Info("try1", "b", try1)
				//log.Info("try2", "b", try2)

				//decode1, err1 := decodeNode(nil, try1)
				//decode2, err2 := decodeNode(nil, try2)
				//log.Info("decode1", "err", err1, "d", decode1)
				//log.Info("decode2", "err", err2, "d", decode2)
				
				//log.Info("newSnRawBytes", "n", fmt.Sprintf("%x",newSnRawBytes))
				newSnKeyHash := common.BytesToHash(HashTrieKey(newSnKey))
				t.TrieKeys[newSnKeyHash] = newSnRawBytes 
				// add the valueNode as well obviously
				newVnKey := append(newSnKey, newSnExtKey...)
				if !bytes.Equal(newVnKey, valNodeKey) {
					log.Info("Not equal", "newvnkey", fmt.Sprintf("%x", newVnKey), "oldk", fmt.Sprintf("%x", valNodeKey))
					panic("not equal")
				}
				var insertVn valueNode = (oldn.Val).(valueNode)
				//t.TrieKeys[valNodeKeyHash] = nodeToBytes(oldn.Val)
				t.TrieKeys[valNodeKeyHash] = insertVn

				// LAST UPDATE: the value node key is the same so leave that alone
				// it's okay to update the shortNode because it can be 1 and the valueNode can be 0
				// TODO: for consistence it's okay to to AddAccess here because KeyAdd will already set it to 1
				log.Info("New snKey", "k", fmt.Sprintf("%x", newSnKey))
				log.Info("Old snKey", "k", fmt.Sprintf("%x", shortNodeKeyHash))
				t.LastUpdate.KeyAdd(newSnKey)
				t.LastUpdate.KeyAdd(newVnKey)
				t.LastUpdate.AddAccess(newSnKey)
				t.LastUpdate.AddAccess(newVnKey)
			} else {
				// how is it possible that the short Node is also the same?
				log.Info("The value node was readded?")
			}
			// ASSUME: value node might not exist in this activation but you shouldn't delete it you should keep it around since the key isn't changing
			log.Info("key bing replaced", "k", fmt.Sprintf("%x",append(oldPrefix, (oldn.Key)...)))
			b := t.ValueNodeExists(n, valNodeKey, len(oldPrefix), path)
			if !b {
				panic("The replaced valueNode wasn't found")
			} else {
				return r
			}
			return r
			// TODO: be shore that a search for n.Key from here returns the same node
		case valueNode:
			// went from valueNode to fullNode this means that given some prefix
			panic("valueNode -> fullNode")
		default: panic("todo")
		}
	case hashNode:
		if !bytes.Equal(oldPrefix, newPrefix) {
			panic("prefixes not the same")
		}
		oldhn, ok := oldRoot.(hashNode)
		if !ok { panic(fmt.Sprintf("New node at path %v is hashNode but original node isn't!", path)) }
		newHash := common.BytesToHash(n)
		newRaw, existNew := preimages[newHash]
		oldNext, errold := DecodeNodeFromPrefix(oldPrefix, t.TrieKeys)
		if !errold || !existNew {
			panic(fmt.Sprintf("we recursed meaning both hash nodes exist but couldn't look them up! path: %v, oldhash: %v, newHash: %v", path, common.BytesToHash(oldhn), newHash))
		}
		newNext, errNew := decodeNode(nil, newRaw)
		if errNew != nil {
			panic(fmt.Sprintf("Couldn't decode new node. errNew: %v", errNew))
		}
		rr := t.UpdateTriePrefix(newNext, oldNext, oldPrefix, newPrefix, preimages, path, storage)
		_, oldfn := oldNext.(*fullNode)
		_, newsn := newNext.(*shortNode)
		prefixH := common.BytesToHash(HashTrieKey(newPrefix))
		if oldfn && newsn {
			log.Info("fullNode -> shortNode", "h", prefixH, "p", fmt.Sprintf("%x", oldPrefix))
		}
		if !bytes.Equal(n, oldhn) {
			// replace
			//log.Info("Hash nodes aren't the same so update TrieKeys", "path", path, "prefix", prefixH, "old", common.BytesToHash(oldhn), "new", common.BytesToHash(n))
			if oldfn && newsn {
				log.Info("replacing node")
			}
			t.TrieKeys[prefixH] = preimages[newHash]
		}
		return rr
	default: panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}



// update trie with new information
// full nodes:
//    we expect at least one child of the full node is the same as before, check and panic if not
//    if a child exists that doesn't exist in the current trie, add the whole subtrie to the cache
//    if a child exists from before but it's hash is different, recurse. If return true, then update this full node in the cache
func (t *ValidatorTrie) UpdateTrie(newRoot node, oldRoot node, preimages map[common.Hash][]byte, path []int, storage bool) bool {
	switch n := newRoot.(type) {
	case valueNode: 
		switch oldn := oldRoot.(type) {
		case valueNode:
			if storage {
				oldStorageTrie, oldAcc, oldexists := getStorageTrie(oldn, t.Nodes)
				newStorageTrie, newAcc, newexists := getStorageTrie(n, preimages)
				if oldexists && newexists {
					// hashesNode are never values
					// if they both exists just updateTrie some more
					//log.Info("[ value node ] both storage exist", fmt.Sprintf("old(%T)", oldStorageTrie), oldStorageTrie, fmt.Sprintf("new(%T)", newStorageTrie), newStorageTrie)
					return t.UpdateTrie(newStorageTrie, oldStorageTrie, preimages, append(path, -1), false)
				} else if oldexists && !newexists {
					// if they aren't the same node, treat it like a missing update in fullNode
					sameNode := bytes.Equal(oldAcc.Root.Bytes(), newAcc.Root.Bytes())
					if !sameNode {
						log.Info("[value node] old -> !new lost", "hold", oldAcc.Root, "hnew", newAcc.Root)
						t.NodesChangedAndLost[newAcc.Root] = t.Nodes[oldAcc.Root]
						delete(t.Nodes, oldAcc.Root)
						// t.RecordChande(
					} else {
						log.Info("An access with the new not existins is a WEIRD thing to happen")
					}
					return true
				} else if !oldexists && newexists {
					// check for a changed node without its data
					oldState, exists := t.NodesChangedAndLost[oldAcc.Root]
					sameNode := bytes.Equal(oldAcc.Root.Bytes(), newAcc.Root.Bytes())
					if exists {
						log.Info("[value node] !old -> new found", "hold", oldAcc.Root, "hnew", newAcc.Root)
						// set this old node as the old root and do UpdateTrie, this case implies the hash has changed
						// our assumption is that a detail in the valueNde chaned and NOT the root
						t.Nodes[oldAcc.Root] = t.NodesChangedAndLost[oldAcc.Root]
						oldStorageTrie, _ := decodeNode(nil, oldState)
						//oldStorageTrie, _ := decodeNode(oldAcc.Root.Bytes(), oldState)
						delete(t.NodesChangedAndLost, oldAcc.Root)  // the UpdateTrie call will make sure of recursive delete

						// DEBUG
						rootChanged := t.valueNodeRootChanged(oldn, n, preimages)
						deetsChanged := t.valueNodeDeetsChanged(oldn, n, preimages)
						// the root can change this time but the deets MUST be different
						if !deetsChanged {
							log.Info("value node reciver", "rootChanged", rootChanged, "deetsChanged", deetsChanged)
							panic("nothng changed")
						}
						// DEBUG
						return t.UpdateTrie(newStorageTrie, oldStorageTrie, preimages, append(path, -1), false)
					} else if !sameNode {		// old doesn't exist and NOT SAME NODE so AddSubTrie
						// add this subtrie
						return t.AddStorageSubTrie(newStorageTrie, preimages)
					} else {  					// old doesn't exist and SAME NODE so still AddSubTrie
						// old doesn't exist and new does, they are the same node therefore add this subTrie
						return t.AddStorageSubTrie(newStorageTrie, preimages)
					}
				} else {
					// !oldExists && !newExists: if the nodes aren't the same painc
					sameNode := bytes.Equal(oldAcc.Root.Bytes(), newAcc.Root.Bytes())
					if !sameNode {
						panic(fmt.Sprintf("Neither exists. Old=%v, new=%v", oldn, n))
					} else {
						// no access to a valueNode wen it doesn't exist so we save it as an old thing
						log.Info("just an access of a valueNod, nothing to do")
						return true
					}
				}
			} else {
				return true
			}
		case *fullNode:
			// fullNode -> valueNode
			log.Info(fmt.Sprintf("ValueNode: The tries differ here. Path=%v, old=%v, new=%v, oldT=%T, newT=%T", path, oldRoot, newRoot, oldRoot, newRoot)) 
			panic("check")
		default: panic(fmt.Sprintf("Value node WAS some other node=%v of type=%T", oldRoot, oldRoot))
		}
	case *shortNode:
		// check shortNode type
		switch oldn := oldRoot.(type) {
		case *fullNode:
			// fullNode -> shortNode means some stuff is deleted
			// the parent of this MUST be a hoashNode so it will have a referenced to `n`
			// TODO: delete recursively
			log.Info("DELETE")
			return t.UpdateNodePreimage(oldn, n, preimages)
		case *shortNode:
			//nBefore := t.NumNodesFlaggedUnsafe(oldn, storage)
			// save this new shortNode in the map
			oldhn := HashNode(oldn)
			newn := HashNode(n)
			//if oldhn != newn {
			//	log.Info("shortNode replace", "new", newn, "old", oldhn)
			//	t.UpdateNodePreimage(oldn, n, preimages)
			//}
			// so far the Val can only change valueNode <-> hashNode
			hnNew, hnNewOk := (n.Val).(hashNode)
			hnOld, hnOldOk := (oldn.Val).(hashNode)
			_, vnNewOk := (n.Val).(valueNode)
			_, vnOldOk := (oldn.Val).(valueNode)
			if (vnNewOk && vnOldOk) {
				//log.Info("Both vnodes", "new", n, "old", oldn, "newval", vnNew, "oldval", vnOld)
				//_, _, oldvnexists := getStorageTrie(vnOld, t.Nodes)
				//_, _, newvnexists := getStorageTrie(vnNew, preimages)
				//if !oldvnexists && !newvnexists {
				//	t.NodesChangedAndLost[newn] = t.Nodes[oldhn]
				//	delete(t.Nodes, oldhn)
				//} else if oldhn != newn {
				if oldhn != newn {
					log.Info("vold and vnew shortNode replace", "new", newn, "old", oldhn)
					t.UpdateNodePreimage(oldn, n, preimages)
				}
				rr := t.UpdateTrie(n.Val, oldn.Val, preimages, path, storage)
				//nAfter := t.NumNodesFlaggedUnsafe(n, true)
				//log.Info("[short node vnOld && vnNew] nodes before", "n", nBefore, "path", path)
				//log.Info("[short node vnOld && vnNew] nodes after", "n", nAfter, "path", path)
				return rr
			} else if (hnNewOk && vnOldOk) {
				// valueNode -> hashNode: there was an insert
				// Don't delete anything the short node will be replaced
				// delete(t.Nodes, HashNode(vnOld))
				// we've added the hashNode to the preimages 
				if oldhn != newn {
					log.Info("hnew and vnold shortNode replace", "new", newn, "old", oldhn)
					t.UpdateNodePreimage(oldn, n, preimages)
				}
				log.Info("short node add")
				return t.AddSubTrie(hnNew, preimages)
				// TODO: check that the value exists in the new trie
			} else if (vnNewOk && hnOldOk) {
				// hashNode -> valueNode: stuff was deleted
				// we don't store valueNodes just delete the hashNode
				//delete(t.Nodes, common.BytesToHash(hnOld))
				if oldhn != newn {
					log.Info("vnew and hold shortNode replace", "new", newn, "old", oldhn)
					t.UpdateNodePreimage(oldn, n, preimages)
				}
				d := t.deleteRecursively(hnOld, storage)
				t.NumDeletes = t.NumDeletes + d
				return true
			} else if (hnNewOk && hnOldOk) {
				// since the hashNode case assumes they exist we have to check here
				if oldhn != newn {
					log.Info("hold hnew shortNode replace", "new", newn, "old", oldhn)
					t.UpdateNodePreimage(oldn, n, preimages)
				}
				_, newExists := preimages[common.BytesToHash(hnNew)]
				_, oldExists := t.Nodes[common.BytesToHash(hnOld)]
				if oldExists && newExists {
					// just recurse
					log.Info("[short node] Both hash nodes and both exist", "old", hnOld, "new", hnNew)
					rr := t.UpdateTrie(hnNew, hnOld, preimages, path, storage)
					//nAfter := t.NumNodesFlaggedUnsafe(n, storage)
					//log.Info("[short node old && new] nodes before", "n", nBefore, "path", path)
					//log.Info("[short node old && new] nodes after", "n", nAfter, "path", path) 
					return rr
				} else if oldExists && !newExists {
					// an update means hashNode encodes another shortNode
					log.Info("[short node] lost hash node", "hold", hnOld, "hnew", hnNew)
					t.NodesChangedAndLost[common.BytesToHash(hnNew)] = t.Nodes[common.BytesToHash(hnOld)]
					// TODO: maybe do recursively?
					delete(t.Nodes, common.BytesToHash(hnOld))
					return true
				} else if !oldExists && newExists {
					// this node is being expanded 
					oldDeadChild, exists := t.NodesChangedAndLost[common.BytesToHash(hnOld)]
					if exists {
						t.Nodes[common.BytesToHash(hnOld)] = oldDeadChild
						delete(t.NodesChangedAndLost, common.BytesToHash(hnOld))
						log.Info("[short node] Accessed lost node", "hold", hnOld, "hnew", hnNew)
						rr := t.UpdateTrie(hnNew, hnOld, preimages, path, storage)
						//nAfter := t.NumNodesFlaggedUnsafe(t.Root, true)
						//log.Info("[short node] nodes after", "n", nAfter)
						return rr
					} else {
						// this is a normal case of an expansion so add the subTrie
						log.Info("!oldExists and new Exists add")
						return t.AddSubTrie(hnNew, preimages)
					}
				} else {	// !oldExists && !newExists
					// if the nodes aren't the same nothing that we can do
					sameNode := bytes.Equal(hnOld, hnNew)
					if !sameNode {
						_, exists := t.NodesChangedAndLost[common.BytesToHash(hnOld)]
						if exists {
							log.Info("short node translate")
							t.NodesChangedAndLost[common.BytesToHash(hnNew)] = t.NodesChangedAndLost[common.BytesToHash(hnOld)]
							delete(t.NodesChangedAndLost, common.BytesToHash(hnOld))
							return true
						} else {
							//panic(fmt.Sprintf("neither exists. old=%v, new=%v", hnOld, hnNew))
							// TODO: what to do here
							return true
						}
					} else {
						log.Info("neither exist and same node")
						return true
					}
				}
			} else {
				panic(fmt.Sprintf("\n\tOld shortnode value (%T) changed to non-VN/HN (%T)", oldn.Val, n.Val))
			}
		//case valueNode:
		//	// an exapsion happened here so save this new shortNode and addSubtrie		
		//	delete(
		default: 
			log.Info("new Nodes", "n", n)
			log.Info("old node", "n", oldRoot)
			n, exists := NodeFromHashNode(HashNode(oldRoot).Bytes(), t.Nodes)
			if exists {
				log.Info("exists", "n", n)
			} else {
				log.Info("not exists")
			}
			r := pathToTypes(t.Root, path, t.Nodes)
			log.Info("path", "p", r)
			panic(fmt.Sprintf("A short node can't change into type. Old=%v, oldtype=%T", oldn, oldn))
		}
	case *fullNode:	
		switch on := oldRoot.(type) {
		case valueNode:
			// went from valueNode --> fullNode
			// TODO: check that the value exists
			prettyPath := pathToTypes(t.Root, path, t.Nodes)
			log.Info("pretty Path in error case","regularpath", path, "ppath", prettyPath)
			// tihs is equivalent to an insertion. If storage=true then it's in the ACCOUNT trie else it's in a storage trie
			// nothing to do with the valueNode just add the new subtrie
			// fullNode doesn't have a hashNode so shortNode addition will take are of it
			return t.AddSubTrie(n, preimages)
		case *shortNode: 
		// try to parse the analogous node in the cache as a full node
		//oldfn, ok := oldRoot.(*fullNode)
		//if !ok { 
			log.Info(fmt.Sprintf("New node at path %v is fullNode but original node isn't!", path))
			log.Info("old short node", "n", on)
			log.Info("new full node", "n", n)
			//switch on := oldRoot.(type) {
			//case *shortNode:
				// this means a key was added a short node turns into a full node
				// add subtrie a and keep this node in preimages
			log.Info("\n\n >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> add subtie for expansion")
			// delete the shortNode from preimages
			delete(t.Nodes, HashNode(on))
			return t.AddSubTrie(hashArbitraryNode(n), preimages)
			//default: panic(fmt.Sprintf("Full node turned into other node: %v", on))
			//}
		//} else {
		case *fullNode:
			//target := common.HexToHash("0x08716bdc0f07de6cd463abcb1437fb0bca1ea5d3222ca1a6f62c46f4925e0d93")
			target := common.HexToHash("28fd62c1c1ab9b9c7d72a7ffe04729ffaec36277b90fa6a2251fff14b4470f7c")
			//target2 := common.HexToHash("d590ceb1ba5cf7e64dc179ee5b85b9aebd97f8963623b5b1854a6ec4ac7e710a")
			//if HashNode(n) == target2 {
			//	log.Info("////////////////////////////////// DEBUG ///////////////////////////")
			//	log.Info("old", "n", on, "path", path)
			//	log.Info("oldh", "h", HashNode(on))
			//	_hnold,_bold := on.cache()
			//	log.Info("oldcache", "_hnold", _hnold, "_bold", _bold)
			//	log.Info("new", "n", n)
			//	log.Info("newh", "h", HashNode(n))
			//	_hn,_b := n.cache()
			//	log.Info("newcache", "_hn", _hn, "_b", _b)
			//	n.flags.hash = nil
			//	log.Info(fmt.Sprintf("cleared new hash hn %v", HashNode(n)))
			//	on.flags.hash = nil
			//	log.Info(fmt.Sprintf("cleared old hash hn %v", HashNode(on)))
			//	log.Info("////////////////////////////////// DEBUG ///////////////////////////")
			//}
			nBefore := t.NumNodesFlaggedUnsafe(on, storage)
			oldfn := on
			log.Info(fmt.Sprintf("[Step] Full nodes at path %v. new: %v, old: %v", path, HashNode(n), HashNode(oldfn)))
			// Check assumption that ALL children of fullNodes are hashNodes
			oknew := sanityCheckFullNode(n)
			okold := sanityCheckFullNode(oldfn)
			if !oknew { panic(fmt.Sprintf("Failed to check NEW fullNode. path=%v, node=%v", path, n)) }
			if !okold { panic(fmt.Sprintf("Failed to check OLD fullNode. path=%v, node=%v", path, oldfn)) }

			// DEBUG: Not guaranteed but we assert that at least one child of a full node is the same
			// now process the updates to the trie
			allGoodRecursion := true
			for i := range &n.Children {
				oldC := oldfn.Children[i]
				newC := n.Children[i]

				// If both nodes aren't nil then find differences to update with
				if oldC != nil && newC != nil {
					if common.BytesToHash(oldC.(hashNode)) == target {
						log.Info("old = target", "path", path, "idx", i)
					} else if common.BytesToHash(newC.(hashNode)) == target {
						log.Info("new = target", "path", path, "idx", i)
					}

					_, oldExists := t.Nodes[common.BytesToHash(oldC.(hashNode))]
					_, newExists := preimages[common.BytesToHash(newC.(hashNode))]
					// are their hashes the same
					sameNode := (bytes.Equal(oldC.(hashNode), newC.(hashNode)))
					if !sameNode {		// DEBUG statement
						log.Info("FullNode children differ.", "idx", i, "old", oldC, "new", newC, "path", path, "parent", HashNode(n))
						log.Info("Do they exist?", "old", oldExists, "new", newExists)
        	            //tg := common.HexToHash("999b74ef968b5eaacc643dea0722e18fb8f0b533e4b091e203aa863d464da227")
						//if tg == common.BytesToHash(oldC.(hashNode)) {
						//	testnode, _ := NodeFromHashNode(newC.(hashNode), preimages)
						//	log.Info("\n\nnew full node child", "idx", i, "n", testnode)
						//}
						//if tg == common.BytesToHash(newC.(hashNode)) {
						//	testnode, _ := NodeFromHashNode(oldC.(hashNode), t.Nodes)
						//	log.Info("\n\nold full node child", "idx", i, "n", testnode)
						//	// get size of subtree at old
						//	oldtNodes := t.NumNodesUnsafe(oldC)
						//	log.Info("\n\nold tnodes", "n", oldtNodes)
						//}

					}

					if newExists && !oldExists {
						// check first the ODD situation
						oldDeadChild, exists := t.NodesChangedAndLost[common.BytesToHash(oldC.(hashNode))]
						//log.Info("expected node", "hn", common.BytesToHash(newC.(hashNode)), "n", oldDeadChild)
						log.Info("new and !old", "old", oldC, "new", newC, "path", path, "idx", i, "oldparent", HashNode(oldfn), "newparent", HashNode(n))
						log.Info("n", "old", oldfn)
						log.Info("n", "new", n)
						if exists {
							// decode the node to a fullNode
							// TODO: just pass in the hashnode
							//oldDeadFn, err := decodeNode(common.BytesToHash(oldC.(hashNode)).Bytes(), oldDeadChild)
							//if err != nil { panic(err) }
							// now treat it as if they both exist and use this node as the old node
							log.Info("node lost exists")
							prevHash, _ := t.LostNodePrevHash[common.BytesToHash(oldC.(hashNode))]
							//t.Nodes[common.BytesToHash(oldC.(hashNode))] = oldDeadChild
							t.Nodes[common.BytesToHash(prevHash)] = oldDeadChild
							delete(t.NodesChangedAndLost, common.BytesToHash(oldC.(hashNode)))
							//log.Info("\n*************************************** so special *******************************")
							// eventually this node will be replaced in in the next call and get deleted from t.Nodes that way
							var newHn hashNode = prevHash
							allGoodRecursion = allGoodRecursion && t.UpdateTrie(newC, newHn, preimages, append(path, i), storage)
							nAfter := t.NumNodesFlaggedUnsafe(n, storage)
							log.Info("[full node new && !old && lost] nodes before", "n", nBefore, "path", path, "idx", i)
							log.Info("[full node new && !old && lost] nodes after", "n", nAfter, "path", path, "idx", i)
						} else {
						// this child isn't expanded currently, but this new input expands it so add it to the trie
							log.Info(">>>>>New expansion (new and !old)", "path", path, "curr", HashNode(n), "oldC", oldC, "newC", newC, "idx", i)
							r := t.AddSubTrie(newC, preimages)
							// if the node is the SAME then you add it here because it's an expansion
							//log.Info("get new nods")
							//nc := t.NumNodesUnsafe(newC) 
							//log.Info("number of nodes added", "n", nc)
							allGoodRecursion = allGoodRecursion && r
						}
					} else if (oldExists && !newExists) && !sameNode {
						log.Info("Hash change as a result of a WRITE", "index", i, "path", path, "oldC", HashNode(oldC), "newC", HashNode(newC), "otherold", common.BytesToHash(newC.(hashNode)), "othernew", common.BytesToHash(oldC.(hashNode)))
						theNextOne, _ := NodeFromHashNode(oldC.(hashNode), t.Nodes)
						log.Info(fmt.Sprintf("Old node=%v, it's type=%T", theNextOne, theNextOne))
						// this is the result of a write, in this case save the old node here
						//log.Info("using hash", "h", common.BytesToHash(newC.(hashNode)))
						t.NodesChangedAndLost[common.BytesToHash(newC.(hashNode))] = t.Nodes[common.BytesToHash(oldC.(hashNode))]
						var oldBytes []byte = oldC.(hashNode)
						t.LostNodePrevHash[common.BytesToHash(newC.(hashNode))] = oldBytes
						delete(t.Nodes, common.BytesToHash(oldC.(hashNode)))
						//if target == common.BytesToHash(newC.(hashNode)) {
						//	panic("found")
						//}
					} else if (!oldExists && !newExists) && !sameNode {
						log.Info("Neither exist but hash change: WRITE.", "index", i, "path", path, "oldC", HashNode(oldC), "newC", HashNode(newC), "otherold", common.BytesToHash(newC.(hashNode)), "othernew", common.BytesToHash(oldC.(hashNode)))
						oldraw, exists := t.NodesChangedAndLost[common.BytesToHash(oldC.(hashNode))]
						if exists {
							log.Info("Another write to a lost node, just translate which hash owns it")
							oldh, exists := t.LostNodePrevHash[common.BytesToHash(oldC.(hashNode))]
							if exists {
								log.Info("lost hash", "h", oldh)
							} else {
								log.Info("prev hash never saved")
							}
							oldn, ok := decodeNode(nil, oldraw)
							//oldn, ok := decodeNode(oldC.(hashNode), oldraw)
							if ok == nil {
								log.Info("decoded node", "n", oldn)
							} else {
								log.Info("couldn't do it")
								panic("decode")
							}

							log.Info("translate", "new", newC, "old", oldC)
							t.NodesChangedAndLost[common.BytesToHash(newC.(hashNode))] = t.NodesChangedAndLost[common.BytesToHash(oldC.(hashNode))]
							t.LostNodePrevHash[common.BytesToHash(newC.(hashNode))] = t.LostNodePrevHash[common.BytesToHash(oldC.(hashNode))]
							delete(t.LostNodePrevHash, common.BytesToHash(oldC.(hashNode)))
							delete(t.NodesChangedAndLost, common.BytesToHash(oldC.(hashNode)))
						}
						// same thing here, this is a write and insert
						// t.NodesChangedAndLost[common.BytesToHash(newC.(hashNode))] = t.Nodes[common.BytesToHash(oldC.(hashNode))]
						// ^^^ don't add them here
					} else if (oldExists && newExists) {
						// they both are expanded so we recurse and keep update hashes OR adding subtries
						//log.Info(">>>>>Both exist and recurse", "path", path, "parent", HashNode(n), "oldC", HashNode(oldC), "newC", HashNode(newC), "idx", i)
						allGoodRecursion = allGoodRecursion && t.UpdateTrie(newC, oldC, preimages, append(path, i), storage)
						//nAfter := t.NumNodesFlaggedUnsafe(n, storage)
						//log.Info("old chilren")
						//whichOld := t.NumChildrenExistUnsafe(oldfn)
						//log.Info("new children")
						//whichNew := t.NumChildrenExistUnsafe(n)
						//log.Info("[full node old && new] nodes before", "n", nBefore, "path", path, "idx", i, "numexist old", whichOld)
						//log.Info("[full node old && new] nodes after", "n", nAfter, "path", path, "idx", i, "numexist new", whichNew)
						//if nBefore == 21 && nAfter == 1 {
						//	log.Info("oldfn", "n", oldfn)
						//	log.Info("newfn", "n", n)
						//}
					}
				} else if oldC == nil && newC != nil {
					// if going from nil to not nil then this is a new subtrie
					r := t.AddSubTrie(newC, preimages)
					//log.Info("get new nods")
					//nc := t.NumNodesUnsafe(newC)
					//log.Info("old == nil and !new=nil", "n", nc)
					allGoodRecursion = allGoodRecursion && r
				} else if oldC != nil && newC == nil {
					// if going from !nil to nil then panic because we don't know how to handle
					// trie rebalancing (this must be the reason?)
					if !storage {
						// a storage leaf can go to nil if it's value is changed because WRITES aren't given
						// this is OK just means that there was a deletion
						tn, _ := NodeFromHashNode(oldC.(hashNode), t.Nodes)
						log.Info("fullNodes", "old", oldfn, "new", n)
						//delete(t.Nodes, common.BytesToHash(oldC.(hashNode)))
						d := t.deleteRecursively(oldC, storage)
						log.Info("delete RECURSIVELY", "num", d)
						t.NumDeletes = t.NumDeletes + d
						log.Info(fmt.Sprintf("A child went from not nil to nil, what is happening? Path: %v, oldchild: %v", path, tn))
						allGoodRecursion = allGoodRecursion && true
					} else {
						// this is an issue
						tn, _ := NodeFromHashNode(oldC.(hashNode), t.Nodes)
						panic(fmt.Sprintf("A child went from not nil to nil, what is happening? Path: %v, oldchild: %v", path, tn))
					}
				} else {
					// they are both nil so don't do anything to this child
					allGoodRecursion = allGoodRecursion && true
				}
			}
			if allGoodRecursion { 
				// if all recursie calls are good check if we need to replace the current fullnode
				oldfnHash := HashNode(oldfn)
				newfnHash := HashNode(n)
				if oldfnHash != newfnHash {
					// replace the current fullNode with this fullNode because all updates were successful
					//log.Info("Full Nodes differ, replacing the node.", "old", oldfnHash, "new", newfnHash, "path", path)
        	        //targetPreimage := common.HexToHash("62630a0c8d350971d46620ae1137262f641de355419f3eb7f32301f9d992f090")
        	        //if newfnHash == targetPreimage {
        	        //    // want to check index 14
        	        //    log.Info("\n\n\tIndex 14", "n", oldfn.Children[14])
        	        //    log.Info("\n\tInde 14 new", "n", n.Children[14])
        	        //    // it should decode to a short node
        	        //    oldc, _ := NodeFromHashNode(oldfn.Children[14].(hashNode), t.Nodes)
        	        //    newc, ok2 := NodeFromHashNode(n.Children[14].(hashNode), t.Nodes)
        	        //    if !ok2 { panic("couldn't get child for new shotnode") }
        	        //    // do both children exist and if so decode them
        	        //    log.Info("\n\tcs", "old", oldc, "new", newc)
        	        //    // now see if their "vals" exst but they sould be direct valueNodes so nothing to be done
        	        //}
					//oldN := t.NumNodesUnsafe(oldfn)
					log.Info("trie nodes at fn", "old", oldfnHash, "n", newfnHash, "path", path)
					r := t.UpdateNodePreimage(oldfn, n, preimages)
					an := t.NumNodesFlaggedUnsafe(n, true)
					target := common.HexToHash("bed3449fa35320eda922ccf3f4d4d738f22de5da00fc156311270fed284a98fa")
					_, exists := t.NodesChangedAndLost[target]
					if exists {
						log.Info("It exists rn")
					}
					if nBefore == 467 && an == 464 {
						log.Info("changed", "oldfn", oldfn, "newfn", n)
					}
				
					//newN := t.NumNodesUnsafe(n)
					//log.Info("trie nodes after update", "new", newfnHash, "n", newN)
					//if oldN > newN {
					//	log.Info("less children after replacement")
					//	log.Info("oldfn", "n", oldfn)
					//	log.Info("newfn", "n", n)
					//	whichNew := t.NumChildrenExistUnsafe(n)
					//	whichOld := t.NumChildrenExistUnsafe(oldfn)
					//	log.Info("children new", "n", whichNew)
					//	log.Info("children old", "n", whichOld)
					//	panic("duh")
					//}
					return r
				} else {
					// they are the same so nothing to do
					log.Info("Full nodes are the SAME", "old", oldfnHash, "new", newfnHash, "path", path)
					//log.Info("oldfn", "n", oldfn)
					//log.Info("newfn", "n", n)
				}
			} else {
				// either a call to AddSubTrie or UpdateTrie failed
				log.Info("recursion not all good")
			}
			return allGoodRecursion
		default: panic(fmt.Sprintf("Full node turned into other node: %v, type=%T", on, on))
		}
	case hashNode:
		//nBefore := t.NumNodesFlaggedUnsafe(t.Root, true)
		//log.Info("[hash node] nodes before", "n", nBefore)
		// if we reach here this means that they both exist in both tries already
		// assert we have the same type of node
		oldhn, ok := oldRoot.(hashNode)
		if !ok { panic(fmt.Sprintf("New node at path %v is hashNode but original node isn't!", path)) }
		// if they aren't the same hash we don't care here because we save actual node hashes in the other cases of this switch statement. fullNodes carry these hashNodes as their children
		newHash := common.BytesToHash(n)
		oldHash := common.BytesToHash(oldhn)
		newRaw, existNew := preimages[newHash]
		oldRaw, existOld := t.Nodes[oldHash]
		//log.Info("These nodes exist", "old", existOld, "new", existNew)

		if !existNew || !existOld { 	// If either node doesn't exist something is wrong in the data
			panic(fmt.Sprintf("we recursed meaning both hash nodes exist but couldn't look them up! path: %v, oldhash: %v, newHash: %v", path, oldHash, newHash))
		}
		target := common.HexToHash("d590ceb1ba5cf7e64dc179ee5b85b9aebd97f8963623b5b1854a6ec4ac7e710a")
		if newHash == target {
			log.Info("\n********** new Here",)
		}
		if oldHash == target {
			log.Info("\n********** old here")
		}
		newNode, errNew := decodeNode(nil, newRaw)
		oldNode, errOld := decodeNode(nil, oldRaw)
		//newNode, errNew := decodeNode(newHash.Bytes(), newRaw)
		//oldNode, errOld := decodeNode(oldHash.Bytes(), oldRaw)
		if (errNew != nil || errOld != nil) {	// If we can't decode the nodes something is wrong
			panic(fmt.Sprintf("Couldn't decode new or old node. errNew: %v\nerrOld: %v", errNew, errOld))
		}
		// Continue update the trie
		//log.Info(fmt.Sprintf("hashs (old, new) = (%v, %v) and decoded (old, new) = (%T, %T) and nodes are \nold=%v \nnew=%v", oldHash, newHash, oldNode, newNode, oldNode, newNode))
		rr := t.UpdateTrie(newNode, oldNode, preimages, path, storage)
		//nAfter := t.NumNodesFlaggedUnsafe(t.Root, true)
		//log.Info("[full node] nodes after", "n", nAfter)
		return rr
	default: panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// UNUSED FUNCTION ; NOT SAFE
func GetSomeValueNode(n node, preimages map[common.Hash][]byte) valueNode {
	switch n := n.(type) {
	case valueNode: return n
	case *shortNode: return GetSomeValueNode(n.Val, preimages)
	case *fullNode:
		ok := sanityCheckFullNode(n)
		if !ok {
			panic(fmt.Sprintf("Failed to check fullNode. node=%v", n))
		}
		for _,child := range &n.Children {
			if child != nil {
				vn := GetSomeValueNode(child, preimages)
				if  vn != nil {
					return vn
				}
			}
		}
		return nilValueNode
	case hashNode:
		realHash := common.BytesToHash(n)
		actualNodeRaw, exists := preimages[realHash]
		if exists {
			actualNode, err := decodeNode(nil, actualNodeRaw)
			//actualNode, err := decodeNode(realHash.Bytes(), actualNodeRaw)
			if (err != nil) { 
				panic(fmt.Sprintf("Can't deode hashnde that exists: %v, %v", realHash, actualNodeRaw))
			} else {
				return GetSomeValueNode(actualNode, preimages)		
			}
		} else {
			return nilValueNode
		}
	default: 
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// Safe call to size of the validator trie (cache) in bytes
func (t *ValidatorTrie) SizeInBytes() int {
	t.Mutex.RLock()
	r := t.sizeFromNode(t.Root)
	t.Mutex.RUnlock()
	return r
}

func (t *ValidatorTrie) SizeInBytesWithStorage() int {
	t.Mutex.RLock()
	r := t.sizeFromNodeFlagged(t.Root, true)
	t.Mutex.RUnlock()
	return r
}

func (t *ValidatorTrie) sizeFromNode(origNode node) int {
	return t.sizeFromNodeFlagged(origNode, false)
}

func (t *ValidatorTrie) StorageTries(orig node) []common.Hash {
	switch n := orig.(type) {
	case valueNode:
		// if storage trie root exists then return it
		_, acc, exists := getStorageTrie(n, t.Nodes)
		if exists {
			return []common.Hash{acc.Root}
		} else {
			return []common.Hash{}
		}
	case *shortNode:
		return t.StorageTries(n.Val)
	case *fullNode:
		final := []common.Hash{}
		for _,child := range(&n.Children) {
			if child != nil {
				final = append(final, t.StorageTries(child)...)
			} 
		}
		return final
	case hashNode:
		next, ok := NodeFromHashNode(n, t.Nodes)
		if !ok {
			return []common.Hash{}
		} else {
			return t.StorageTries(next)
		}
	default: panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}	
}

// size of trie rooted at `origNode` in bytes (unsafe)
func (t *ValidatorTrie) sizeFromNodeFlagged(origNode node, storage bool) int {
	nodeHash := HashNode(origNode)
	switch n := (origNode).(type) {
	case valueNode:
		if storage {
			storageRoot, _, exists := getStorageTrie(n, t.Nodes)
			if exists {
				return binary.Size(t.Nodes[nodeHash]) + t.sizeFromNodeFlagged(storageRoot, false)
			}
		}
		return binary.Size(t.Nodes[nodeHash])
	// valueNode isn't reached because it is encoded in shortNode
	case *shortNode: 
		sanityCheckShortNode(n, t.Nodes)
		//if !ok {
		//	panic("shortnode assumption violated")
		//}
		r := t.Nodes[nodeHash]
		return binary.Size(r)
	case *fullNode:
		ok := sanityCheckFullNode(n)
		if !ok {
			panic(fmt.Sprintf("Failed to check fullNode. node=%v", n))
		}
		fullSize := 0
		for _,child := range &n.Children {
			if child != nil {
				fullSize += t.sizeFromNodeFlagged(child, storage)
			}
		}
		tn := t.Nodes[nodeHash]
		return binary.Size(tn) + fullSize
	case hashNode:
		// hashNodes will be accounted for in the encoding of the fullNode so don't add 32
		// to the recursive case
		realHash := common.BytesToHash(n)
		actualNodeRaw, exists := t.Nodes[realHash]
		actualNode, err := decodeNode(nil, actualNodeRaw)
		//actualNode, err := decodeNode(realHash.Bytes(), actualNodeRaw)
		if (!exists || err != nil) {
			return 0  // node doesn't exist in cache or couldnot be decoded if nil
		} else {
			return t.sizeFromNodeFlagged(actualNode, storage)
		}
	default: panic("unknown type of node")
	}
}

// get node from `preimages` corresponding to the preimage `n`
func NodeFromHashNode(n hashNode, preimages map[common.Hash][]byte) (node, bool) {
	realHash := common.BytesToHash(n)
	actualNodeRaw, exists := preimages[realHash]
	actualNode, err := decodeNode(nil, actualNodeRaw)
	//actualNode, err := decodeNode(realHash.Bytes(), actualNodeRaw)
	if (err != nil || !exists) {
		return nilValueNode, false
	}
	return actualNode, true
}

func DecodeNodeFromPrefix(prefix []byte, keymap map[common.Hash][]byte) (node, bool) {
	prefixH := common.BytesToHash(HashTrieKey(prefix))
	raw, exists := keymap[prefixH]
	if !exists { return nil, false }
	actualNode, err := decodeNode(nil, raw)
	if err != nil { return nil, false }
	return actualNode, true
}

// get node from it's hash in the validator trie (unsafe)
func (t *ValidatorTrie) NodeFromHashNodeUnsafe(n hashNode) (node, bool) {
	return NodeFromHashNode(n, t.Nodes)
}

// type method for getting node from its hashnode
func (t *ValidatorTrie) NodeFromHashNode(n hashNode) (node, bool) {
	t.Mutex.RLock()
	r, ok := t.NodeFromHashNodeUnsafe(n)
	t.Mutex.RUnlock()
	return r, ok
}

// safe: how many children of a full node are expanded on (exist) in the validator trie
func (t *ValidatorTrie) NumChildrenExist(n node) int {
	t.Mutex.RLock()
	r := t.NumChildrenExistUnsafe(n)
	t.Mutex.RUnlock()
	return r
}

func numChildrenOfFn(n node, preimages map[common.Hash][]byte) int {
	switch n := (n).(type) {
	case *fullNode:
		num := 0
		for _, child := range &n.Children {
			if child != nil {
				_, exists := preimages[HashNode(child)]
				if exists {
					num += 1
				}
			}
		}
		return num
	default: panic("Only call this for nodes will children: fullNodes")
	}
}

func numNilChildren(n node, trieKeys map[common.Hash][]byte) int {
	switch n := n.(type) {
	case *fullNode:
		num := 0
		for _, child := range &n.Children {
			if child != nil {
				num = num + 1
			}
		}
		return num
	default: panic(fmt.Sprintf("NonNilChildrenFn called on non fullnode type %T", n))
	}
}

func (t *ValidatorTrie) NumChildrenExistUnsafe(n node) int {
	switch n := (n).(type) {
	case *fullNode:
		num := 0
		for _, child := range &n.Children {
			if child != nil {
				_, exists := t.Nodes[HashNode(child)]
				if exists {
					log.Info("Child exists", "h", child)
					num += 1
				}
			}
		}
		return num
	default: panic("Only call this for nodes will children: fullNodes")
	}
}

// number of nodes in the validator trie
func (t *ValidatorTrie) NumTrieNodes() int {
	return t.NumNodes(t.Root)
}

func (t *ValidatorTrie) NumNodes(origNode node) int {
	t.Mutex.RLock()
	r := t.NumNodesUnsafe(origNode)
	t.Mutex.RUnlock()
	return r
}

func (t *ValidatorTrie) NumNodesWithStorage() int {
	t.Mutex.RLock()
	r := t.NumNodesFlaggedUnsafe(t.Root, true)
	t.Mutex.RUnlock()
	return r
}

func (t *ValidatorTrie) NumNodesUnsafe(origNode node) int {
	return t.NumNodesFlaggedUnsafe(origNode, false)
}

// number of nodes in validator trie rooted at origNode
func (t *ValidatorTrie) NumNodesFlaggedUnsafe(origNode node, storage bool) int {
	switch n := (origNode).(type) {
	case valueNode:
		//log.Info("[NumNodes] value node", "h", n)
		if storage {
			storageRoot, _, exists := getStorageTrie(n, t.Nodes)
			if exists {
				//log.Info("[ Num Nodes ] accounr root", "h", acc.Root)
				return 1 + t.NumNodesFlaggedUnsafe(storageRoot, false)
			}
		}
		return 1
	case *shortNode: 
		//log.Info("[NumNodes] short node", "h", HashNode(n))
		sanityCheckShortNode(n, t.Nodes)
		switch (n.Val).(type) {
		case valueNode: return t.NumNodesFlaggedUnsafe(n.Val, storage)
		case hashNode: return t.NumNodesFlaggedUnsafe(n.Val, storage)
		default: panic("short node child is fullNode or another shortnode")
		}
		return t.NumNodesFlaggedUnsafe(n.Val, storage)
	case *fullNode:
		//log.Info("[NumNodes] fullNodes", "h", HashNode(n)) 
		target := common.HexToHash("bed3449fa35320eda922ccf3f4d4d738f22de5da00fc156311270fed284a98fa")
		num := 0
		for _, child := range &n.Children {
			if child != nil {
				//log.Info("[NumNodes] Child", "n", child) 
				if common.BytesToHash(child.(hashNode)) == target {
					log.Info("full node parent")
				}
				num += t.NumNodesFlaggedUnsafe(child, storage)
			}
		}
		return 1 + num
	case hashNode:
		target := common.HexToHash("bed3449fa35320eda922ccf3f4d4d738f22de5da00fc156311270fed284a98fa")
		//if common.BytesToHash(n) == target {
		//	log.Info("this is the target")
		//}
		actualNode, exists := NodeFromHashNode(n, t.Nodes)
		if !exists {
			//log.Info("[Numodes] hashNode does NOT exist", "h", n)
			// here check if this is changed node that we lost
			oldhn, oldExists := t.NodesChangedAndLost[common.BytesToHash(n)]
			//_, testexist := t.NodesChangedAndLost[target]
			//if testexist && !storage {
			//	log.Info("this is the target")	
			//}
			if oldExists {
		//newNode, errNew := decodeNode(newHash.Bytes(), newRaw)
				newNode, _ := decodeNode(nil, oldhn)
				//newNode, _ := decodeNode(HashNode(n).Bytes(), oldhn)
				if common.BytesToHash(n) == target {
					log.Info("found old changed", "hn", n)
					oldn, exists := NodeFromHashNode(oldhn, t.Nodes)
					log.Info("\n\noldn", "n", oldn, "exists", exists)
				}
				return t.NumNodesFlaggedUnsafe(newNode, storage)
			} else {
				return 0
			}
		} else {
			//log.Info("[Numodes] hashNode exists", "h", n)
			return t.NumNodesFlaggedUnsafe(actualNode, storage)
		}	
	default: panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// number of nodes in the validator trie
func (t *ValidatorTrie) NumTrieNodesPrefix() int {
	return t.NumNodesPrefix(t.Root)
}

func (t *ValidatorTrie) NumNodesPrefix(origNode node) int {
	t.Mutex.RLock()
	r := t.NumNodesPrefixUnsafe(origNode)
	t.Mutex.RUnlock()
	return r
}

func (t *ValidatorTrie) NumNodesWithStoragePrefix() int {
	t.Mutex.RLock()
	r := t.NumNodesFlaggedPrefixUnsafe(t.Root, []byte{}, true)
	t.Mutex.RUnlock()
	return r
}

func (t *ValidatorTrie) NumNodesPrefixUnsafe(origNode node) int {
	return t.NumNodesFlaggedPrefixUnsafe(origNode, []byte{}, false)
}

// number of nodes in validator trie rooted at origNode
func (t *ValidatorTrie) NumNodesFlaggedPrefixUnsafe(origNode node, prefix []byte, storage bool) int {
	switch n := (origNode).(type) {
	case valueNode:
		//log.Info("[NumNodes] value node", "h", n)
		if storage {
			storageRoot, _, exists := getStorageTrie(n, t.Nodes)
			if exists {
				//log.Info("[ Num Nodes ] accounr root", "h", acc.Root)
				return 1 + t.NumNodesFlaggedPrefixUnsafe(storageRoot, append(prefix, byte(1)), false)
			}
		}
		return 1
	case *shortNode: 
		//log.Info("[NumNodes] short node", "h", HashNode(n))
		sanityCheckShortNode(n, t.Nodes)
		switch (n.Val).(type) {
		case valueNode: return t.NumNodesFlaggedPrefixUnsafe(n.Val, append(prefix, (n.Key)...), storage)
		case hashNode: return t.NumNodesFlaggedPrefixUnsafe(n.Val, append(prefix, (n.Key)...), storage)
		default: panic("short node child is fullNode or another shortnode")
		}
		return t.NumNodesFlaggedPrefixUnsafe(n.Val, append(prefix, (n.Key)...), storage)
	case *fullNode:
		//log.Info("[NumNodes] fullNodes", "h", HashNode(n)) 
		target := common.HexToHash("bed3449fa35320eda922ccf3f4d4d738f22de5da00fc156311270fed284a98fa")
		num := 0
		for i, child := range &n.Children {
			if child != nil {
				//log.Info("[NumNodes] Child", "n", child) 
				if common.BytesToHash(child.(hashNode)) == target {
					log.Info("full node parent")
				}
				num += t.NumNodesFlaggedPrefixUnsafe(child, append(prefix, byte(i)), storage)
			}
		}
		return num
	case hashNode:
		//if common.BytesToHash(n) == target {
		//	log.Info("this is the target")
		//}
		//actualNode, exists := NodeFromHashNode(n, t.Nodes)
		actualNode, exists := DecodeNodeFromPrefix(prefix, t.TrieKeys)
		if !exists {
			//log.Info("[Numodes] hashNode does NOT exist", "h", n)
			// here check if this is changed node that we lost
			//oldhn, oldExists := t.NodesChangedAndLost[common.BytesToHash(n)]
			oldhn, oldExists := t.NodesChangedAndLostPrefix[common.BytesToHash(HashTrieKey(prefix))]
			//_, testexist := t.NodesChangedAndLost[target]
			//if testexist && !storage {
			//	log.Info("this is the target")	
			//}
			if oldExists {
		//newNode, errNew := decodeNode(newHash.Bytes(), newRaw)
				newNode, _ := decodeNode(nil, oldhn)
				//newNode, _ := decodeNode(HashNode(n).Bytes(), oldhn)
				return 1 + t.NumNodesFlaggedPrefixUnsafe(newNode, prefix, storage)
			} else {
				return 0
			}
		} else {
			//log.Info("[Numodes] hashNode exists", "h", n)
			return 1 + t.NumNodesFlaggedPrefixUnsafe(actualNode, prefix, storage)
		}	
	default: panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// convert list of ints to strings (used to encode a string path)
func IntListToStr(l []int) string {
	if len(l) == 0 {
		return ""
	} else {
		finalS := ""
		for _,i := range(l) {
			finalS += (strconv.Itoa(i) + " ")
		}
		return finalS[:len(finalS)-1]
	}
}

// NOT USED CURRENTLY: creates a map from `path :: []string' to `node`
func (t *ValidatorTrie) InitPathmap() bool {
	f, err := os.Open("/home/sbakshi/caching/pathmaplog.txt")
	if err != nil { panic(fmt.Sprintf("Can't even open the file: %v", err)) }
	r := t.CreatePathmap(t.Root, []int{}, f)
	f.Close()
	return r
}

func (t *ValidatorTrie) CreatePathmap(origNode node, path []int, f *os.File) bool {	
	t.Mutex.RLock()
	r := t.CreatePathmapUnsafe(origNode, path, f)
	t.Mutex.RUnlock()
	return r
}

// create a path map from trie rooted at `origNode` with current path `path`
func (t *ValidatorTrie) CreatePathmapUnsafe(origNode node, path []int, f *os.File) bool {	
	switch n := (origNode).(type) {
	case *shortNode:
		ok := sanityCheckShortNode(n, t.Nodes)
		if !ok {
			panic("shortnode assumption violated")
		}
		// save current path as path for this type
		h := HashNode(n)
		_, ok = t.Nodes[h]
		if !ok { 
			f.WriteString(fmt.Sprintf("shortNode hash isn't in preimages: %v", path))
			f.Close()
			panic(fmt.Sprintf("shortNode hash isn't in preimages: %v", path))
			return false
		}
		//t.PathMap[h] = IntListToStr(path)
		t.Pathmap[IntListToStr(path)] = h
		return true
	case *fullNode:
		ok := sanityCheckFullNode(n)
		if !ok {
			panic(fmt.Sprintf("Failed to check fullNode. path=%v, node=%v", path, n))
		}
		// a full Node is child of another fullNode
		h := HashNode(n)
		_, ok = t.Nodes[h]
		if !ok { 
			f.WriteString(fmt.Sprintf("couldn't find fullNode hash in preimages: %v", path))
			f.Close()
			panic(fmt.Sprintf("fullNode hash isn't in preimages: %v", path))
			return false 
		}
		//t.PathMap[h] = IntListToStr(path)
		t.Pathmap[IntListToStr(path)] = h
		finalReturn := true
		for idx, child := range &n.Children {
			if child != nil {
				r := t.CreatePathmapUnsafe(child, append(path, idx), f)
				if r == false { 
					finalReturn = false
					break
				}
			}
		}
		return finalReturn
	case hashNode:
		// don't do anything only index the real node in PathMap
		realHash := common.BytesToHash(n)
		rawNode, exists := t.Nodes[realHash]
		if exists {
			nextNode, err := decodeNode(nil, rawNode)
			//nextNode, err := decodeNode(realHash.Bytes(), rawNode)
			if err != nil { 
				f.WriteString(fmt.Sprintf("couldn't decode hashNode that exists in the preimages: %v", path))
				f.Close()
				panic(fmt.Sprintf("couldn't decode node! Path: %v, RawNode: %v, hash: %v", path, rawNode, realHash))
			}
			return t.CreatePathmapUnsafe(nextNode, path, f)
		} else {
			f.WriteString(fmt.Sprintf("hashNode isn't in preimages, no problem: %v\n", path))
			f.Close()
			return true
		}
	case valueNode: 
		f.WriteString(fmt.Sprintf("Encountered a valueNode: %v", path))
		f.Close()
		panic("shouldn't ever get to a valueNode in CreatePathmap")
	default: 
		f.WriteString(fmt.Sprintf("Default case: %v", path))
		f.Close()
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

func NumStorageRoots(origNode node, preimages map[common.Hash][]byte) int {
	switch n := (origNode).(type) {
	case valueNode:
		storageRoot, _, exists := getStorageTrie(n, preimages)
		if exists {
			switch storageRoot.(type) {
			case *fullNode: log.Info("we good")
			case *shortNode: panic("short node")
			case hashNode: panic("hashNode")
			case valueNode: panic("another value node")
			default: panic("root is something other than fullnode")
			}
			return 1
		} else {
			return 0
		}
	case *shortNode:
		return NumStorageRoots(n.Val, preimages)
	case *fullNode:
		num := 0
		for _, child := range &n.Children {
			if child != nil {
				num += NumStorageRoots(child, preimages)
			}
		}
		return num
	case hashNode:
		actualNode, exists := NodeFromHashNode(n, preimages)
		if exists {
			return NumStorageRoots(actualNode, preimages)
		} else { 
			return 0
		}
	default: panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// only need to store preimages of hashNodes everything else is in encoded data

// DOesn't need to be thread-safe
func TrieFromNode(n node, preimages map[common.Hash][]byte) ([]common.Hash) {
	switch n := (n).(type) {
	case valueNode: 
		//log.Info("valueNode reached", "valueNode", n)
		//return []common.Hash{}
		storageRoot, acc, exists := getStorageTrie(n, preimages)
		if exists {
			// add the root to the map and recurse
			return append([]common.Hash{acc.Root}, TrieFromNode(storageRoot, preimages)...)
		} else {
			return []common.Hash{} 
		}
	case *shortNode:
		// shortNodes are extensions or valueNodes
		// they are usually stored as hashNodes so don't save anything here
		//log.Info("shortNode expansion", "short node", HashNode(n))
		switch (n.Val).(type) {
		case *fullNode: panic("child of short node is a full node")
		default:
		}
		return TrieFromNode(n.Val, preimages)
	case *fullNode:
		// exension nodes
		//log.Info("fullNode expansion", "full node", HashNode(n))
		ok := sanityCheckFullNode(n)
		if !ok {
			panic(fmt.Sprintf("Failed to check fullNode. node=%v", n))
		}
		finalList := []common.Hash{}
		for _,child := range &n.Children {
			// save all hashes from subtrie
			if child != nil {
				// DEBUG
				_, ok := child.(hashNode)
				if !ok { panic("child of full node not a hashnode") }
				// DEBUG
				restPath := TrieFromNode(child, preimages)
				finalList = append(finalList, restPath...)
			}
		}
		return finalList
	case hashNode:
		// in some cases the hashNode isn't in the pre-images map so try a different one
		realHash := common.BytesToHash(n)
		hn := HashNode(n)
		if hn != realHash {
			panic(fmt.Sprintf("Hasnode hashes unequal! HashNode: %v, BytesToHash: %v, hn: %v", n, realHash, hn))
		}
		actualNodeRaw, exists := preimages[realHash]
		actualNode, err := decodeNode(nil, actualNodeRaw)
		//actualNode, err := decodeNode(realHash.Bytes(), actualNodeRaw)
		finalList := []common.Hash{}
		// if it is expanded go down the path
		if err == nil && exists {
			//log.Info("Expanding hashNode in creating subtrie.", "hash", realHash)
			finalList = append([]common.Hash{realHash}, TrieFromNode(actualNode,preimages)...)
		}
		return finalList
	default:
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

func TrieFromNodeDebug(n node, preimages map[common.Hash][]byte, nodesChangedAndLost map[common.Hash][]byte, path []int) ([]common.Hash) {
	target := common.HexToHash("b1a82cffa5c45d3b649f8ea279aa9d54db2cc49bfcc74094c9f40886d0f4230b")
	switch n := (n).(type) {
	case valueNode: 
		//log.Info("valueNode reached", "valueNode", n)
		//return []common.Hash{}
		storageRoot, acc, exists := getStorageTrie(n, preimages)
		if exists {
			// add the root to the map and recurse
			return append([]common.Hash{acc.Root}, TrieFromNodeDebug(storageRoot, preimages, nodesChangedAndLost, path)...)
		} else {
			return []common.Hash{} 
		}
	case *shortNode:
		// shortNodes are extensions or valueNodes
		// they are usually stored as hashNodes so don't save anything here
		//log.Info("shortNode expansion", "short node", HashNode(n))
		switch (n.Val).(type) {
		case *fullNode: panic("child of short node is a full node")
		default:
		}
		return TrieFromNodeDebug(n.Val, preimages, nodesChangedAndLost, path)
	case *fullNode:
		// exension nodes
		//log.Info("fullNode expansion", "full node", HashNode(n))
		ok := sanityCheckFullNode(n)
		if !ok {
			panic(fmt.Sprintf("Failed to check fullNode. node=%v", n))
		}
		finalList := []common.Hash{}
		for i,child := range &n.Children {
			// save all hashes from subtrie
			if child != nil {
				// DEBUG
				_, ok := child.(hashNode)
				if !ok { panic("child of full node not a hashnode") }
				// DEBUG
				restPath := TrieFromNodeDebug(child, preimages, nodesChangedAndLost, append(path, i))
				finalList = append(finalList, restPath...)
			}
		}
		return finalList
	case hashNode:
		// in some cases the hashNode isn't in the pre-images map so try a different one
		realHash := common.BytesToHash(n)
		hn := HashNode(n)
		if hn != realHash {
			panic(fmt.Sprintf("Hasnode hashes unequal! HashNode: %v, BytesToHash: %v, hn: %v", n, realHash, hn))
		}
		if target == realHash {
			log.Info("Found target")
		}
		actualNodeRaw, exists := preimages[realHash]
		if !exists {
			oldhn, oldExists := nodesChangedAndLost[common.BytesToHash(n)]
			if oldExists {
		//newNode, errNew := decodeNode(newHash.Bytes(), newRaw)
				newNode, _ := decodeNode(nil, oldhn)
				//newNode, _ := decodeNode(HashNode(n).Bytes(), oldhn)
				if realHash == target {
					log.Info("[NodesChangedAndLost] Target actual node", "n", newNode, "type", fmt.Sprintf("%T", newNode), "path", path)
				}
				return append([]common.Hash{realHash}, TrieFromNodeDebug(newNode, preimages, nodesChangedAndLost, path)...)
			} else {
				return []common.Hash{}
			}
		} else {
			actualNode, err := decodeNode(nil, actualNodeRaw)
			//actualNode, err := decodeNode(realHash.Bytes(), actualNodeRaw)
			finalList := []common.Hash{}
			// if it is expanded go down the path
			if err == nil && exists {
				if realHash == target {
					log.Info("[Nodes] Target actual node", "n", actualNode, "type", fmt.Sprintf("%T", actualNode), "path", path)
				}
				//log.Info("Expanding hashNode in creating subtrie.", "hash", realHash)
				finalList = append([]common.Hash{realHash}, TrieFromNodeDebug(actualNode,preimages, nodesChangedAndLost, path)...)
			}
			return finalList
		}
	default:
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

func TrieFromNodePrefixDebug(n node, trieKeys map[common.Hash][]byte, nodesChangedAndLostPrefix map[common.Hash][]byte, prefix []byte) ([]common.Hash) {
	//target := common.HexToHash("6a442855f44454c96c388b49ecbcc0d5d3a4599ac47b682b7bfd4b4a4443ac7a")
	target := common.HexToHash("dc61dc2f54ca0dcef2c46466a396d9da868ca6bd5271a1b768af1251d6a2eef7")
	//targetPrefix := []byte{5, 7, 6, 14, 14}
	//samePrefix := bytes.Equal(targetPrefix, prefix)
	currKey := common.BytesToHash(HashTrieKey(prefix))
	if target == currKey {
		log.Info("Target found", "h", HashNode(n))
	}
	switch n := (n).(type) {
	case valueNode: 
		//log.Info("valueNode reached", "valueNode", n)
		//storageRoot, acc, exists := getStorageTriePrefix(n, append(prefix, byte(1)), trieKeys)
		storageRoot, _, exists := getStorageTriePrefix(n, prefix, trieKeys)
		//log.Info("storage root", "h", acc.Root)
		//log.Info("storage root outside", "n", storageRoot)
		thisPreimage := common.BytesToHash(HashTrieKey(prefix))
		r := []common.Hash{thisPreimage}
		if exists {
			// the root is directly encoded as a fullNode there is not intermediate representation so we must add its key to the map right now
			storageKey := common.Hash(HashTrieKey(append(prefix, byte(1))))
			//log.Info("storage key", "k", storageKey)
			//log.Info("Stroage node", "n", storageRoot, "h", HashNode(storageRoot), "root", acc.Root)
			r = append(r, storageKey)
			return append(r, TrieFromNodePrefixDebug(storageRoot, trieKeys, nodesChangedAndLostPrefix, append(prefix, byte(1)))...)
			//return append([]common.Hash{storageKey}, TrieFromNodePrefixDebug(storageRoot, trieKeys, nodesChangedAndLostPrefix, append(prefix, byte(1)))...)
		} else {
			return r
		}
	case *shortNode:
		// shortNodes are extensions or valueNodes
		// they are usually stored as hashNodes so don't save anything here
		//log.Info("shortNode expansion", "short node", HashNode(n))
		//if samePrefix {
		//	log.Info("Found the prefix")
		//}
		switch (n.Val).(type) {
		case *fullNode: panic("child of short node is a full node")
		default:
		}
		return TrieFromNodePrefixDebug(n.Val, trieKeys, nodesChangedAndLostPrefix, append(prefix, (n.Key)...))
	case *fullNode:
		// exension nodes
		//log.Info("fullNode expansion", "full node", HashNode(n))
		//if len(prefix) > 0 {
		//	if byte(1) == prefix[len(prefix)-1] {
		//		log.Info("full node of storage trie", "key", common.BytesToHash(HashTrieKey(prefix)), "h", HashNode(n))
		//	}
		//}
		//if len(prefix) > 1 {
		//	if bytes.Equal([]byte{1,1}, []byte{ prefix[len(prefix)-2], prefix[len(prefix)-1]}) {
		//		log.Info("full node of storage trie (1,1)", "key", common.BytesToHash(HashTrieKey(prefix)), "h", HashNode(n))
		//	}
		//}
		finalList := []common.Hash{}
		for i,child := range &n.Children {
			//if len(prefix) > 1 {
			//	//if byte(1) == prefix[len(prefix)-1] {
			//	if bytes.Equal([]byte{1, 1}, []byte{prefix[len(prefix)-1], prefix[len(prefix)-2]}) {
			//		log.Info("storage path 1, 1", "key", common.BytesToHash(HashTrieKey(prefix)))
			//		log.Info("would be prefix", "k", common.BytesToHash(HashTrieKey(append(prefix, 15))))
			//	}
			//}
			// save all hashes from subtrie
			if child != nil {
				// DEBUG
				_, ok := child.(hashNode)
				if !ok { panic("child of full node not a hashnode") }
				// DEBUG
				restPath := TrieFromNodePrefixDebug(child, trieKeys, nodesChangedAndLostPrefix, append(prefix, byte(i)))
				finalList = append(finalList, restPath...)
			}
		}
		return finalList
	case hashNode:
		// in some cases the hashNode isn't in the pre-images map so try a different one
		nextNode, err := DecodeNodeFromPrefix(prefix, trieKeys)
		currKey := common.BytesToHash(HashTrieKey(prefix))
		if target == currKey {
			log.Info("\nHere is the kie in the hashnode branch")
		}
		if !err {
			oldRaw, exists := nodesChangedAndLostPrefix[currKey]
			if exists {
				newNode, _ := decodeNode(nil, oldRaw)
				return append([]common.Hash{currKey}, TrieFromNodePrefixDebug(newNode, trieKeys, nodesChangedAndLostPrefix, prefix)...)
			} else {
				return []common.Hash{}
			}
		} else {
			rr := TrieFromNodePrefixDebug(nextNode, trieKeys, nodesChangedAndLostPrefix, prefix)
			return append([]common.Hash{currKey}, rr...)
		}
	default:
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

func (t *ValidatorTrie) TrieCreateKeyMap() {
	t.CreateKeyMap(t.Root, []byte{}, []int{})
}

func (c *CacheUpdate) KeyAdd(key []byte) {
	keyHash := common.BytesToHash(HashTrieKey(key))
	c.NodesAdded = append(c.NodesAdded, keyHash)
}

func (c *CacheUpdate) AddAccess(key []byte) {
	keyHash := common.BytesToHash(HashTrieKey(key))
	c.NodesAccessed = append(c.NodesAccessed, keyHash)
}

func (c *CacheUpdate) RecordChange(key []byte) {
	keyHash := common.BytesToHash(HashTrieKey(key))
	c.NodesChanged = append(c.NodesChanged, keyHash)
}

func (c *CacheUpdate) RecordDelete(key []byte) {
	keyHash := common.BytesToHash(HashTrieKey(key))
	c.NodesDeleted = append(c.NodesDeleted, keyHash) 
}

func (t *ValidatorTrie) CreateKeyMap(n node, prefix []byte, path []int) {
	//target := []int{11, 3, 9, 9, 2, 11, 14}
	target := common.HexToHash("43855364b4a20a9c6d82e9096e6c742b31d63166d4fdf8cc57056f7e1b5b4540")
	currKey := common.BytesToHash(HashTrieKey(prefix))
	switch n := n.(type) {
	case valueNode:
		if target == currKey {
			log.Info("Found it, valueNode", "path", path)
		}
		// save prefix
		//log.Info("valueNode hash", "h", h)
		//pp, exists := t.TrieKeys[common.BytesToHash(h)]
		prefixH := common.BytesToHash(HashTrieKey(prefix))
		t.TrieKeys[prefixH] = n
		storageTrie, acc, exists := getStorageTrie(n, t.Nodes)
		if exists {
			// TODO: we add a "0x1" when going from valueNode to the root of its storage trie
			// we're probably missing a 
			// add the storage ROot here instead
			k := append(prefix, byte(1))
			keyH := HashTrieKey(append(prefix, byte(1)))
			t.TrieKeys[common.BytesToHash(keyH)] = t.Nodes[acc.Root]

			// add the full Node here
			t.LastUpdate.KeyAdd(k)
			t.LastUpdate.AddAccess(k)

			t.CreateKeyMap(storageTrie, append(prefix, byte(1)), append(path, -1))
		}
		t.LastUpdate.KeyAdd(prefix)
		t.LastUpdate.AddAccess(prefix)
	case *shortNode:
		if target == currKey {
			log.Info("Found it, shortNode", "path", path)
		}
		// nothing to save here, we save on valueNodes and fullNodes
		// short node child is either a value node or a hashNode
		// we don't care if it exists or not we're still saving this node in the map
		//h := HashTrieKey(prefix)
		//log.Info("short Node", "p", path, "hash", common.BytesToHash(h))
		//log.Info("short key", "k", fmt.Sprintf("%x",n.Key))
		//if reflect.DeepEqual(target, path) {
		//	log.Info("here's the path")
		//}
		//pp, exists := t.TrieKeys[common.BytesToHash(h)]
		//if exists {
		//	log.Info("path", "p", path)
		//	log.Info("prefix", "p", pp)
		//	panic("hashing same prefix")
		//}
		//raw, exists := t.Nodes[HashNode(n)]
		//if !exists { panic("doesn't exist") }
		//t.TrieKeys[common.BytesToHash(h)] = raw
		t.CreateKeyMap(n.Val, append(prefix, (n.Key)...), path)
	case *fullNode:
		if target == currKey {
			log.Info("Found it, fullNode", "path", path)
		}
		if len(prefix) == 0 {
			log.Info("no prefix")
		}
		// save this node's prefix
		//h := HashTrieKey(HashNode(n).Bytes())			
		//h := HashTrieKey(prefix)
		//log.Info("fullNode hash", "h", h)
		//pp, exists := t.TrieKeys[common.BytesToHash(h)]
		//if exists {
		//	log.Info("prefix", "p", pp)
		//	panic("hashing same prefix")
		//}
		//raw, exists := t.Nodes[HashNode(n)]
		//if !exists { panic("doesn't exist") }
		//t.TrieKeys[common.BytesToHash(h)] = raw
		for i, child := range &n.Children {
			if child != nil {
				switch child.(type) {
				case *shortNode: panic("fuill node child is a shortNode")
				case hashNode: t.CreateKeyMap(child, append(prefix, byte(i)), append(path, i))	
				default: panic("Shouldn't be any other types")
				}
			}
		}
	case hashNode:
		next, exists := NodeFromHashNode(n, t.Nodes)
		if exists {
			prefixH := HashTrieKey(prefix)
			t.TrieKeys[common.BytesToHash(prefixH)] = t.Nodes[common.BytesToHash(n)]
			t.CreateKeyMap(next, prefix, path)
			t.LastUpdate.KeyAdd(prefix)
			t.LastUpdate.AddAccess(prefix)
		}
	}
}

func (t* ValidatorTrie) ReturnFullKey(origNode node, path []int) []byte {
	switch n := origNode.(type) {
	case valueNode:
		_, _, exists := getStorageTrie(n, t.Nodes)
		if exists {
			log.Info("contract account")
		} else {
			log.Info("Not an account")
		}	
		return []byte{}
	case *shortNode:
		log.Info(fmt.Sprintf("key in short node: %x", n.Key))
		return append(n.Key, t.ReturnFullKey(n.Val, path)...)
	case *fullNode:
		nextidx := path[0]
		rest := path[1:]
		return append([]byte{byte(nextidx)}, t.ReturnFullKey(n.Children[nextidx], rest)...)	
	case hashNode:
		nextNode, exists := t.NodeFromHashNode(n)
		// assumption we only give a fully traversible path
		if exists {
			return t.ReturnFullKey(nextNode, path)
		} else {
			panic("Path not traversible")
		}
	default:
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// IMPORTANT CHANGE: 
//		The root node is stored as a shortNode

// ASSUME lock around preimages
func ChooseRandomFullNode (n node, preimages map[common.Hash][]byte, height int) ([]int, bool)  {
	switch n := (n).(type) {
	case valueNode: return []int{}, false
	case *shortNode: 
		panic("Choosing random shortNode")
		return ChooseRandomFullNode(n.Val, preimages, height)
	case hashNode:
		h := common.BytesToHash(n)
		rawNode, exists := preimages[h]
		if exists {
			newN, err := decodeNode(nil, rawNode)
			//newN, err := decodeNode(h.Bytes(), rawNode)
			if err == nil {
				return ChooseRandomFullNode(newN, preimages, height)
			}
		}
		return []int{}, false	
	case *fullNode:
		if height == 0 {
			return []int{}, true
		} else {
			// could be the root node
			ok := sanityCheckFullNode(n)
			if !ok {
				panic(fmt.Sprintf("Failed to check fullNode. node=%v", n))
			}
			//a := []node{}
			//for _,x := range(&n.Children) {
			//	a = append(a, x)
			//}
			a := [17]int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
			rand.Seed(time.Now().UnixNano())
			rand.Shuffle(len(a), func(i, j int) { a[i], a[j] = a[j], a[i] })
			for idx := range(a) {
				// check if the child exists in the map
				if n.Children[idx] != nil {
					p, b := ChooseRandomFullNode(n.Children[idx], preimages, height-1)
					if b {
						//log.Info("node", "full", n)
						//log.Info("chosen index", "idx", idx, "child", n.Children[idx])
						return append([]int{idx}, p...), b
					}
				}
			}
			return []int{}, false 
		}
	default: // don't do anything for other nodes we should never get there				
		panic ("the case went through witout any return")
	}
}

func (t *ValidatorTrie) TriePrefixFromPath(path []int) []byte {
	return PrefixFromPath(t.Root, path, t.Nodes)
}

func PrefixFromPath(n node, path []int, preimages map[common.Hash][]byte) []byte {
	if len(path) == 0 {
		return []byte{}
	} else {
		switch n := n.(type) {
		case valueNode:
			storageRoot, _, exists := getStorageTrie(n, preimages)
			if exists { // path isn't done so we're fucked
				nextidx := path[0]
				if nextidx != -1 {
					panic("getting valuenode trie buyt idx is not -1")
				}
				rest := path[1:]
				return PrefixFromPath(storageRoot, rest, preimages)
			} else {
				panic("[valueNode] search termiantes before path does")
			}
		case *shortNode:
			return append(n.Key, PrefixFromPath(n.Val, path, preimages)...)
		case *fullNode:
			nextidx := path[0]
			rest := path[1:]
			child := n.Children[nextidx]
			if child != nil {
				return append([]byte{byte(nextidx)}, PrefixFromPath(child, rest, preimages)...)
			} else {
				panic("search terminates before path does")
			}
		case hashNode:
			next, exists := NodeFromHashNode(n, preimages)
			if exists {
				return PrefixFromPath(next, path, preimages)
			} else {
				panic("search termiantes before path does [hashnode]")
			}
		default: panic(fmt.Sprintf("%T: invalid node: %v", n, n))
		}
	}
}

//// used by validator to choose a random full node as the cache trie root
//func ChooseRandomFullNode (origNode node, preimages map[common.Hash][]byte, height int) ([] int) {
//	for {
//		choice := ChooseRandomNode(origNode, preimages, height)
//		n, exists := NodeFromPath(origNode, choice, preimages)
//		if (!exists) { panic("Node gotten from trie no longer exists") }
//		switch n.(type) {
//		case *fullNode: return choice
//		default:
//		}
//	}
//}

// returns the types of nodes on a path as a list of strings
func NodeTypesOnPath(n node, preimages map[common.Hash][]byte, path []int) ([]string) {	
	switch n := n.(type) {
	case valueNode: return []string{"valueNode"}
	case *shortNode: return append([]string{"shortNode"}, NodeTypesOnPath(n.Val, preimages, path)...)
	case *fullNode: return append([]string{"fullNode"}, NodeTypesOnPath(n.Children[path[0]], preimages, path[1:])...)
	case hashNode:
		realHash := common.BytesToHash(n)
		actualNodeRaw, _ := preimages[realHash]
		actualNode, _ := decodeNode(nil, actualNodeRaw)
		//actualNode, _ := decodeNode(realHash.Bytes(), actualNodeRaw)
		return append([]string{"hashNode"}, NodeTypesOnPath(actualNode, preimages, path)...)
	default: panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

func HashTrieKey(key []byte) ([]byte) {
	h := newHasher(false)
	h.sha.Reset()
	h.sha.Write(key)
	s := make([]byte, common.HashLength)
	h.sha.Read(s)
	//log.Info("HashTrieKey", "h", s)
	returnHasherToPool(h)
	return s
}

// hash a node (returns HashNode)
func hashArbitraryNode(n node) (node) {
	h := newHasher(false)
	defer func() {
		returnHasherToPool(h)
	}()
	hashed, _ := h.hash(n, true)
	return hashed	
}

// returns common.Hash of a node
func HashNode (n node) common.Hash {
	hash := hashArbitraryNode(n)
	//return common.BytesToHash(hash.(hashNode))
	switch hn := hash.(type) {
	case hashNode: return common.BytesToHash(hn)
	case valueNode: return common.BytesToHash(hn)
	default: return common.BytesToHash(hash.(hashNode))
	}
	//return common.BytesToHash(hash)
}

func HashNodeAsHashNode(n node) node {
	hash := hashArbitraryNode(n)
	return hash
}

func (t *ValidatorTrie) NodeFromPrefix(prefix []byte) (node, bool) {
	t.Mutex.RLock()
	n, ok := TrieNodeFromPrefix(t.Root, prefix, 0, t.TrieKeys)
	t.Mutex.RUnlock()
	return n, ok
	
}
func TrieNodeFromPrefix(n node, prefix []byte, pos int, keymap map[common.Hash][]byte) (node, bool) {
	// if we're at the end of the prefix, this is the node tha we want
	// but this might be a hashNode so first we should try to decode the node
	switch n := n.(type) {
	case nil: return nil, false
	case valueNode:
		// either we're done
		if len(prefix) == pos {
			return n, true
		} else {
			// or we continue ot the storage trie of this acount
			if prefix[pos] != byte(1) {
				panic("The byte after a valueNode isn't a 0x1")
			} else {
				storageTrie, _, exists := getStorageTriePrefix(n, prefix[:pos], keymap)
				if exists {
					// keep going without adjusting the prefix
					return TrieNodeFromPrefix(storageTrie, prefix, pos+1, keymap)
				} else {
					return nil, false
				}
			}
		}
	case *shortNode:
		// we query for short nodes and it's values differently
		// is the key in the trie? if so then the prefix shoud be at least as long as n.Key
		// and it should match the key
		if len(prefix) == pos {
			// this is the node
			return n, true
		} else if len(prefix)-pos < len(n.Key) || !bytes.Equal(n.Key, prefix[pos:pos+len(n.Key)]) {
			return nil, false
		} else {
			return TrieNodeFromPrefix(n.Val, prefix, pos+len(n.Key), keymap)
		}
	case *fullNode:
		if len(prefix) == pos {
			return n, true
		} else { 
			log.Info("Getting index", "n", n, "prefix", prefix, "pos", prefix[pos])
			log.Info("child node", "h", n.Children[prefix[pos]])
			return TrieNodeFromPrefix(n.Children[prefix[pos]], prefix, pos+1, keymap)
		}
	case hashNode:
		// hashNode prefix is the same as the node that it encodes
		// so just query the prefix
		h := HashTrieKey(prefix[:pos])
		raw, exists := keymap[common.BytesToHash(h)]
		next, err := decodeNode(nil, raw)
		if err != nil {
			log.Info("Hashcode decode node", "key", prefix[:pos])
			panic("Couldn't decode node")
		}
		if exists {
			return TrieNodeFromPrefix(next, prefix, pos, keymap)
		} else {
			return nil, false
		}
	default: panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// hash of the node at `path` rooted at `n`
// TODO: add the case of the value node storage trie
func NodeHashFromPath (n node, path []int, preimages map[common.Hash][]byte) (common.Hash, bool) {
	switch n := (n).(type) {
	case *fullNode:
		//log.Info("full node", "path", path)
		//log.Info(fmt.Sprintf("%v", n))
		ok := sanityCheckFullNode(n)
		if !ok {
			panic(fmt.Sprintf("Failed to check fullNode. path=%v, node=%v", path, n))
		}
		if len(path) == 0 {
			return HashNode(n), true
		} else {
			nextidx := path[0]
			rest := path[1:]
			return NodeHashFromPath(n.Children[nextidx], rest, preimages)	
		}
	case hashNode:
		// can't assume the fullNode in question can exist in every request
		//log.Info("hash node", "path", path)
		realHash := common.BytesToHash(n)
		actualNodeRaw, exists := preimages[realHash]
		if !exists { 
			//log.Info("hsah doesn't exist", "h", realHash)
			return realHash, false 
		}
		actualNode, _ := decodeNode(nil, actualNodeRaw)
		//actualNode, _ := decodeNode(realHash.Bytes(), actualNodeRaw)
		// validation of hashing
		testHash := HashNode(actualNode)
		if testHash != realHash { panic("can't hash properly") }
		return NodeHashFromPath(actualNode, path, preimages)
	case *shortNode:
		if len(path) == 0 {
			// we want this node
			return HashNode(n), true
		} else {
			return NodeHashFromPath(n.Val, path, preimages)
		}
	case valueNode:
		storageRoot, _, exists := getStorageTrie(n, preimages)
		nextidx := path[0]
		if nextidx != -1 { panic(fmt.Sprintf("At value node but next path is %v, path=%v", nextidx, path)) }
		rest := path[1:]
		if exists {
			return NodeHashFromPath(storageRoot, rest, preimages)
		} else {
			return common.BytesToHash(n), false
		}
	default: panic("Never encounter any other node")
	}
}

// hash of node at path in validator trie
func (t *ValidatorTrie) TrieNodeHashFromPath(path []int) (common.Hash, bool) {
	t.Mutex.RLock()
	r, ok := t.TrieNodeHashFromPathUnsafe(path)
	t.Mutex.RUnlock()
	return r, ok
}

func (t *ValidatorTrie) TrieNodeHashFromPathUnsafe(path []int) (common.Hash, bool) {
	return NodeHashFromPath(t.Root, path, t.Nodes)
}

// get node from path in trie from `preimages`
func NodeFromPath(n node, path []int, preimages map[common.Hash][]byte) (node, bool) {
	h, exists := NodeHashFromPath(n, path, preimages)
	if !exists { return nilValueNode, false }
	raw := preimages[h]	
	actualNode, _ := decodeNode(nil, raw)
	//actualNode, _ := decodeNode(h.Bytes(), raw)
	return actualNode, true
}

// go down a random path in trie reooted at `n`
func TraverseArbitraryPath(n node, preimages map[common.Hash][]byte) ([] string) {
	switch n := (n).(type) {
	case valueNode: return []string{"valueNode"}
	case *shortNode:
		// shortNodes are extensions or valueNodes
		return append(TraverseArbitraryPath(n.Val, preimages), "shortNode")
	case *fullNode:
		// exension nodes
		for _,child := range &n.Children {
			if child != nil {
				restPath := TraverseArbitraryPath(child, preimages)
				if restPath[0] == "false" { 
					continue
				} else { 
					return append(restPath, "fullNode") 
				}
			}
		}
		return []string{"no valid child to fullNode"}
	case hashNode:
		// in some cases the hashNode isn't in the pre-images map so try a different one
		realHash := common.BytesToHash(n)
		actualNodeRaw, exists := preimages[realHash]
		actualNode, err := decodeNode(nil, actualNodeRaw)
		//actualNode, err := decodeNode(realHash.Bytes(), actualNodeRaw)
		if err != nil {
			return append([]string{}, fmt.Sprintf("%t", exists))
		} else { 
			return append(TraverseArbitraryPath(actualNode, preimages), "hashNode")
		}
	default:
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// get node referred to be `n` if it exists in `preimages`
func parseHashNode(n hashNode, preimages map[common.Hash][]byte) (node, bool, error) {
	realHash := common.BytesToHash(n)
	actualNodeRaw, exists := preimages[realHash]
	actualNode, err := decodeNode(nil, actualNodeRaw)
	//actualNode, err := decodeNode(realHash.Bytes(), actualNodeRaw)
	return actualNode, exists, err	
}

// DEBUG function NOT USED
func DoesStorageTrieExist(origNode node, preimages map[common.Hash][]byte, path []int) bool {
	switch n := (origNode).(type) {
	case valueNode:
		// decode the valueNode
		acc := new(types.StateAccount)
		err := rlp.DecodeBytes(n, acc)
		if err != nil { panic("Couldn't decode acount") }
		// if account has a state trie 
		storageTrieRootRaw, exists := preimages[acc.Root]
		if exists {
			storageTrieRoot, err := decodeNode(nil, storageTrieRootRaw)
			//storageTrieRoot, err := decodeNode(acc.Root.Bytes(), storageTrieRootRaw)
			if err != nil {
				panic("Couldn't decode storage trie root that exists")
			}
			n := GetSomeValueNode(storageTrieRoot, preimages)
			log.Info("Value node in storage trie.", "leaf", n)
			return true
		} else { 
			log.Info("storage trie doesn't exist")
			return false
		}
	case *shortNode:
		sanityCheckShortNode(n, preimages)
		//if !b { panic(fmt.Sprintf("[TrieExist] shortNode child isn't valueNode: %v", n.Val)) }
		return DoesStorageTrieExist(n.Val, preimages, path)
	case *fullNode:
		// exension nodes
		for i,child := range &n.Children {
			if child != nil {
				log.Info("Full node child.", "path", path, "idx", i)
				b := DoesStorageTrieExist(child, preimages, append(path, i))
				if b { return true }
			}
		}
		return false
	case hashNode:
		realHash := common.BytesToHash(n)
		actualNodeRaw, exists := preimages[realHash]
		actualNode, err := decodeNode(nil, actualNodeRaw)
		//actualNode, err := decodeNode(realHash.Bytes(), actualNodeRaw)
		//actualNode, exists, err := parseHashNode(n, preimages)
		if err == nil && exists {
			log.Info("HashNode decoded", "path", path)
			return DoesStorageTrieExist(actualNode, preimages, path)
		} else {
			log.Info("HashNode doesn't exist or can't be decoded", "path", path)
			return false
		}
	default:
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

