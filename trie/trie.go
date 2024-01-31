// Copyright 2014 The go-ethereum Authors
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

// Package trie implements Merkle Patricia Tries.
package trie

import (
	"os"
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"encoding/binary"
	"strconv"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-ethereum/triedb/database"
)

// Trie is a Merkle Patricia Trie. Use New to create a trie that sits on
// top of a database. Whenever trie performs a commit operation, the generated
// nodes will be gathered and returned in a set. Once the trie is committed,
// it's not usable anymore. Callers have to re-create the trie with new root
// based on the updated trie database.
//
// Trie is not safe for concurrent use.
type Trie struct {
	root  node
	owner common.Hash

	// Flag whether the commit operation is already performed. If so the
	// trie is not usable(latest states is invisible).
	committed bool

	// Keep track of the number leaves which have been inserted since the last
	// hashing operation. This number will not directly map to the number of
	// actually unhashed nodes.
	unhashed int

	// uncommitted is the number of updates since last commit.
	uncommitted int

	// reader is the handler trie can retrieve nodes from.
	reader *trieReader

	// tracer is the tool to track the trie changes.
	tracer *tracer
}

// newFlag returns the cache flag value for a newly created node.
func (t *Trie) newFlag() nodeFlag {
	return nodeFlag{dirty: true}
}

// Copy returns a copy of Trie.
func (t *Trie) Copy() *Trie {
	return &Trie{
		root:        t.root,
		owner:       t.owner,
		committed:   t.committed,
		reader:      t.reader,
		tracer:      t.tracer.copy(),
		uncommitted: t.uncommitted,
		unhashed:    t.unhashed,
	}
}

// New creates the trie instance with provided trie id and the read-only
// database. The state specified by trie id must be available, otherwise
// an error will be returned. The trie root specified by trie id can be
// zero hash or the sha3 hash of an empty string, then trie is initially
// empty, otherwise, the root node must be present in database or returns
// a MissingNodeError if not.
func New(id *ID, db database.NodeDatabase) (*Trie, error) {
	reader, err := newTrieReader(id.StateRoot, id.Owner, db)
	if err != nil {
		return nil, err
	}
	trie := &Trie{
		owner:  id.Owner,
		reader: reader,
		tracer: newTracer(),
	}
	if id.Root != (common.Hash{}) && id.Root != types.EmptyRootHash {
		rootnode, err := trie.resolveAndTrack(id.Root[:], nil)
		if err != nil {
			return nil, err
		}
		trie.root = rootnode
	}
	return trie, nil
}

// NewEmpty is a shortcut to create empty tree. It's mostly used in tests.
func NewEmpty(db database.NodeDatabase) *Trie {
	tr, _ := New(TrieID(types.EmptyRootHash), db)
	return tr
}

// MustNodeIterator is a wrapper of NodeIterator and will omit any encountered
// error but just print out an error message.
func (t *Trie) MustNodeIterator(start []byte) NodeIterator {
	it, err := t.NodeIterator(start)
	if err != nil {
		log.Error("Unhandled trie error in Trie.NodeIterator", "err", err)
	}
	return it
}

// NodeIterator returns an iterator that returns nodes of the trie. Iteration starts at
// the key after the given start key.
func (t *Trie) NodeIterator(start []byte) (NodeIterator, error) {
	// Short circuit if the trie is already committed and not usable.
	if t.committed {
		return nil, ErrCommitted
	}
	return newNodeIterator(t, start), nil
}

// MustGet is a wrapper of Get and will omit any encountered error but just
// print out an error message.
func (t *Trie) MustGet(key []byte) []byte {
	res, err := t.Get(key)
	if err != nil {
		log.Error("Unhandled trie error in Trie.Get", "err", err)
	}
	return res
}

// Get returns the value for key stored in the trie.
// The value bytes must not be modified by the caller.
//
// If the requested node is not present in trie, no error will be returned.
// If the trie is corrupted, a MissingNodeError is returned.
func (t *Trie) Get(key []byte) ([]byte, error) {
	// Short circuit if the trie is already committed and not usable.
	if t.committed {
		return nil, ErrCommitted
	}
	value, newroot, didResolve, err := t.get(t.root, keybytesToHex(key), 0)
	if err == nil && didResolve {
		t.root = newroot
	}
	return value, err
}

func (t *Trie) get(origNode node, key []byte, pos int) (value []byte, newnode node, didResolve bool, err error) {
	switch n := (origNode).(type) {
	case nil:
		return nil, nil, false, nil
	case valueNode:
		return n, n, false, nil
	case *shortNode:
		if !bytes.HasPrefix(key[pos:], n.Key) {
			// key not found in trie
			return nil, n, false, nil
		}
		value, newnode, didResolve, err = t.get(n.Val, key, pos+len(n.Key))
		if err == nil && didResolve {
			n = n.copy()
			n.Val = newnode
		}
		return value, n, didResolve, err
	case *fullNode:
		value, newnode, didResolve, err = t.get(n.Children[key[pos]], key, pos+1)
		if err == nil && didResolve {
			n = n.copy()
			n.Children[key[pos]] = newnode
		}
		return value, n, didResolve, err
	case hashNode:
		child, err := t.resolveAndTrack(n, key[:pos])
		if err != nil {
			return nil, n, true, err
		}
		value, newnode, _, err := t.get(child, key, pos)
		return value, newnode, true, err
	default:
		panic(fmt.Sprintf("%T: invalid node: %v", origNode, origNode))
	}
}

// MustGetNode is a wrapper of GetNode and will omit any encountered error but
// just print out an error message.
func (t *Trie) MustGetNode(path []byte) ([]byte, int) {
	item, resolved, err := t.GetNode(path)
	if err != nil {
		log.Error("Unhandled trie error in Trie.GetNode", "err", err)
	}
	return item, resolved
}


///////////////////////////////////////// cche functions ///////////////////////////////////////
// store nodes
type ValidatorTrie struct {
	Root node
    Nodes map[common.Hash][]byte
	Pathmap map[string]common.Hash
	Mutex *sync.RWMutex
}

// remove origNode from the ValidatorTrie Nodes map and add newNode
func (t *ValidatorTrie) UpdateNodePreimage(origNode node, newNode node, newPreimages map[common.Hash][]byte) bool {
	// check that origNode is in the current trie
	origHash := HashNode(origNode)
	//log.Info("[UpdateNodePreImage] origHash.", "origHash", origHash)
	_, ok := t.Nodes[origHash]
	if !ok { return false }

	// check new node is in new preimages
	newHash := HashNode(newNode)
	//log.Info("[UpdateNodePreImage] newHash", "newHash", newHash)
	newNodeBytes, ok := newPreimages[newHash]
	if !ok { return false }

	log.Info("Replacing hashs", "old", origHash, "new", newHash)

	delete(t.Nodes, origHash)
	t.Nodes[newHash] = newNodeBytes
	return true	
}

// ASSUMPTION: shortNode children are always valueNodes
func sanityCheckShortNode(n *shortNode) bool {
	switch (n.Val).(type) {
	case valueNode: return true
	default: return false
	}
}

// ASSUMPTION: fullNode children are always hashNodes or nil
func sanityCheckFullNode(n *fullNode) bool {
	for i,child := range(&n.Children) {
		if child != nil {
			switch (child).(type) {
			case valueNode, *shortNode, *fullNode:
				log.Info("Child of fullNode isn't a hashNode.", "node", HashNode(n), "idx", i)
				return false
			default: continue
			}
		}
	}
	return true
}

// return a list of indices of fullNode children which exist in the validator trie
func (t *ValidatorTrie) WhichNodesExist(n *fullNode) []int {
	r := []int{}
	for i, child := range &n.Children {
		if child != nil {
			hn, ok := child.(hashNode)
			if !ok {
				panic("couldn't convert fullNode child to hashNode")
			} else {
				_, exists := t.Nodes[common.BytesToHash(hn)]
				if exists {
					r = append(r, i)
				}
			}
		}
	}
	return r
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


// add the subtrie starting ate `n` to the ValidatorTrie, called by `UpdateTrie` when a new branch
// is expanded in a new input
func (t *ValidatorTrie) AddSubTrie(n node, preimages map[common.Hash][]byte) bool {
	switch n := n.(type) {
	case valueNode: panic("[AddSubTrie] never reach valueNode")
	case *shortNode: 
		b := sanityCheckShortNode(n)
		if !b { panic(fmt.Sprintf("[AddTrie] shortNode child isn't valueNode: %v", n.Val)) }
		return true	// nothing to do tese aways lead to valueNodes
	case *fullNode:
		ok := sanityCheckFullNode(n)
		if !ok {
			panic(fmt.Sprintf("Failed to check fullNode. node=%v", n))
		}
		log.Info("[AddTrie] adding a fullNode")
		res := true
		for i, child := range &n.Children {
			if child != nil {
				log.Info("Trying child", "idx", i)
				r := t.AddSubTrie(child, preimages)
				if !r {
					res = false
				}
			}
		}
		return res
	case hashNode:
		// only the hashNodes are saved to the Nodes map because
		// all nodes appear from hashNodes in the input we received 
		// see `sanityCheck...` functions
		realHash := common.BytesToHash(n)
		actualNodeRaw, exists := preimages[realHash]
		log.Info("[AddTrie] hashNode exists", "hashNode", realHash)
		if exists {
			actualNode, err := decodeNode(realHash.Bytes(), actualNodeRaw)
			if err != nil {
				panic("Failed to decode node from hashNode in addSubTrie")
			}
			// add the hash to the trie
			t.Nodes[realHash] = preimages[realHash]
			return t.AddSubTrie(actualNode, preimages)
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
	return t.UpdateTrie(newRoot, t.Root, preimages, []int{})
}

// update trie with new information
// full nodes:
//    we expect at least one child of the full node is the same as before, check and panic if not
//    if a child exists that doesn't exist in the current trie, add the whole subtrie to the cache
//    if a child exists from before but it's hash is different, recurse. If return true, then update this full node in the cache
func (t *ValidatorTrie) UpdateTrie(newRoot node, oldRoot node, preimages map[common.Hash][]byte, path []int) bool {
	switch n := newRoot.(type) {
	case valueNode: panic("Should never reach a valueNode")
	case *shortNode:
		// assert the two nodes in the tries are the same type
		oldsn, ok := oldRoot.(*shortNode)
		if !ok { panic(fmt.Sprintf("The tries differ here. Path=%v, old=%v, new=%v", path, oldRoot, newRoot)) }

		// Our assumption from data input is that shortNode.Val is always a fullNode 
		ok1 := sanityCheckShortNode(n)
		ok2 := sanityCheckShortNode(oldsn)
		if !ok1 || !ok2 { panic(fmt.Sprintf("Val of shortNode isn't a valueNode. Old=%v, new=%v", oldsn, n)) }

		// We only replace the hash of the short node because it contains itself and its child
		return t.UpdateNodePreimage(oldsn, n, preimages)
	case *fullNode:	
		// try to parse the analogous node in the cache as a full node
		oldfn, ok := oldRoot.(*fullNode)
		log.Info(fmt.Sprintf("Full nodes at path %v. new: %v, old: %v", path, HashNode(n), HashNode(oldfn)))
		if !ok { panic(fmt.Sprintf("New node at path %v is fullNode but original node isn't!", path)) }

		// Check assumption that ALL children of fullNodes are hashNodes
		oknew := sanityCheckFullNode(n)
		okold := sanityCheckFullNode(oldfn)
		if !oknew { panic(fmt.Sprintf("Failed to check NEW fullNode. path=%v, node=%v", path, n)) }
		if !okold { panic(fmt.Sprintf("Failed to check OLD fullNode. path=%v, node=%v", path, oldfn)) }

		// DEBUG: Not guaranteed but we assert that at least one child of a full node is the same
		// low probability that all are accessed and modified in a single input
		anyMatch := false
		for i := range &n.Children {
			oldC := oldfn.Children[i]
			newC := n.Children[i]
			if (oldC != nil && newC != nil) && (bytes.Equal(oldC.(hashNode), newC.(hashNode))) { anyMatch = true }
		}
		if !anyMatch { panic(fmt.Sprintf("None of the children are the same.\n\told node: %v\n\t newnode: %v", n, oldfn)) }
		// ^^^ DEBUG

		// now process the updates to the trie
		allGoodRecursion := true
		for i := range &n.Children {
			oldC := oldfn.Children[i]
			newC := n.Children[i]

			// If both nodes aren't nil then find differences to update with
			if oldC != nil && newC != nil {
				_, oldExists := t.Nodes[common.BytesToHash(oldC.(hashNode))]
				_, newExists := preimages[common.BytesToHash(newC.(hashNode))]
				// are their hashes the same
				sameNode := (bytes.Equal(oldC.(hashNode), newC.(hashNode)))
				if !sameNode {		// DEBUG statement
					log.Info("FullNode children differ.", "idx", i, "old", oldC, "new", newC, "path", path)
				}

				if newExists && !oldExists {
					// this child isn't expanded currently, but this new input expands it so add it to the trie
					log.Info(">>>>>New expansion (new and !old)", "path", path, "parent", HashNode(n), "oldC", HashNode(oldC), "newC", HashNode(newC), "idx", i)
					allGoodRecursion = allGoodRecursion && t.AddSubTrie(newC, preimages)
				} else if (oldExists && !newExists) && !sameNode {
					// should be impossible for the hash of this child to change but the node isn't expanded in the new input
					panic(fmt.Sprintf("New validation doesn't subTrie at index %v at path %v so the two children should be the same. Old: %v, new: %v. Root: %v\n oldfn: %v\n newfn: %v", i, path, oldC, newC, t.Root, oldfn, n))
				} else if (!oldExists && !newExists) && !sameNode {
					// should be impossible for the hash to change but no information is known about the children of these nodes
					panic(fmt.Sprintf("Neither expand indx %v at path %v so the two children should be the same. Old: %v, new: %v", i, path, oldC, newC)) 
				} else {
					// they both are expanded so we recurse and keep update hashes OR adding subtries
					log.Info(">>>>>Both exist and recurse", "path", path, "parent", HashNode(n), "oldC", HashNode(oldC), "newC", HashNode(newC), "idx", i)
					allGoodRecursion = allGoodRecursion && t.UpdateTrie(newC, oldC, preimages, append(path, i))
				}
			} else if oldC == nil && newC != nil {
				// if going from nil to not nil then this is a new subtrie
				allGoodRecursion = allGoodRecursion && t.AddSubTrie(newC, preimages)
			} else if oldC != nil && newC == nil {
				// if going from !nil to nil then panic because we don't know how to handle
				// trie rebalancing (this must be the reason?)
				panic(fmt.Sprintf("A child went from not nil to nil, what is happening? Path: %v", path))
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
				log.Info("Full Nodes differ, replacing the node.", "old", oldfnHash, "new", newfnHash, "path", path)
				return t.UpdateNodePreimage(oldfn, n, preimages)
			} else {
				// they are the same so nothing to do
				log.Info("Full nodes are the SAME", "old", oldfnHash, "new", newfnHash, "path", path)
			}
		} else {
			// either a call to AddSubTrie or UpdateTrie failed
			log.Info("recursion not all good")
		}
		return allGoodRecursion
	case hashNode:
		// if we reach here this means that they both exist in both tries already
		// assert we have the same type of node
		oldhn, ok := oldRoot.(hashNode)
		if !ok { panic(fmt.Sprintf("New node at path %v is hashNode but original node isn't!", path)) }
		// if they aren't the same hash we don't care here because we save actual node hashes in the other cases of this switch statement. fullNodes carry these hashNodes as their children
		newHash := common.BytesToHash(n)
		oldHash := common.BytesToHash(oldhn)
		newRaw, existNew := preimages[newHash]
		oldRaw, existOld := t.Nodes[oldHash]

		if !existNew || !existOld { 	// If either node doesn't exist something is wrong in the data
			panic(fmt.Sprintf("we recursed meaning both hash nodes exist but couldn't look them up! path: %v, oldhash: %v, newHash: %v", path, oldHash, newHash))
		}
		newNode, errNew := decodeNode(newHash.Bytes(), newRaw)
		oldNode, errOld := decodeNode(oldHash.Bytes(), oldRaw)
		if (errNew != nil || errOld != nil) {	// If we can't decode the nodes something is wrong
			panic(fmt.Sprintf("Couldn't decode new or old node. errNew: %v\nerrOld: %v", errNew, errOld))
		}
		// Continue update the trie
		return t.UpdateTrie(newNode, oldNode, preimages, path)
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
			actualNode, err := decodeNode(realHash.Bytes(), actualNodeRaw)
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

// size of trie rooted at `origNode` in bytes (unsafe)
func (t *ValidatorTrie) sizeFromNode(origNode node) int {
	nodeHash := HashNode(origNode)
	switch n := (origNode).(type) {
	// valueNode isn't reached because it is encoded in shortNode
	case *shortNode: 
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
				fullSize += t.sizeFromNode(child)
			}
		}
		tn := t.Nodes[nodeHash]
		return binary.Size(tn) + fullSize
	case hashNode:
		// hashNodes will be accounted for in the encoding of the fullNode so don't add 32
		// to the recursive case
		realHash := common.BytesToHash(n)
		actualNodeRaw, exists := t.Nodes[realHash]
		actualNode, err := decodeNode(realHash.Bytes(), actualNodeRaw)
		if (!exists || err != nil) {
			return 0  // node doesn't exist in cache or couldnot be decoded if nil
		} else {
			return t.sizeFromNode(actualNode)
		}
	default: panic("unknown type of node")
	}
}

// get node from `preimages` corresponding to the preimage `n`
func NodeFromHashNode(n hashNode, preimages map[common.Hash][]byte) (node, bool) {
	realHash := common.BytesToHash(n)
	actualNodeRaw, exists := preimages[realHash]
	actualNode, err := decodeNode(realHash.Bytes(), actualNodeRaw)
	if (err != nil || !exists) {
		return nilValueNode, false
	}
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

func (t *ValidatorTrie) NumChildrenExistUnsafe(n node) int {
	switch n := (n).(type) {
	case *fullNode:
		num := 0
		for _, child := range &n.Children {
			if child != nil {
				_, exists := t.Nodes[HashNode(child)]
				if exists {
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

// number of nodes in validator trie rooted at origNode
func (t *ValidatorTrie) NumNodesUnsafe(origNode node) int {
	switch n := (origNode).(type) {
	case *shortNode: return 1
	case *fullNode:
		num := 0
		for _, child := range &n.Children {
			if child != nil {
				num += t.NumNodesUnsafe(child)
			}
		}
		return 1 + num
	case hashNode:
		actualNode, exists := NodeFromHashNode(n, t.Nodes)
		if !exists {
			return 0
		} else {
			return t.NumNodesUnsafe(actualNode) 
		}	
	case valueNode: panic("should never get to a valueNode")
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
		// save current path as path for this type
		h := HashNode(n)
		_, ok := t.Nodes[h]
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
			nextNode, err := decodeNode(realHash.Bytes(), rawNode)
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

// only need to store preimages of hashNodes everything else is in encoded data

// DOesn't need to be thread-safe
func TrieFromNode(n node, preimages map[common.Hash][]byte) ([]common.Hash) {
	switch n := (n).(type) {
	case valueNode: 
		log.Info("valueNode reached", "valueNode", n)
		return []common.Hash{}
	case *shortNode:
		// shortNodes are extensions or valueNodes
		// they are usually stored as hashNodes so don't save anything here
		log.Info("shortNode expansion", "short node", HashNode(n))
		return TrieFromNode(n.Val, preimages)
	case *fullNode:
		// exension nodes
		log.Info("fullNode expansion", "full node", HashNode(n))
		ok := sanityCheckFullNode(n)
		if !ok {
			panic(fmt.Sprintf("Failed to check fullNode. node=%v", n))
		}
		finalList := []common.Hash{}
		for _,child := range &n.Children {
			// save all hashes from subtrie
			if child != nil {
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
		actualNode, err := decodeNode(realHash.Bytes(), actualNodeRaw)
		finalList := []common.Hash{}
		// if it is expanded go down the path
		if err == nil && exists {
			log.Info("Expanding hashNode in creating subtrie.", "hash", realHash)
			finalList = append([]common.Hash{realHash}, TrieFromNode(actualNode,preimages)...)
		}
		return finalList
	default:
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// IMPORTANT CHANGE: 
//		The root node is stored as a shortNode

// ASSUME lock around preimages
func ChooseRandomNode (n node, preimages map[common.Hash][]byte, height int) ([]int)  {
	switch n := (n).(type) {
	case *fullNode:
		// could be the root node
		ok := sanityCheckFullNode(n)
		if !ok {
			panic(fmt.Sprintf("Failed to check fullNode. node=%v", n))
		}
		for {
			// choose random index
			randIdx := rand.Intn(17)
			// check if the child exists in the map
			child := n.Children[randIdx]
			hashNodeChild, ok := child.(hashNode)
			if child != nil && ok {
				childHash := common.BytesToHash(hashNodeChild)
				actualNodeRaw, exists := preimages[childHash]
				fullNode, err := decodeNode(childHash.Bytes(), actualNodeRaw)
				if exists && err == nil { 
					// we can go down this path
					if (height > 1) {
						return append([]int{randIdx}, ChooseRandomFullNode(fullNode, preimages, height-1)...)
					} else {
						return []int{randIdx}
					}
				}
			}
		}
	default: // don't do anything for other nodes we should never get there				
		panic ("the case went through witout any return")
	}
}

// used by validator to choose a random full node as the cache trie root
func ChooseRandomFullNode (origNode node, preimages map[common.Hash][]byte, height int) ([] int) {
	for {
		choice := ChooseRandomNode(origNode, preimages, height)
		n, exists := NodeFromPath(origNode, choice, preimages)
		if (!exists) { panic("Node gotten from trie no longer exists") }
		switch n.(type) {
		case *fullNode: return choice
		default:
		}
	}
}

// returns the types of nodes on a path as a list of strings
func NodeTypesOnPath(n node, preimages map[common.Hash][]byte, path []int) ([]string) {	
	switch n := n.(type) {
	case valueNode: return []string{"valueNode"}
	case *shortNode: return append([]string{"shortNode"}, NodeTypesOnPath(n.Val, preimages, path)...)
	case *fullNode: return append([]string{"fullNode"}, NodeTypesOnPath(n.Children[path[0]], preimages, path[1:])...)
	case hashNode:
		realHash := common.BytesToHash(n)
		actualNodeRaw, _ := preimages[realHash]
		actualNode, _ := decodeNode(realHash.Bytes(), actualNodeRaw)
		return append([]string{"hashNode"}, NodeTypesOnPath(actualNode, preimages, path)...)
	default: panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
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
	return common.BytesToHash(hash.(hashNode))
}

// hash of the node at `path` rooted at `n`
func NodeHashFromPath (n node, path []int, preimages map[common.Hash][]byte) (common.Hash, bool) {
	switch n := (n).(type) {
	case *fullNode:
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
		realHash := common.BytesToHash(n)
		actualNodeRaw, exists := preimages[realHash]
		if !exists { return realHash, false }
		actualNode, _ := decodeNode(realHash.Bytes(), actualNodeRaw)
		// validation of hashing
		testHash := HashNode(actualNode)
		if testHash != realHash { panic("can't hash properly") }
		return NodeHashFromPath(actualNode, path, preimages)
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
	actualNode, _ := decodeNode(h.Bytes(), raw)
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
		actualNode, err := decodeNode(realHash.Bytes(), actualNodeRaw)
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
	actualNode, err := decodeNode(realHash.Bytes(), actualNodeRaw)
	return actualNode, exists, err	
}

// DEBUG function NOT USED
func DoesStorageTrieExist(origNode node, preimages map[common.Hash][]byte) bool {
	switch n := (origNode).(type) {
	case valueNode:
		// decode the valueNode
		acc := new(types.StateAccount)
		err := rlp.DecodeBytes(n, acc)
		if err != nil { panic("Couldn't decode acount") }
		// if account has a state trie 
		storageTrieRootRaw, exists := preimages[acc.Root]
		if exists {
			storageTrieRoot, err := decodeNode(acc.Root.Bytes(), storageTrieRootRaw)
			if err != nil {
				panic("Couldn't decode storage trie root that exists")
			}
			n := GetSomeValueNode(storageTrieRoot, preimages)
			log.Info("Value node in storage trie.", "leaf", n)
			return true
		} else { 
			return false
		}
	case *shortNode:
		b := sanityCheckShortNode(n)
		if !b { panic(fmt.Sprintf("[AddTrie] shortNode child isn't valueNode: %v", n.Val)) }
		return DoesStorageTrieExist(n.Val, preimages)
	case *fullNode:
		// exension nodes
		for _,child := range &n.Children {
			if child != nil {
				b := DoesStorageTrieExist(child, preimages)
				if b { return true }
			}
		}
		return false
	case hashNode:
		//realHash := common.BytesToHash(n)
		//actualNodeRaw, exists := preimages[realHash]
		//actualNode, err := decodeNode(realHash.Bytes(), actualNodeRaw)
		actualNode, exists, err := parseHashNode(n, preimages)
		if err != nil && exists {
			return DoesStorageTrieExist(actualNode, preimages)
		} else {
			return false
		}
	default:
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

/////////////////////////////////////// fin cache ///////////////////////////////////////////

// GetNode retrieves a trie node by compact-encoded path. It is not possible
// to use keybyte-encoding as the path might contain odd nibbles.
//
// If the requested node is not present in trie, no error will be returned.
// If the trie is corrupted, a MissingNodeError is returned.
func (t *Trie) GetNode(path []byte) ([]byte, int, error) {
	// Short circuit if the trie is already committed and not usable.
	if t.committed {
		return nil, 0, ErrCommitted
	}
	item, newroot, resolved, err := t.getNode(t.root, compactToHex(path), 0)
	if err != nil {
		return nil, resolved, err
	}
	if resolved > 0 {
		t.root = newroot
	}
	return item, resolved, nil
}

func (t *Trie) getNode(origNode node, path []byte, pos int) (item []byte, newnode node, resolved int, err error) {
	// If non-existent path requested, abort
	if origNode == nil {
		return nil, nil, 0, nil
	}
	// If we reached the requested path, return the current node
	if pos >= len(path) {
		// Although we most probably have the original node expanded, encoding
		// that into consensus form can be nasty (needs to cascade down) and
		// time consuming. Instead, just pull the hash up from disk directly.
		var hash hashNode
		if node, ok := origNode.(hashNode); ok {
			hash = node
		} else {
			hash, _ = origNode.cache()
		}
		if hash == nil {
			return nil, origNode, 0, errors.New("non-consensus node")
		}
		blob, err := t.reader.node(path, common.BytesToHash(hash))
		return blob, origNode, 1, err
	}
	// Path still needs to be traversed, descend into children
	switch n := (origNode).(type) {
	case valueNode:
		// Path prematurely ended, abort
		return nil, nil, 0, nil

	case *shortNode:
		if !bytes.HasPrefix(path[pos:], n.Key) {
			// Path branches off from short node
			return nil, n, 0, nil
		}
		item, newnode, resolved, err = t.getNode(n.Val, path, pos+len(n.Key))
		if err == nil && resolved > 0 {
			n = n.copy()
			n.Val = newnode
		}
		return item, n, resolved, err

	case *fullNode:
		item, newnode, resolved, err = t.getNode(n.Children[path[pos]], path, pos+1)
		if err == nil && resolved > 0 {
			n = n.copy()
			n.Children[path[pos]] = newnode
		}
		return item, n, resolved, err

	case hashNode:
		child, err := t.resolveAndTrack(n, path[:pos])
		if err != nil {
			return nil, n, 1, err
		}
		item, newnode, resolved, err := t.getNode(child, path, pos)
		return item, newnode, resolved + 1, err

	default:
		panic(fmt.Sprintf("%T: invalid node: %v", origNode, origNode))
	}
}

// MustUpdate is a wrapper of Update and will omit any encountered error but
// just print out an error message.
func (t *Trie) MustUpdate(key, value []byte) {
	if err := t.Update(key, value); err != nil {
		log.Error("Unhandled trie error in Trie.Update", "err", err)
	}
}

// Update associates key with value in the trie. Subsequent calls to
// Get will return value. If value has length zero, any existing value
// is deleted from the trie and calls to Get will return nil.
//
// The value bytes must not be modified by the caller while they are
// stored in the trie.
//
// If the requested node is not present in trie, no error will be returned.
// If the trie is corrupted, a MissingNodeError is returned.
func (t *Trie) Update(key, value []byte) error {
	// Short circuit if the trie is already committed and not usable.
	if t.committed {
		return ErrCommitted
	}
	return t.update(key, value)
}

func (t *Trie) update(key, value []byte) error {
	t.unhashed++
	t.uncommitted++
	k := keybytesToHex(key)
	if len(value) != 0 {
		_, n, err := t.insert(t.root, nil, k, valueNode(value))
		if err != nil {
			return err
		}
		t.root = n
	} else {
		_, n, err := t.delete(t.root, nil, k)
		if err != nil {
			return err
		}
		t.root = n
	}
	return nil
}

func (t *Trie) insert(n node, prefix, key []byte, value node) (bool, node, error) {
	if len(key) == 0 {
		if v, ok := n.(valueNode); ok {
			return !bytes.Equal(v, value.(valueNode)), value, nil
		}
		return true, value, nil
	}
	switch n := n.(type) {
	case *shortNode:
		matchlen := prefixLen(key, n.Key)
		// If the whole key matches, keep this short node as is
		// and only update the value.
		if matchlen == len(n.Key) {
			dirty, nn, err := t.insert(n.Val, append(prefix, key[:matchlen]...), key[matchlen:], value)
			if !dirty || err != nil {
				return false, n, err
			}
			return true, &shortNode{n.Key, nn, t.newFlag()}, nil
		}
		// Otherwise branch out at the index where they differ.
		branch := &fullNode{flags: t.newFlag()}
		var err error
		_, branch.Children[n.Key[matchlen]], err = t.insert(nil, append(prefix, n.Key[:matchlen+1]...), n.Key[matchlen+1:], n.Val)
		if err != nil {
			return false, nil, err
		}
		_, branch.Children[key[matchlen]], err = t.insert(nil, append(prefix, key[:matchlen+1]...), key[matchlen+1:], value)
		if err != nil {
			return false, nil, err
		}
		// Replace this shortNode with the branch if it occurs at index 0.
		if matchlen == 0 {
			return true, branch, nil
		}
		// New branch node is created as a child of the original short node.
		// Track the newly inserted node in the tracer. The node identifier
		// passed is the path from the root node.
		t.tracer.onInsert(append(prefix, key[:matchlen]...))

		// Replace it with a short node leading up to the branch.
		return true, &shortNode{key[:matchlen], branch, t.newFlag()}, nil

	case *fullNode:
		dirty, nn, err := t.insert(n.Children[key[0]], append(prefix, key[0]), key[1:], value)
		if !dirty || err != nil {
			return false, n, err
		}
		n = n.copy()
		n.flags = t.newFlag()
		n.Children[key[0]] = nn
		return true, n, nil

	case nil:
		// New short node is created and track it in the tracer. The node identifier
		// passed is the path from the root node. Note the valueNode won't be tracked
		// since it's always embedded in its parent.
		t.tracer.onInsert(prefix)

		return true, &shortNode{key, value, t.newFlag()}, nil

	case hashNode:
		// We've hit a part of the trie that isn't loaded yet. Load
		// the node and insert into it. This leaves all child nodes on
		// the path to the value in the trie.
		rn, err := t.resolveAndTrack(n, prefix)
		if err != nil {
			return false, nil, err
		}
		dirty, nn, err := t.insert(rn, prefix, key, value)
		if !dirty || err != nil {
			return false, rn, err
		}
		return true, nn, nil

	default:
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// MustDelete is a wrapper of Delete and will omit any encountered error but
// just print out an error message.
func (t *Trie) MustDelete(key []byte) {
	if err := t.Delete(key); err != nil {
		log.Error("Unhandled trie error in Trie.Delete", "err", err)
	}
}

// Delete removes any existing value for key from the trie.
//
// If the requested node is not present in trie, no error will be returned.
// If the trie is corrupted, a MissingNodeError is returned.
func (t *Trie) Delete(key []byte) error {
	// Short circuit if the trie is already committed and not usable.
	if t.committed {
		return ErrCommitted
	}
	t.uncommitted++
	t.unhashed++
	k := keybytesToHex(key)
	_, n, err := t.delete(t.root, nil, k)
	if err != nil {
		return err
	}
	t.root = n
	return nil
}

// delete returns the new root of the trie with key deleted.
// It reduces the trie to minimal form by simplifying
// nodes on the way up after deleting recursively.
func (t *Trie) delete(n node, prefix, key []byte) (bool, node, error) {
	switch n := n.(type) {
	case *shortNode:
		matchlen := prefixLen(key, n.Key)
		if matchlen < len(n.Key) {
			return false, n, nil // don't replace n on mismatch
		}
		if matchlen == len(key) {
			// The matched short node is deleted entirely and track
			// it in the deletion set. The same the valueNode doesn't
			// need to be tracked at all since it's always embedded.
			t.tracer.onDelete(prefix)

			return true, nil, nil // remove n entirely for whole matches
		}
		// The key is longer than n.Key. Remove the remaining suffix
		// from the subtrie. Child can never be nil here since the
		// subtrie must contain at least two other values with keys
		// longer than n.Key.
		dirty, child, err := t.delete(n.Val, append(prefix, key[:len(n.Key)]...), key[len(n.Key):])
		if !dirty || err != nil {
			return false, n, err
		}
		switch child := child.(type) {
		case *shortNode:
			// The child shortNode is merged into its parent, track
			// is deleted as well.
			t.tracer.onDelete(append(prefix, n.Key...))

			// Deleting from the subtrie reduced it to another
			// short node. Merge the nodes to avoid creating a
			// shortNode{..., shortNode{...}}. Use concat (which
			// always creates a new slice) instead of append to
			// avoid modifying n.Key since it might be shared with
			// other nodes.
			return true, &shortNode{concat(n.Key, child.Key...), child.Val, t.newFlag()}, nil
		default:
			return true, &shortNode{n.Key, child, t.newFlag()}, nil
		}

	case *fullNode:
		dirty, nn, err := t.delete(n.Children[key[0]], append(prefix, key[0]), key[1:])
		if !dirty || err != nil {
			return false, n, err
		}
		n = n.copy()
		n.flags = t.newFlag()
		n.Children[key[0]] = nn

		// Because n is a full node, it must've contained at least two children
		// before the delete operation. If the new child value is non-nil, n still
		// has at least two children after the deletion, and cannot be reduced to
		// a short node.
		if nn != nil {
			return true, n, nil
		}
		// Reduction:
		// Check how many non-nil entries are left after deleting and
		// reduce the full node to a short node if only one entry is
		// left. Since n must've contained at least two children
		// before deletion (otherwise it would not be a full node) n
		// can never be reduced to nil.
		//
		// When the loop is done, pos contains the index of the single
		// value that is left in n or -2 if n contains at least two
		// values.
		pos := -1
		for i, cld := range &n.Children {
			if cld != nil {
				if pos == -1 {
					pos = i
				} else {
					pos = -2
					break
				}
			}
		}
		if pos >= 0 {
			if pos != 16 {
				// If the remaining entry is a short node, it replaces
				// n and its key gets the missing nibble tacked to the
				// front. This avoids creating an invalid
				// shortNode{..., shortNode{...}}.  Since the entry
				// might not be loaded yet, resolve it just for this
				// check.
				cnode, err := t.resolve(n.Children[pos], append(prefix, byte(pos)))
				if err != nil {
					return false, nil, err
				}
				if cnode, ok := cnode.(*shortNode); ok {
					// Replace the entire full node with the short node.
					// Mark the original short node as deleted since the
					// value is embedded into the parent now.
					t.tracer.onDelete(append(prefix, byte(pos)))

					k := append([]byte{byte(pos)}, cnode.Key...)
					return true, &shortNode{k, cnode.Val, t.newFlag()}, nil
				}
			}
			// Otherwise, n is replaced by a one-nibble short node
			// containing the child.
			return true, &shortNode{[]byte{byte(pos)}, n.Children[pos], t.newFlag()}, nil
		}
		// n still contains at least two values and cannot be reduced.
		return true, n, nil

	case valueNode:
		return true, nil, nil

	case nil:
		return false, nil, nil

	case hashNode:
		// We've hit a part of the trie that isn't loaded yet. Load
		// the node and delete from it. This leaves all child nodes on
		// the path to the value in the trie.
		rn, err := t.resolveAndTrack(n, prefix)
		if err != nil {
			return false, nil, err
		}
		dirty, nn, err := t.delete(rn, prefix, key)
		if !dirty || err != nil {
			return false, rn, err
		}
		return true, nn, nil

	default:
		panic(fmt.Sprintf("%T: invalid node: %v (%v)", n, n, key))
	}
}

func concat(s1 []byte, s2 ...byte) []byte {
	r := make([]byte, len(s1)+len(s2))
	copy(r, s1)
	copy(r[len(s1):], s2)
	return r
}

func (t *Trie) resolve(n node, prefix []byte) (node, error) {
	if n, ok := n.(hashNode); ok {
		return t.resolveAndTrack(n, prefix)
	}
	return n, nil
}

// resolveAndTrack loads node from the underlying store with the given node hash
// and path prefix and also tracks the loaded node blob in tracer treated as the
// node's original value. The rlp-encoded blob is preferred to be loaded from
// database because it's easy to decode node while complex to encode node to blob.
func (t *Trie) resolveAndTrack(n hashNode, prefix []byte) (node, error) {
	blob, err := t.reader.node(prefix, common.BytesToHash(n))
	if err != nil {
		return nil, err
	}
	t.tracer.onRead(prefix, blob)
	return mustDecodeNode(n, blob), nil
}

// Hash returns the root hash of the trie. It does not write to the
// database and can be used even if the trie doesn't have one.
func (t *Trie) Hash() common.Hash {
	hash, cached := t.hashRoot()
	t.root = cached
	return common.BytesToHash(hash.(hashNode))
}

// Commit collects all dirty nodes in the trie and replaces them with the
// corresponding node hash. All collected nodes (including dirty leaves if
// collectLeaf is true) will be encapsulated into a nodeset for return.
// The returned nodeset can be nil if the trie is clean (nothing to commit).
// Once the trie is committed, it's not usable anymore. A new trie must
// be created with new root and updated trie database for following usage
func (t *Trie) Commit(collectLeaf bool) (common.Hash, *trienode.NodeSet) {
	defer func() {
		t.committed = true
	}()
	// Trie is empty and can be classified into two types of situations:
	// (a) The trie was empty and no update happens => return nil
	// (b) The trie was non-empty and all nodes are dropped => return
	//     the node set includes all deleted nodes
	if t.root == nil {
		paths := t.tracer.deletedNodes()
		if len(paths) == 0 {
			return types.EmptyRootHash, nil // case (a)
		}
		nodes := trienode.NewNodeSet(t.owner)
		for _, path := range paths {
			nodes.AddNode([]byte(path), trienode.NewDeleted())
		}
		return types.EmptyRootHash, nodes // case (b)
	}
	// Derive the hash for all dirty nodes first. We hold the assumption
	// in the following procedure that all nodes are hashed.
	rootHash := t.Hash()

	// Do a quick check if we really need to commit. This can happen e.g.
	// if we load a trie for reading storage values, but don't write to it.
	if hashedNode, dirty := t.root.cache(); !dirty {
		// Replace the root node with the origin hash in order to
		// ensure all resolved nodes are dropped after the commit.
		t.root = hashedNode
		return rootHash, nil
	}
	nodes := trienode.NewNodeSet(t.owner)
	for _, path := range t.tracer.deletedNodes() {
		nodes.AddNode([]byte(path), trienode.NewDeleted())
	}
	// If the number of changes is below 100, we let one thread handle it
	t.root = newCommitter(nodes, t.tracer, collectLeaf).Commit(t.root, t.uncommitted > 100)
	t.uncommitted = 0
	return rootHash, nodes
}

// hashRoot calculates the root hash of the given trie
func (t *Trie) hashRoot() (node, node) {
	if t.root == nil {
		return hashNode(types.EmptyRootHash.Bytes()), nil
	}
	// If the number of changes is below 100, we let one thread handle it
	h := newHasher(t.unhashed >= 100)
	defer func() {
		returnHasherToPool(h)
		t.unhashed = 0
	}()
	hashed, cached := h.hash(t.root, true)
	return hashed, cached
}

// Witness returns a set containing all trie nodes that have been accessed.
func (t *Trie) Witness() map[string]struct{} {
	if len(t.tracer.accessList) == 0 {
		return nil
	}
	witness := make(map[string]struct{}, len(t.tracer.accessList))
	for _, node := range t.tracer.accessList {
		witness[string(node)] = struct{}{}
	}
	return witness
}

// Reset drops the referenced root node and cleans all internal state.
func (t *Trie) Reset() {
	t.root = nil
	t.owner = common.Hash{}
	t.unhashed = 0
	t.uncommitted = 0
	t.tracer.reset()
	t.committed = false
}
