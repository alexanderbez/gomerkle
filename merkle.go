package gomerkle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
)

// Errors reflecting invalid operations on a Merkle tree.
var (
	ErrDirtyMerkleTree    = errors.New("merkle tree has not been finalized")
	ErrNotDirtyMerkleTree = errors.New("merkle tree has been finalized")
	ErrEmptyMerkleTree    = errors.New("merkle tree has no data blocks")
	ErrNilBlock           = errors.New("block cannot be nil")
)

var (
	internalNodePrefix = '\x01'
	leafNodePrefix     = '\x00'
)

type (
	// MerkleTree implements a binary complete Merkle tree data structure such
	// that every node is cryptographically hashed and is composed of the
	// hashes of it's children. If a node has no child, it is the cryptographic
	// hash of a data block. A Merkle tree allows for efficient and secure
	// verification of the existence of data blocks that lead up to a secure
	// root hash. A data block is any arbitrary data structure that can be
	// interpreted as a byte slice such as chunks of a file.
	//
	// Data blocks can be inserted into the Merkle tree in a given order where
	// the order is critical as it corelates to the construction of the root
	// hash. When the Merkle tree is ready to be constructed, it is "finalized"
	// such that the root hash is computed and proofs may be granted along with
	// verification of said proofs.
	MerkleTree struct {
		blocks []Block
		nodes  []Node
		root   Node
		dirty  bool
	}
)

// NewMerkleTree returns a reference to a new initialized Merkle tree with a
// given set of initial data blocks.
func NewMerkleTree(blocks ...Block) *MerkleTree {
	return &MerkleTree{
		blocks: blocks,
		dirty:  true,
	}
}

// String implements the Stringer interface. It returns the string-encoded root
// hash with a '0x' prefix.
func (mt *MerkleTree) String() (s string) {
	if rh, err := mt.RootHash(); err == nil {
		s = fmt.Sprintf("0x%s", hex.EncodeToString(rh))
	}

	return
}

// Insert inserts a new data block into the Merkle tree. This operations marks
// the tree as dirty and thus Finalize will need to be invoked to recreate the
// root hash. An error is returned if the given block is nil.
func (mt *MerkleTree) Insert(b Block) error {
	if b == nil {
		return ErrNilBlock
	}

	if !mt.dirty {
		return fmt.Errorf("cannot insert into Merkle tree: %v", ErrNotDirtyMerkleTree)
	}

	if mt.blocks == nil {
		mt.blocks = []Block{}
	}

	mt.blocks = append(mt.blocks, b)
	return nil
}

// RootHash returns the root hash of a finalized Merkle tree. An error is
// returned if the tree has not been finalized yet.
func (mt *MerkleTree) RootHash() ([]byte, error) {
	if mt.dirty {
		return nil, fmt.Errorf("invalid root hash: %v", ErrDirtyMerkleTree)
	}

	return copyNode(mt.root).Bytes(), nil
}

// Finalize builds a SHA256 cryptographically hashed Merkle tree from a list of
// data blocks. If no blocks exist in the tree, an error is returned. The
// following invariants will be enforced:
//
// All leaf nodes and root node will be encoded with a 0x00 byte prefix and all
// internal nodes will be encoded with a 0x01 byte prefix to prevent second
// pre-image attacks.
//
// If there are an odd number of leaf nodes, the last data block will be
// duplicated to create an even set.
func (mt *MerkleTree) Finalize() error {
	if len(mt.blocks) == 0 {
		return fmt.Errorf("failed to finalize: %v", ErrEmptyMerkleTree)
	}

	// no need to finalize the tree if it has already been constructed/finalized
	if !mt.dirty {
		return nil
	}

	if len(mt.blocks)%2 == 1 {
		mt.blocks = append(mt.blocks, mt.blocks[len(mt.blocks)-1])
	}

	// allocate total number of nodes needed for a complete (binary) Merkle tree
	mt.nodes = make([]Node, 2*len(mt.blocks)-1)

	// set leaf nodes from the blocks
	j := len(mt.nodes) - len(mt.blocks)
	for _, b := range mt.blocks {
		mt.nodes[j] = hashNode(b.Bytes(), false)
		j++
	}

	mt.root = mt.finalize(0)
	mt.dirty = false

	return nil
}

// finalize recursively fills out the Merkle tree starting at a given node by
// nodeIdx and a given depth for that node. In other words, it builds the
// Merkle tree from the ground up.
func (mt *MerkleTree) finalize(nodeIdx int) Node {
	if !mt.hasChild(nodeIdx) {
		return mt.nodes[nodeIdx]
	}

	left := mt.finalize(2*nodeIdx + 1)
	right := mt.finalize(2*nodeIdx + 2)

	mt.nodes[nodeIdx] = hashNode(append(left, right...), true)
	return mt.nodes[nodeIdx]
}

// Proof returns a cryptographic Merkle proof for the existence of some block.
// If the Merkle tree has not been finalized or if the block does not exist, an
// error is returned. Otherwise, a proof consisting of Nodes is returned
// following the given procedure:
//
// for any given node (starting at the provided block), add it's sibling to the
// proof and then set the current node to the current node's parent, repeating
// until the root is reached.
func (mt MerkleTree) Proof(block Block) ([]Node, error) {
	if mt.dirty {
		return nil, fmt.Errorf("cannot provide proof for a dirty Merkle tree")
	}

	leafIdx, err := mt.findLeaf(block)
	if err != nil {
		return nil, err
	}

	k := 0
	currNodeIdx := leafIdx
	proof := make([]Node, int(math.Log2(float64(len(mt.nodes)))))

	for currNodeIdx > 0 {
		// add the sibling of the current node to the proof
		if currNodeIdx%2 == 0 {
			// add left sibling
			proof[k] = copyNode(mt.nodes[currNodeIdx-1])
		} else {
			// add right sibling
			proof[k] = copyNode(mt.nodes[currNodeIdx+1])
		}

		k++

		// set the new current node to be the current node's parent
		currNodeIdx = (currNodeIdx - 1) / 2
	}

	// in case a proof was requested for a block on the second to last level,
	// remove the last empty proof chunk
	if proof[len(proof)-1] == nil {
		return proof[:len(proof)-1], nil
	}

	return proof, nil
}

// Verify performs a cryptographic Merkle tree verification for a given block
// and proof. If the given proof can be constructed up to the Merkle root
// correctly, the proof is valid. Otherwise, an error is returned.
func (mt MerkleTree) Verify(block Block, proof []Node) error {
	if mt.dirty {
		return fmt.Errorf("cannot validate proof for a dirty Merkle tree")
	}

	leafIdx, err := mt.findLeaf(block)
	if err != nil {
		return err
	}

	currNodeIdx := leafIdx

	for i, proofChunk := range proof {
		var parentNode Node

		proofChunkCpy := copyNode(proofChunk)
		currNodeCpy := copyNode(mt.nodes[currNodeIdx])

		if currNodeIdx%2 == 0 {
			parentNode = hashNode(append(proofChunkCpy, currNodeCpy...), true)
		} else {
			parentNode = hashNode(append(currNodeCpy, proofChunkCpy...), true)
		}

		parentNodeIdx := (currNodeIdx - 1) / 2
		matchNode := mt.nodes[parentNodeIdx]

		if !bytes.Equal(parentNode.Bytes(), matchNode.Bytes()) {
			return fmt.Errorf("invalid proof at index %d for block %X; got: %X, want: %X",
				i, block, parentNode.Bytes(), matchNode.Bytes())
		}

		currNodeIdx = parentNodeIdx
	}

	return nil
}

// findLeaf attempts to find a leaf node's index that corresponds to a given
// block. An error is returned if the block does not exist.
func (mt MerkleTree) findLeaf(block Block) (int, error) {
	var (
		leaf    Node
		leafIdx int
	)

	i := 0
	j := len(mt.nodes) - len(mt.blocks) // contains possible leaf index range

	// attempt to find the leaf corresponding to the block
	for i < len(mt.blocks) {
		if bytes.Equal(mt.blocks[i].Bytes(), block.Bytes()) {
			leaf = mt.nodes[j]
			leafIdx = j

			break
		}

		i++
		j++
	}

	if leaf == nil {
		return 0, fmt.Errorf("block does not exist: %v", hex.EncodeToString(block))
	}

	return leafIdx, nil
}

// hasChild returns true if a node at a given index in the Merkle tree has a
// child and false otherwise.
func (mt MerkleTree) hasChild(nodeIdx int) bool {
	n := len(mt.nodes)
	l := 2*nodeIdx + 1
	r := 2*nodeIdx + 2

	return l < n || r < n
}

// hashNode returns a SHA256 hash of a node's raw byte slice with a specified
// prefix which depends on if the node is internal or not.
func hashNode(data []byte, internal bool) Node {
	raw := make(Node, len(data)+1)

	if internal {
		raw[0] = byte(internalNodePrefix)
	}

	copy(raw[1:], data)
	sum := sha256.Sum256(raw)

	return Node(sum[:])
}

// copyNode returns a copy of a given Node.
func copyNode(node Node) Node {
	cpy := make(Node, len(node))
	copy(cpy, node)
	return cpy
}
