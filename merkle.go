package gomerkle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
)

var (
	// ErrDirtyMerkleTree reflects an error signifying the Merkle tree hash not
	// yet been finalized.
	ErrDirtyMerkleTree = errors.New("merkle tree has not been finalized")
	// ErrEmptyMerkleTree reflects an error signifying the Merkle tree is
	// empty.
	ErrEmptyMerkleTree = errors.New("merkle tree has no data blocks")

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
	// the order is important as it corelates to the construction of the root
	// hash. When the Merkle tree is ready to be constructed, it is "finalized"
	// such that the root hash is computed and proofs may be granted along with
	// verification of said proofs.
	MerkleTree struct {
		blocks []Block
		nodes  []Hash
		root   Hash
		dirty  bool
		depth  int
	}

	// Block reflects a block of data to be stored in the tree.
	Block []byte
	// Hash reflects a unique and uniformly distributed hash of a node in the
	// tree.
	Hash []byte
)

// NewMerkleTree returns a reference to a new initialized Merkle tree with a
// given set of initial data blocks.
func NewMerkleTree(blocks ...Block) *MerkleTree {
	return &MerkleTree{
		blocks: blocks,
		dirty:  true,
	}
}

// Insert inserts a new data block into the Merkle tree. This operations marks
// the tree as dirty and thus Finalize will need to be invoked to recreate the
// root hash.
func (mt *MerkleTree) Insert(b Block) {
	if b == nil {
		return
	}

	mt.dirty = true

	if mt.blocks == nil {
		mt.blocks = []Block{}
	}

	mt.blocks = append(mt.blocks, b)
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

	// no need to finalize the tree if it has already been constructed
	if !mt.dirty {
		return nil
	}

	if len(mt.blocks)%2 == 1 {
		mt.blocks = append(mt.blocks, mt.blocks[len(mt.blocks)-1])
	}

	// Allocate total number of nodes needed for a perfect (binary) Merkle tree
	// and set the depth.
	mt.nodes = make([]Hash, 2*len(mt.blocks)-1)
	mt.depth = int(math.Log2(float64(len(mt.blocks)))) + 1

	// set leaf nodes from blocks
	j := len(mt.nodes) - len(mt.blocks)
	for _, b := range mt.blocks {
		mt.nodes[j] = mt.hash(mt.depth-1, b[:])
		j++
	}

	mt.finalize(0, 0)

	mt.dirty = false
	return nil
}

// RootHash returns the root hash of a finalized Merkle tree. An error is
// returned if the tree has not been finalized yet.
func (mt *MerkleTree) RootHash() (Hash, error) {
	if mt.dirty {
		return nil, fmt.Errorf("invalid root hash: %v", ErrDirtyMerkleTree)
	}

	return mt.nodes[0], nil
}

// String implements the Stringer interface. It returns the string-encoded root
// hash with a '0x' prefix.
func (mt *MerkleTree) String() (s string) {
	if rh, err := mt.RootHash(); err == nil {
		s = fmt.Sprintf("0x%s", hex.EncodeToString(rh))
	}

	return
}

// finalize recursively fills out the Merkle tree starting at a given node by
// nodeIdx and a given depth for that node. In other words, it builds the
// Merkle tree from the ground up.
func (mt *MerkleTree) finalize(nodeIdx, depth int) Hash {
	if depth == mt.depth-1 {
		return mt.nodes[nodeIdx]
	}

	left := mt.finalize(2*nodeIdx+1, depth+1)
	right := mt.finalize(2*nodeIdx+2, depth+1)

	mt.nodes[nodeIdx] = mt.hash(depth, append(left, right...))
	return mt.nodes[nodeIdx]
}

// hash returns a SHA256 hash of a byte slice with a specified prefix. The
// depth determines which prefix to use.
func (mt *MerkleTree) hash(depth int, data []byte) Hash {
	raw := make(Block, len(data)+1)

	if depth == mt.depth-1 {
		raw[0] = byte(leafNodePrefix)
	} else {
		raw[0] = byte(internalNodePrefix)
	}

	copy(raw[1:], data)
	sum := sha256.Sum256(raw)

	return Hash(sum[:])
}
