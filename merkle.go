package gomerkle

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
		blocks []block
		levels []node
		root   []byte
		dirty  bool
	}

	node  []byte
	block []byte
)

// TODO: ...
func NewMerkleTree(blocks ...block) *MerkleTree {
	return &MerkleTree{
		blocks: blocks,
		dirty:  true,
	}
}
