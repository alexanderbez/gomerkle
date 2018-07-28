package gomerkle

type (
	// Block reflects a block of data to be stored in the tree.
	Block []byte
	// Hash reflects a unique and uniformly distributed hash of a node in the
	// tree.
	Hash []byte
)

// Bytes returns the raw bytes of a Block.
func (b Block) Bytes() []byte {
	return b
}

// Bytes returns the raw bytes of a Hash.
func (h Hash) Bytes() []byte {
	return h
}
