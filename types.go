package gomerkle

type (
	// Block reflects a block of data to be stored in the tree.
	Block []byte
	// Node reflects a unique and uniformly distributed hash of a node in the
	// tree.
	Node []byte
)

// Bytes returns the raw bytes of a Block.
func (b Block) Bytes() []byte {
	return b
}

// Bytes returns the raw bytes of a Node.
func (h Node) Bytes() []byte {
	return h
}
