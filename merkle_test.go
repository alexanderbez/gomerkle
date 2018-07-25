package gomerkle

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReset(t *testing.T) {
	mt := NewMerkleTree()
	mt.Reset()

	require.True(t, mt.dirty, "expected Merkle tree to be dirty")
	require.Nil(t, mt.blocks, "expected Merkle tree to have no blocks")
	require.Nil(t, mt.levels, "expected Merkle tree to have no levels")
}

func TestInsert(t *testing.T) {
	testCases := []struct {
		input  Block
		blocks []Block
	}{
		{nil, nil},
		{[]byte("Hello, World!"), []Block{[]byte("Hello, World!")}},
		{[]byte("Merkle"), []Block{[]byte("Hello, World!"), []byte("Merkle")}},
		{[]byte("Crypto"), []Block{[]byte("Hello, World!"), []byte("Merkle"), []byte("Crypto")}},
	}

	mt := NewMerkleTree()

	for i, tc := range testCases {
		mt.Insert(tc.input)

		require.Equal(t, tc.blocks, mt.blocks, fmt.Sprintf("test case #%d", i))
	}
}

func TestFinalize(t *testing.T) {
	mt := NewMerkleTree()

	mt.Insert([]byte("a"))
	mt.Insert([]byte("b"))
	mt.Insert([]byte("c"))
	mt.Insert([]byte("d"))

	err := mt.Finalize()

	fmt.Println(err)
	fmt.Println(mt.levels)

	require.True(t, false)
}
