package gomerkle

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

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

func TestDepth(t *testing.T) {
	testCases := []struct {
		blocks        []Block
		expectedDepth int
	}{
		{
			expectedDepth: 0,
		},
		{
			blocks: []Block{
				Block("blockA"),
				Block("blockB"),
			},
			expectedDepth: 2,
		},
		{
			blocks: []Block{
				Block("blockA"),
				Block("blockB"),
				Block("blockC"),
				Block("blockD"),
			},
			expectedDepth: 3,
		},
		{
			blocks: []Block{
				Block("blockA"),
				Block("blockB"),
				Block("blockC"),
				Block("blockD"),
				Block("blockE"),
				Block("blockF"),
				Block("blockG"),
				Block("blockH"),
			},
			expectedDepth: 4,
		},
	}

	for i, tc := range testCases {
		mt := NewMerkleTree(tc.blocks...)

		if len(tc.blocks) > 0 {
			mt.Finalize()
		}

		require.Equal(t, tc.expectedDepth, mt.depth, fmt.Sprintf("unexpected depth: test case #%d", i))
	}
}

func TestRootHash(t *testing.T) {
	testCases := []struct {
		blocks       []Block
		expectedRoot string
		expectedErr  bool
	}{
		{
			expectedErr: true,
		},
		{
			blocks: []Block{
				Block("blockA"),
				Block("blockB"),
			},
			expectedRoot: "526885312f344b1ecf858295f8ccb0205d5a9e34f99eddf899726750183c4d4b",
		},
		{
			blocks: []Block{
				Block("blockA"),
				Block("blockB"),
				Block("blockC"),
				Block("blockD"),
			},
			expectedRoot: "cfd8b30f6bd15f8f7f4efd80528a57c74b85bf6c3beabfcf409b11e84041e573",
		},
		{
			blocks: []Block{
				Block("blockA"),
				Block("blockB"),
				Block("blockC"),
				Block("blockD"),
				Block("blockE"),
				Block("blockF"),
				Block("blockG"),
				Block("blockH"),
			},
			expectedRoot: "1e405b87167acaa710a77783bbc02558bacab62cf682fb1b8cf0a249a5167ad6",
		},
	}

	for i, tc := range testCases {
		mt := NewMerkleTree(tc.blocks...)

		if len(tc.blocks) > 0 {
			mt.Finalize()
		}

		root, err := mt.RootHash()

		if tc.expectedErr {
			require.Error(t, err, fmt.Sprintf("expected error: test case #%d", i))
		} else {
			expectedRoot, _ := hex.DecodeString(tc.expectedRoot)

			require.NoError(t, err, fmt.Sprintf("unexpected error: test case #%d", i))
			require.Equal(t, expectedRoot, root.Bytes(), fmt.Sprintf("unexpected root: test case #%d", i))
		}
	}
}

func TestString(t *testing.T) {
	testCases := []struct {
		blocks      []Block
		expectedStr string
	}{
		{
			expectedStr: "",
		},
		{
			blocks: []Block{
				Block("blockA"),
				Block("blockB"),
			},
			expectedStr: "0x526885312f344b1ecf858295f8ccb0205d5a9e34f99eddf899726750183c4d4b",
		},
		{
			blocks: []Block{
				Block("blockA"),
				Block("blockB"),
				Block("blockC"),
				Block("blockD"),
			},
			expectedStr: "0xcfd8b30f6bd15f8f7f4efd80528a57c74b85bf6c3beabfcf409b11e84041e573",
		},
		{
			blocks: []Block{
				Block("blockA"),
				Block("blockB"),
				Block("blockC"),
				Block("blockD"),
				Block("blockE"),
				Block("blockF"),
				Block("blockG"),
				Block("blockH"),
			},
			expectedStr: "0x1e405b87167acaa710a77783bbc02558bacab62cf682fb1b8cf0a249a5167ad6",
		},
	}

	for i, tc := range testCases {
		mt := NewMerkleTree(tc.blocks...)

		if len(tc.blocks) > 0 {
			mt.Finalize()
		}

		require.Equal(t, tc.expectedStr, mt.String(), fmt.Sprintf("unexpected value: test case #%d", i))
	}
}

func TestFinalize(t *testing.T) {
	testCases := []struct {
		blocks           []Block
		expectedErr      bool
		expectedBlockLen int
		expectedRoot     string
	}{
		{
			expectedErr: true,
		},
		{
			blocks: []Block{
				Block("blockA"),
				Block("blockB"),
				Block("blockC"),
			},
			expectedBlockLen: 4,
			expectedRoot:     "d0faee80290ba6a184111d2b2bfe8e66ad89df287a0f0f582e5162d02ffc7013",
		},
		{
			blocks: []Block{
				Block("blockA"),
				Block("blockB"),
				Block("blockC"),
				Block("blockD"),
			},
			expectedBlockLen: 4,
			expectedRoot:     "cfd8b30f6bd15f8f7f4efd80528a57c74b85bf6c3beabfcf409b11e84041e573",
		},
	}

	for i, tc := range testCases {
		mt := NewMerkleTree(tc.blocks...)

		err := mt.Finalize()

		if tc.expectedErr {
			require.Error(t, err, fmt.Sprintf("expected error: test case #%d", i))
		} else {
			expectedRoot, _ := hex.DecodeString(tc.expectedRoot)

			require.NoError(t, err, fmt.Sprintf("unexpected error: test case #%d", i))
			require.Equal(t, tc.expectedBlockLen, len(mt.blocks), fmt.Sprintf("unexpected number of blocks: test case #%d", i))
			require.False(t, mt.dirty, fmt.Sprintf("unexpected tree to not be dirty: test case #%d", i))
			require.Equal(t, expectedRoot, mt.root.Bytes(), fmt.Sprintf("unexpected root: test case #%d", i))
		}
	}
}

func TestProof(t *testing.T) {

}

func TestVerify(t *testing.T) {

}
