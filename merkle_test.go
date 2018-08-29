package gomerkle

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

func newTestMerkleTree() (*MerkleTree, []Block) {
	dataSize := 1000000
	chunkSize := 10
	chunks := dataSize / chunkSize
	blocks := make([]Block, chunks)

	for i := 0; i < chunks; i++ {
		block := make(Block, chunkSize)
		rand.Read(block)

		blocks[i] = block
	}

	mt := NewMerkleTree(blocks...)
	if err := mt.Finalize(); err != nil {
		panic(err)
	}

	return mt, blocks
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
			require.Equal(t, expectedRoot, root, fmt.Sprintf("unexpected root: test case #%d", i))
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
				Block("blockE"),
			},
			expectedStr: "0x8f95978f1b0dd9d3d792cc82e5b21c7c32927c7fe7c8d477be030ab1654bbc93",
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
				Block("blockD"),
				Block("blockE"),
			},
			expectedBlockLen: 6,
			expectedRoot:     "8f95978f1b0dd9d3d792cc82e5b21c7c32927c7fe7c8d477be030ab1654bbc93",
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
			expectedBlockLen: 8,
			expectedRoot:     "1e405b87167acaa710a77783bbc02558bacab62cf682fb1b8cf0a249a5167ad6",
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
	dataSet1 := []Block{
		Block("blockA"),
		Block("blockB"),
		Block("blockC"),
		Block("blockD"),
		Block("blockE"),
		Block("blockF"),
		Block("blockG"),
		Block("blockH"),
	}
	dataSet2 := []Block{
		Block("blockA"),
		Block("blockB"),
		Block("blockC"),
		Block("blockD"),
		Block("blockE"),
	}

	testCases := []struct {
		blocks        []Block
		proofBlock    Block
		expectedErr   bool
		expectedProof []string
	}{
		{
			expectedErr: true,
		},
		{
			blocks:      dataSet1,
			expectedErr: false,
			proofBlock:  Block("blockA"),
			expectedProof: []string{
				"631E1AF9330CDFA88E9EB39ACE2431F5F471B93EAB8E7C085B4B40F2A5F637D7",
				"9577C5848D134240A957225DD68A3D697C7D937592380C653DFE184F50DD8482",
				"1E5347BF6618F0C97D2838DBC3758A9805AEF13383FB6C12ABFF31500AD66ABD",
			},
		},
		{
			blocks:      dataSet1,
			expectedErr: false,
			proofBlock:  Block("blockF"),
			expectedProof: []string{
				"5E6F4831C72462B47E9594F04DC58822FD3AB0A050452C97119E1EC017FAADF2",
				"1212F9BB2DB7915781AFCF9E104892DB1191878C402E9C8AC4954CE9F5A0295D",
				"CFD8B30F6BD15F8F7F4EFD80528A57C74B85BF6C3BEABFCF409B11E84041E573",
			},
		},
		{
			blocks:      dataSet2,
			expectedErr: false,
			proofBlock:  Block("blockA"),
			expectedProof: []string{
				"631E1AF9330CDFA88E9EB39ACE2431F5F471B93EAB8E7C085B4B40F2A5F637D7",
				"E1270856BC57D48181A2946A66121663C3FAA0BBD8B6743B079CD0C5D87AD3E2",
			},
		},
		{
			blocks:      dataSet2,
			expectedErr: false,
			proofBlock:  Block("blockE"),
			expectedProof: []string{
				"5E6F4831C72462B47E9594F04DC58822FD3AB0A050452C97119E1EC017FAADF2",
				"9577C5848D134240A957225DD68A3D697C7D937592380C653DFE184F50DD8482",
				"526885312F344B1ECF858295F8CCB0205D5A9E34F99EDDF899726750183C4D4B",
			},
		},
		{
			blocks:      dataSet1,
			expectedErr: true,
			proofBlock:  Block("blockZ"),
		},
		{
			blocks:      dataSet2,
			expectedErr: true,
			proofBlock:  Block("blockZ"),
		},
	}

	for i, tc := range testCases {
		mt := NewMerkleTree(tc.blocks...)
		mt.Finalize()

		proof, err := mt.Proof(tc.proofBlock)

		if tc.expectedErr {
			require.Error(t, err, fmt.Sprintf("expected error: test case #%d", i))
		} else {
			require.NoError(t, err, fmt.Sprintf("unexpected error: test case #%d", i))
			require.Equal(t, len(tc.expectedProof), len(proof), fmt.Sprintf("unexpected proof length: test case #%d", i))

			for j, exChunk := range tc.expectedProof {
				chunk := fmt.Sprintf("%X", proof[j])

				require.Equal(t, exChunk, chunk, fmt.Sprintf("invalid proof: test case #%d", i))
			}
		}
	}
}

func TestVerify(t *testing.T) {
	dataSet1 := []Block{
		Block("blockA"),
		Block("blockB"),
		Block("blockC"),
		Block("blockD"),
		Block("blockE"),
		Block("blockF"),
		Block("blockG"),
		Block("blockH"),
	}
	dataSet2 := []Block{
		Block("blockA"),
		Block("blockB"),
		Block("blockC"),
		Block("blockD"),
		Block("blockE"),
	}

	testCases := []struct {
		blocks      []Block
		proofBlock  Block
		proof       []string
		expectedErr bool
	}{
		{
			expectedErr: true,
		},
		{
			blocks:      dataSet1,
			expectedErr: false,
			proofBlock:  Block("blockA"),
			proof: []string{
				"631E1AF9330CDFA88E9EB39ACE2431F5F471B93EAB8E7C085B4B40F2A5F637D7",
				"9577C5848D134240A957225DD68A3D697C7D937592380C653DFE184F50DD8482",
				"1E5347BF6618F0C97D2838DBC3758A9805AEF13383FB6C12ABFF31500AD66ABD",
			},
		},
		{
			blocks:      dataSet1,
			expectedErr: false,
			proofBlock:  Block("blockF"),
			proof: []string{
				"5E6F4831C72462B47E9594F04DC58822FD3AB0A050452C97119E1EC017FAADF2",
				"1212F9BB2DB7915781AFCF9E104892DB1191878C402E9C8AC4954CE9F5A0295D",
				"CFD8B30F6BD15F8F7F4EFD80528A57C74B85BF6C3BEABFCF409B11E84041E573",
			},
		},

		{
			blocks:      dataSet2,
			expectedErr: false,
			proofBlock:  Block("blockA"),
			proof: []string{
				"631E1AF9330CDFA88E9EB39ACE2431F5F471B93EAB8E7C085B4B40F2A5F637D7",
				"E1270856BC57D48181A2946A66121663C3FAA0BBD8B6743B079CD0C5D87AD3E2",
			},
		},
		{
			blocks:      dataSet2,
			expectedErr: false,
			proofBlock:  Block("blockE"),
			proof: []string{
				"5E6F4831C72462B47E9594F04DC58822FD3AB0A050452C97119E1EC017FAADF2",
				"9577C5848D134240A957225DD68A3D697C7D937592380C653DFE184F50DD8482",
				"526885312F344B1ECF858295F8CCB0205D5A9E34F99EDDF899726750183C4D4B",
			},
		},
		{
			blocks:      dataSet1,
			expectedErr: true,
			proofBlock:  Block("blockD"),
			proof: []string{
				"5E6F4831C72462B47E9594F04DC58822FD3AB0A050452C97119E1EC017FAADF2",
				"9577C5848D134240A957225DD68A3D697C7D937592380C653DFE184F50DD8482",
				"526885312F344B1ECF858295F8CCB0205D5A9E34F99EDDF899726750183C4D4B",
			},
		},
		{
			blocks:      dataSet2,
			expectedErr: true,
			proofBlock:  Block("blockC"),
			proof: []string{
				"5E6F4831C72462B47E9594F04DC58822FD3AB0A050452C97119E1EC017FAADF2",
				"9577C5848D134240A957225DD68A3D697C7D937592380C653DFE184F50DD8482",
				"526885312F344B1ECF858295F8CCB0205D5A9E34F99EDDF899726750183C4D4B",
			},
		},
		{
			blocks:      dataSet1,
			expectedErr: true,
			proofBlock:  Block("blockZ"),
			proof: []string{
				"5E6F4831C72462B47E9594F04DC58822FD3AB0A050452C97119E1EC017FAADF2",
				"9577C5848D134240A957225DD68A3D697C7D937592380C653DFE184F50DD8482",
				"526885312F344B1ECF858295F8CCB0205D5A9E34F99EDDF899726750183C4D4B",
			},
		},
		{
			blocks:      dataSet2,
			expectedErr: true,
			proofBlock:  Block("blockZ"),
			proof: []string{
				"5E6F4831C72462B47E9594F04DC58822FD3AB0A050452C97119E1EC017FAADF2",
				"9577C5848D134240A957225DD68A3D697C7D937592380C653DFE184F50DD8482",
				"526885312F344B1ECF858295F8CCB0205D5A9E34F99EDDF899726750183C4D4B",
			},
		},
	}

	for i, tc := range testCases {
		mt := NewMerkleTree(tc.blocks...)
		mt.Finalize()

		proof := make([]Node, len(tc.proof))
		for j, p := range tc.proof {
			proof[j], _ = hex.DecodeString(p)
		}

		err := mt.Verify(tc.proofBlock, proof)

		if tc.expectedErr {
			require.Error(t, err, fmt.Sprintf("expected error: test case #%d", i))
		} else {
			require.NoError(t, err, fmt.Sprintf("unexpected error: test case #%d", i))
		}
	}
}

func TestProveAndVerifyRandom(t *testing.T) {
	mt, blocks := newTestMerkleTree()
	randBlock := blocks[rand.Intn(len(blocks))]

	proof, err := mt.Proof(randBlock)
	require.NoError(t, err)
	require.False(t, mt.dirty)

	err = mt.Verify(randBlock, proof)
	require.NoError(t, err)
	require.False(t, mt.dirty)

	err = mt.Insert(Block("blockX"))
	require.Error(t, err)
}
