# gomerkle

[![GoDoc](https://godoc.org/github.com/alexanderbez/gomerkle?status.svg)](https://godoc.org/github.com/alexanderbez/gomerkle)
[![Build Status](https://travis-ci.org/alexanderbez/gomerkle.svg?branch=master)](https://travis-ci.org/alexanderbez/gomerkle)
[![Go Report Card](https://goreportcard.com/badge/github.com/alexanderbez/gomerkle)](https://goreportcard.com/report/github.com/alexanderbez/gomerkle)

An implementation of a [Merkle Tree](https://en.wikipedia.org/wiki/Merkle_tree)
data structure in Golang using the SHA256 cryptographic hashing algorithm with
builtin defense against second-preimage attacks.

A Merkle tree allows for efficient and secure verification of the contents of
large data structures. This implementation provides APIs to perform the fundamental
operations on Merkle trees such as providing a Merkle root, generating proofs and
verifying them.

## API

The `MerkleTree` operates on a `Block` which is just a byte slice and typically
represents chunks of a larger data structure such as a file. It can be instantiated
with a list of blocks and inserted after initialization. Note, that order of
insertion is important and correlates to the Merkle root. If the supplied list of
blocks is not a power of two, the last block is duplicated which results in a
complete binary Merkle tree.

To initialize and insert chunks of raw data (blocks):

```golang
import (
  "github.com/alexanderbez/gomerkle"
)

blocks := []gomerkle.Block{
  gomerkle.Block("chunk1"),
  gomerkle.Block("chunk2"),
  gomerkle.Block("chunk3"),
  // ...
  gomerkle.Block("chunkn"),
}

mt := gomerkle.NewMerkleTree(blocks...)
```

Or create an empty Merkle tree and insert chunks:

```golang
mt := gomerkle.NewMerkleTree()

err := mt.Insert(gomerkle.Block("chunk1"))
if err != nil {
  // handle error...
}
```

Once all chunks have been inserted, a Merkle tree needs to 'finalized' to provide
a Merkle root, proofs, and proof verification:

```golang
err := mt.Finalize()
if err != nil {
  // handle error...
}
```

To obtain the Merkle root:

```golang
root, err := mt.RootHash()
if err != nil {
  // handle error...
}
```

To generate a Merkle proof for a chunk of data (block):

```golang
proof, err := mt.Proof(gomerkle.Block("chunk1"))
if err != nil {
  // handle error...
}
```

To verify a generated Merkle proof:

```golang
err := mt.Verify(gomerkle.Block("chunk1"), proof)
if err != nil {
  // handle error...
}
```

## Tests

```shell
$ go test -v ./...
```

## Contributing

1. [Fork it](https://github.com/alexanderbez/gomerkle/fork)
2. Create your feature branch (`git checkout -b feature/my-new-feature`)
3. Commit your changes (`git commit -m 'Add some feature'`)
4. Push to the branch (`git push origin feature/my-new-feature`)
5. Create a new Pull Request
