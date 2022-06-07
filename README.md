# Merkle-Trees

Implementation of a Merkle tree using one time signatures, such as Lamport or Winternitz, as leaves


## Usage

    use sha2::Sha256;
    use merkle_trees_cry4::{OneTimeScheme, MerkleSecretKey, MerklePublicKey};

    let message = b"Hi There!";

    let mut sk = MerkleSecretKey::<Sha256>::new(128, OneTimeScheme::Lamport).unwrap();
    let pk = MerklePublicKey::<Sha256>::new(&sk);

    let leaf_index = 66;
    let sig = sk.sign_arbitrary(message, leaf_index).unwrap();
    pk.verify_arbitrary(message, &sig).unwrap();

## Benchmark

To build the benchmark file run:

    cargo build --features build-binary --bin benchmark
