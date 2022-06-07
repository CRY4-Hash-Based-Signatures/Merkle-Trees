use sha2::{Digest, digest::FixedOutputReset};
use std::marker::PhantomData;
use one_time_signatures_cry4::{
    OneTimeScheme, 
    lamport::{LamportSecretKey, LamportPublicKey},
    winternitz::{WinternitzSecretKey, WinternitzPublicKey}, 
    OneTimeSecretKey, OneTimePublicKey, OneTimeSignature
};


fn next_layer<D: Digest + FixedOutputReset>(layer: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut hasher = D::new();
    layer.chunks_exact(2).map(|chunk| {
        <D as Digest>::update(&mut hasher, &chunk[0]);
        <D as Digest>::update(&mut hasher, &chunk[1]);
        hasher.finalize_reset().to_vec()
    }).collect()
}

pub struct MerkleSignature<D> {
    ots_sig: Box<dyn OneTimeSignature>,
    ots_pk: Box<dyn OneTimePublicKey<D>>,
    auth_path: Vec<Vec<u8>>,
    index: usize,
}

pub struct MerkleSecretKey<D: Digest> {
    sk_leaves: Vec<Box<dyn OneTimeSecretKey<D>>>,
    pk_leaves: Vec<Box<dyn OneTimePublicKey<D>>>,
    used_leaves: Vec<bool>,
    p: PhantomData<D>,
}

#[allow(non_snake_case)]
impl<D: Digest + 'static + Clone + FixedOutputReset> MerkleSecretKey<D> {
    pub fn new(N: usize, scheme: OneTimeScheme) -> Result<MerkleSecretKey<D>, String> {
        if N == 0 || (N & (N - 1)) != 0  {
            return Err(String::from("N must be a power of 2"))
        }

        let mut sk_leaves: Vec<Box<dyn OneTimeSecretKey<D>>> = Vec::with_capacity(N);
        let mut pk_leaves: Vec<Box<dyn OneTimePublicKey<D>>> = Vec::with_capacity(N);

        for _ in 0..N {
            let (sk_leaf, pk_leaf): (Box<dyn OneTimeSecretKey<D>>, Box<dyn OneTimePublicKey<D>>) = match scheme {
                OneTimeScheme::Lamport => {
                    let sk = LamportSecretKey::<D>::new();
                    let pk = LamportPublicKey::<D>::new(&sk);
                    (Box::new(sk), Box::new(pk))
                }
                OneTimeScheme::Winternitz(w) => {
                    let sk = WinternitzSecretKey::<D>::new(w);
                    let pk = WinternitzPublicKey::<D>::new(&sk);
                    (Box::new(sk), Box::new(pk))
                }
            };
            sk_leaves.push(sk_leaf);
            pk_leaves.push(pk_leaf);
        }

        let used_leaves = vec![false; N];

        Ok(MerkleSecretKey { sk_leaves, pk_leaves, used_leaves, p: PhantomData })
    }

    pub fn sign(&mut self, m: &[u8], leaf: usize) -> Result<MerkleSignature<D>, String> {
        if self.used_leaves.len() <= leaf { 
            return Err(format!("Leaf {} doesn't exist with {} leaves", leaf, self.used_leaves.len()))
        }

        if self.used_leaves[leaf] {
            return Err(format!("Leaf {} already used", leaf))
        }
    
        self.used_leaves[leaf] = true;

        let ots_sig = self.sk_leaves[leaf].sign(m)?;
        let ots_pk = self.pk_leaves[leaf].clone();
        let auth_path = self.find_auth_path(leaf);
        
        Ok(MerkleSignature { ots_sig, ots_pk, auth_path, index: leaf })
    }

    pub fn sign_arbitrary(&mut self, m: &[u8], leaf: usize) -> Result<MerkleSignature<D>, String> {
        self.sign(&D::digest(m), leaf)
    }

    fn find_auth_path(&self, index: usize) -> Vec<Vec<u8>> {
        let mut proof: Vec<Vec<u8>> = Vec::with_capacity(self.height());

        // Find first neighbour
        let neighbour_index = if index % 2 == 0 { index + 1 } else {index - 1};
        proof.push(D::digest(&self.pk_leaves[neighbour_index].to_bytes()).to_vec());
        let mut next_index = index / 2;
        
        // Get the next to bottom layer:
        let leaf_bytes = self.pk_leaves.iter().map(|leaf| D::digest(leaf.to_bytes()).to_vec()).collect();
        let mut layer = next_layer::<D>(leaf_bytes);
        
        //1: Find nabo (x%2 ? x-1 : x+1)
        //2: udregn næste lag
        //3: find index vi er på
        //4: repeat

        loop {
            if layer.len() <= 1 {
                break;
            }

            // If index even, the neighbour is to the rigth, and left otherwise
            let neighbour_index = if next_index % 2 == 0 {next_index+1} else {next_index-1};

            // Add neighbour to proof
            proof.push(layer[neighbour_index].clone());
            
            //Calculate next layer
            layer = next_layer::<D>(layer);

            //Find index of this node
            next_index /= 2;
        }

        proof
    }

    pub fn height(&self) -> usize {
        let leaf_amount = self.pk_leaves.len();
        (leaf_amount as f64).log2() as usize
    }
}


pub struct MerklePublicKey<D> {
    pk: Vec<u8>,
    p: PhantomData<D>,
}

impl<D: Digest + FixedOutputReset> MerklePublicKey<D> {
    pub fn new(sk: &MerkleSecretKey<D>) -> MerklePublicKey<D> {
        let mut hasher = D::new();
        let pk = if sk.pk_leaves.len() == 1 {
            D::digest(&sk.pk_leaves[0].to_bytes()).to_vec()
        } else {
            let first: Vec<Vec<u8>> = sk.pk_leaves.iter().map(|leaf| D::digest(&leaf.to_bytes()).to_vec()).collect();
            let mut next_layer: Vec<Vec<u8>>;
            let mut it = first.chunks_exact(2);
            let mut remain = it.remainder();
            while remain.len() == 0 {
                next_layer = it.map(|chunk| {
                    <D as Digest>::update(&mut hasher, &chunk[0]);
                    <D as Digest>::update(&mut hasher, &chunk[1]);
                    hasher.finalize_reset().to_vec()
                }).collect();
                it = next_layer.chunks_exact(2);
                remain = it.remainder();
            }
            
            remain[0].clone()
        };

        MerklePublicKey { pk, p: PhantomData }
    }

    pub fn verify(&self, m: &[u8], sig: &MerkleSignature<D>) -> Result<(), String> {
        sig.ots_pk.verify(m, &sig.ots_sig)?;
        self.check_auth_path(&sig.auth_path, &sig.ots_pk.to_bytes(), sig.index)?;
        Ok(())
    }

    pub fn verify_arbitrary(&self, m: &[u8], sig: &MerkleSignature<D>) -> Result<(), String> {
        self.verify(&D::digest(m), sig)
    }

    fn check_auth_path(&self, proof: &Vec<Vec<u8>>, pk_bytes: &[u8], mut index: usize) -> Result<(), String> {
        let mut hasher = D::new();
        let mut res = D::digest(pk_bytes);
        for hash in proof {
            if index % 2 == 0 {
                <D as Digest>::update(&mut hasher, res);
                <D as Digest>::update(&mut hasher, &hash);
            } else {
                <D as Digest>::update(&mut hasher, &hash);
                <D as Digest>::update(&mut hasher, res);
            }
            res = hasher.finalize_reset();
            index = index / 2
        }

        if res.to_vec() == self.pk {
            Ok(())
        } else {
            Err(String::from("Auth path proof failed"))
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    const TEST_MESSAGE32: &[u8] = b"32 byte test message for Merkle!";
    const TEST_MESSAGE64: &[u8] = b"64 byte test message, used for wider hash functions with Merkle!";
    const TEST_MESSAGE_AB: &[u8] = b"An arbitrary length message used to test Merkle trees signing using digests";

    #[test]
    fn test_create_key() {
        MerkleSecretKey::<Sha256>::new(8, OneTimeScheme::Lamport).unwrap();
    }

    #[test]
    fn test_one_ots() {
        MerkleSecretKey::<Sha256>::new(1, OneTimeScheme::Lamport).unwrap();
    }

    #[test]
    fn test_wrong_amount() {
        let sk = MerkleSecretKey::<Sha256>::new(7, OneTimeScheme::Lamport);
        let sk2 = MerkleSecretKey::<Sha256>::new(0, OneTimeScheme::Lamport);
        
        assert!(sk.is_err());
        assert!(sk2.is_err());
    }

    #[test]
    fn test_correct_root_2() {
        let sk = MerkleSecretKey::<Sha256>::new(2, OneTimeScheme::Lamport).unwrap();
        let pk = MerklePublicKey::<Sha256>::new(&sk);

        let mut hasher = Sha256::new();
        hasher.update(Sha256::digest(&sk.pk_leaves[0].to_bytes()));
        hasher.update(Sha256::digest(&sk.pk_leaves[1].to_bytes()));
        let correct_pk = hasher.finalize().to_vec();

        assert_eq!(pk.pk, correct_pk);
    }

    #[test]
    fn test_correct_root_4() {
        let sk = MerkleSecretKey::<Sha256>::new(4, OneTimeScheme::Lamport).unwrap();
        let pk = MerklePublicKey::<Sha256>::new(&sk);

        let mut hasher = Sha256::new();
        hasher.update(Sha256::digest(&sk.pk_leaves[0].to_bytes()));
        hasher.update(Sha256::digest(&sk.pk_leaves[1].to_bytes()));
        let left = hasher.finalize_reset();
        hasher.update(Sha256::digest(&sk.pk_leaves[2].to_bytes()));
        hasher.update(Sha256::digest(&sk.pk_leaves[3].to_bytes()));
        let right = hasher.finalize_reset();
        hasher.update(left);
        hasher.update(right);

        let correct_pk = hasher.finalize().to_vec();

        assert_eq!(pk.pk, correct_pk);
    }

    #[test]
    fn test_find_auth_path() {
        let sk = MerkleSecretKey::<Sha256>::new(4, OneTimeScheme::Lamport).unwrap();

        let leaf = 0;
        let auth_path = sk.find_auth_path(leaf);

        let mut hasher = Sha256::new();

        let path1 = Sha256::digest(&sk.pk_leaves[1].to_bytes()).to_vec();

        hasher.update(Sha256::digest(&sk.pk_leaves[2].to_bytes()));
        hasher.update(Sha256::digest(&sk.pk_leaves[3].to_bytes()));
        let path2 = hasher.finalize().to_vec();

        let correct_auth_path = vec![path1, path2];

        assert_eq!(auth_path, correct_auth_path);
    }

    #[test]
    fn test_sign_verify_lamport() {
        let mut sk = MerkleSecretKey::<Sha256>::new(4, OneTimeScheme::Lamport).unwrap();
        let pk = MerklePublicKey::<Sha256>::new(&sk);

        let leaf = 0;
        let sig = sk.sign(TEST_MESSAGE32, leaf).unwrap();
        pk.verify(TEST_MESSAGE32, &sig).unwrap();
    }

    #[test]
    fn test_sign_verify_lamport_big_tree() {
        let mut sk = MerkleSecretKey::<Sha256>::new(2048, OneTimeScheme::Lamport).unwrap();
        let pk = MerklePublicKey::<Sha256>::new(&sk);

        let leaf = 121;
        let sig = sk.sign(TEST_MESSAGE32, leaf).unwrap();
        pk.verify(TEST_MESSAGE32, &sig).unwrap();
    }

    #[test]
    fn test_sign_verify_winternitz() {
        let mut sk = MerkleSecretKey::<Sha256>::new(4, OneTimeScheme::Winternitz(256)).unwrap();
        let pk = MerklePublicKey::<Sha256>::new(&sk);

        let leaf = 0;
        let sig = sk.sign(TEST_MESSAGE32, leaf).unwrap();
        pk.verify(TEST_MESSAGE32, &sig).unwrap();
    }

    #[test]
    fn test_sign_verify_winternitz_big_tree() {
        let mut sk = MerkleSecretKey::<Sha256>::new(2048, OneTimeScheme::Winternitz(16)).unwrap();
        let pk = MerklePublicKey::<Sha256>::new(&sk);

        let leaf = 119;
        let sig = sk.sign(TEST_MESSAGE32, leaf).unwrap();
        pk.verify(TEST_MESSAGE32, &sig).unwrap();
    }

    #[test]
    fn test_sign_all_leaves() {
        let mut sk = MerkleSecretKey::<Sha256>::new(16, OneTimeScheme::Lamport).unwrap();
        let pk = MerklePublicKey::<Sha256>::new(&sk);

        for leaf in 0..16 {
            let sig = sk.sign(TEST_MESSAGE32, leaf).unwrap();
            pk.verify(TEST_MESSAGE32, &sig).unwrap();
        }
    }

    #[test]
    fn test_sign_already_used_leaf() {
        let mut sk = MerkleSecretKey::<Sha256>::new(4, OneTimeScheme::Lamport).unwrap();

        let leaf = 0;
        sk.sign(TEST_MESSAGE32, leaf).unwrap();
        let res = sk.sign(TEST_MESSAGE32, leaf);

        assert!(res.is_err())
    }

    #[test]
    fn test_sign_verify_arbitrary() {
        let mut sk = MerkleSecretKey::<Sha256>::new(4, OneTimeScheme::Lamport).unwrap();
        let pk = MerklePublicKey::<Sha256>::new(&sk);

        let leaf = 0;
        let sig = sk.sign_arbitrary(TEST_MESSAGE_AB, leaf).unwrap();
        pk.verify_arbitrary(TEST_MESSAGE_AB, &sig).unwrap();
    }

    #[test]
    fn test_sign_verify_wrong_message() {
        let mut sk = MerkleSecretKey::<Sha256>::new(4, OneTimeScheme::Lamport).unwrap();
        let pk = MerklePublicKey::<Sha256>::new(&sk);

        let leaf = 0;
        let sig = sk.sign_arbitrary(TEST_MESSAGE32, leaf).unwrap();
        let new_message = b"This is a different message, so ";
        let res = pk.verify_arbitrary(new_message, &sig);

        assert!(res.is_err());
    }

    #[test]
    fn test_sign_wrong_message_size() {
        let mut sk = MerkleSecretKey::<Sha256>::new(4, OneTimeScheme::Lamport).unwrap();

        let leaf = 0;
        let sig = sk.sign(TEST_MESSAGE64, leaf);

        assert!(sig.is_err());
    }
}