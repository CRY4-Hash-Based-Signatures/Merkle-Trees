//use cry4_one_time_signatures::{LamportSecretKey, LamportPublicKey, WinternitzSecretKey, WinternitzPublicKey, MerkleSecretKey, MerklePublicKey, OneTimeScheme};
use std::time::Instant;
use sha2::{Sha256, Digest, digest::FixedOutputReset};
use rand::{Rng, RngCore, thread_rng};
use merkle_trees_cry4::{OneTimeScheme, MerklePublicKey, MerkleSecretKey};

struct BenchResults {
    keygen_times: Vec<u128>,
    signing_times: Vec<u128>,
    verifying_times: Vec<u128>,
}

fn merkle_bench<D: Digest + Clone + FixedOutputReset + 'static>(i: usize, scheme: OneTimeScheme, N: usize) -> BenchResults {
    let mut sk;
    let mut pk;
    let mut sig;
    let mut kgs = Vec::with_capacity(i);
    let mut sgs = Vec::with_capacity(i);
    let mut ves = Vec::with_capacity(i);
    let TEST_MESSAGE = &mut [0u8; 32];

    for track in 0..i {
        thread_rng().fill_bytes(TEST_MESSAGE);
        let leaf = rand::thread_rng().gen_range(0..N);

        let now = Instant::now();
        sk = MerkleSecretKey::<D>::new(N, scheme).unwrap();
        pk = MerklePublicKey::<D>::new(&sk);
        let elapsed = now.elapsed();
        kgs.push(elapsed.as_micros());

        let now = Instant::now();
        sig = sk.sign(TEST_MESSAGE, leaf).unwrap();
        let elapsed = now.elapsed();
        sgs.push(elapsed.as_micros());

        let now = Instant::now();
        pk.verify(TEST_MESSAGE, &sig).unwrap();
        let elapsed = now.elapsed();
        ves.push(elapsed.as_micros());

        println!("{}", track);
    }

    let a = 1000.0;
    if i == 1 {
            let av_kg = kgs.iter().sum::<u128>() as f64 / i as f64;
            let av_sig = sgs.iter().sum::<u128>() as f64 / i as f64;
            let av_ver = ves.iter().sum::<u128>() as f64 / i as f64;
            println!("With a single Merkle run, the times are\nKeygen:\t\t{:.3?}\nSigning:\t{:.3?}\nVerifying:\t{:.3?}", av_kg / a, av_sig / a, av_ver / a);
    }

    BenchResults { keygen_times: kgs, signing_times: sgs, verifying_times: ves }
}

fn main() {
    let path = "";
    let iterations = 100;

    let bench_res = merkle_bench::<Sha256>(iterations, OneTimeScheme::Winternitz(256), 8192);

    let formatted_data = izip!(&bench_res.keygen_times, &bench_res.signing_times, &bench_res.verifying_times)
        .fold(String::from(""), |acc, (&kg, &sign, &ver)| acc + format!("{:.3?}\t{:.3?}\t{:.3?}\n", kg as f64 / 1000.0, sign as f64 / 1000.0, ver as f64 / 1000.0).as_str());
    let contents = format!("{} with {} iterations\nkeygen\tsigning\tverifying\n{}", "Lamport", iterations, formatted_data);

    use std::fs;
    fs::write(path, contents).unwrap();
}