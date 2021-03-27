use criterion::{
    criterion_group, criterion_main, BenchmarkGroup, BenchmarkId, Criterion, Throughput,
};
use dbs_bench::*;
use rand::{rngs::StdRng, SeedableRng};

const SEED: u64 = 42;
static TEST_POINTS: [usize; 7] = [3, 10, 20, 30, 50, 75, 100];
const BENCH_COUNT: usize = 10;

pub fn dbs_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("dbs_generation");
    BenchmarkGroup::sampling_mode(&mut group, criterion::SamplingMode::Flat);
    for &n in &TEST_POINTS {
        let rng = &mut StdRng::seed_from_u64(SEED);
        let t = (n + 1) / 2;
        group.throughput(Throughput::Bytes(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                let keys: Vec<(SecretKey, PublicKey)> =
                    (0..n).map(|_| generate_keypair(rng)).collect();
                let public_keys: Vec<PublicKey> = (0..n).map(|i| keys[i].1).collect();
                generate_shares(n, t, &public_keys, rng)
            });
        });
    }
    group.finish();
}

pub fn dbs_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("dbs_proof_verification");
    BenchmarkGroup::sampling_mode(&mut group, criterion::SamplingMode::Flat);
    for &n in &TEST_POINTS {
        let rng = &mut StdRng::seed_from_u64(SEED);
        let t = (n + 1) / 2;
        let keys: Vec<(SecretKey, PublicKey)> = (0..n).map(|_| generate_keypair(rng)).collect();
        let public_keys: Vec<PublicKey> = (0..n).map(|i| keys[i].1).collect();
        let (_, shares, proof) = generate_shares(n, t, &public_keys, rng);
        group.throughput(Throughput::Bytes(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                (0..n)
                    .map(|i| verify(n, t, i, public_keys[i], shares[i], &proof, rng).unwrap())
                    .collect::<Vec<_>>()
            });
        });
    }
    group.finish();
}

pub fn dbs_share_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("dbs_share_verification");
    BenchmarkGroup::sampling_mode(&mut group, criterion::SamplingMode::Flat);
    for &n in &TEST_POINTS {
        let rng = &mut StdRng::seed_from_u64(SEED);
        let t = (n + 1) / 2;
        let keys: Vec<(SecretKey, PublicKey)> = (0..n).map(|_| generate_keypair(rng)).collect();
        let public_keys: Vec<PublicKey> = (0..n).map(|i| keys[i].1).collect();
        let (_, shares, proof) = generate_shares(n, t, &public_keys, rng);
        let decrypted_shares: Vec<Share> = (0..n)
            .map(|i| decrypt_share(keys[i].0, shares[i]))
            .collect();
        group.throughput(Throughput::Bytes(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                (0..n)
                    .map(|i| verify_share(decrypted_shares[i], proof[i]).unwrap())
                    .collect::<Vec<_>>()
            });
        });
    }
    group.finish();
}

pub fn dbs_reconstruction(c: &mut Criterion) {
    let mut group = c.benchmark_group("dbs_reconstruction");
    BenchmarkGroup::sampling_mode(&mut group, criterion::SamplingMode::Flat);
    for &n in &TEST_POINTS {
        let rng = &mut StdRng::seed_from_u64(SEED);
        let t = (n + 1) / 2;
        let keys: Vec<(SecretKey, PublicKey)> = (0..n).map(|_| generate_keypair(rng)).collect();
        let public_keys: Vec<PublicKey> = (0..n).map(|i| keys[i].1).collect();
        let (_, shares, _) = generate_shares(n, t, &public_keys, rng);
        let decrypted_shares: Vec<_> = (0..n)
            .map(|i| Some(decrypt_share(keys[i].0, shares[i])))
            .collect();
        group.throughput(Throughput::Bytes(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| reconstruct(n, &decrypted_shares));
        });
    }
    group.finish();
}

pub fn dbs_combination(c: &mut Criterion) {
    let mut group = c.benchmark_group("dbs_combination");
    BenchmarkGroup::sampling_mode(&mut group, criterion::SamplingMode::Flat);
    for &n in &TEST_POINTS {
        let rng = &mut StdRng::seed_from_u64(SEED);
        let t = (n + 1) / 2;
        let keys: Vec<(SecretKey, PublicKey)> = (0..n).map(|_| generate_keypair(rng)).collect();
        let public_keys: Vec<PublicKey> = (0..n).map(|i| keys[i].1).collect();
        let (_, shares1, proof1) = generate_shares(n, t, &public_keys, rng);
        let (_, shares2, proof2) = generate_shares(n, t, &public_keys, rng);
        group.throughput(Throughput::Bytes(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                (
                    (0..n).map(|i| shares1[i] + shares2[i]).collect::<Vec<_>>(),
                    (0..n).map(|i| proof1[i] + proof2[i]).collect::<Vec<_>>(),
                )
            });
        });
    }
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(BENCH_COUNT);
    targets = dbs_generation, dbs_proof_verification, dbs_share_verification, dbs_reconstruction, dbs_combination);
criterion_main!(benches);
