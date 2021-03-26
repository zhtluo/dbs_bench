pub use ark_bls12_381::Bls12_381;
pub use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
pub use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
pub use ark_poly::{univariate::DensePolynomial, Polynomial as Poly, UVPolynomial};
pub use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{error::Error, fmt};

pub type Scalar = <Bls12_381 as PairingEngine>::Fr;
pub type Polynomial = DensePolynomial<Scalar>;
pub type G1 = <Bls12_381 as PairingEngine>::G1Affine;
pub type G2 = <Bls12_381 as PairingEngine>::G2Affine;
pub type G1P = <Bls12_381 as PairingEngine>::G1Projective;
pub type G2P = <Bls12_381 as PairingEngine>::G2Projective;
pub type GT = <Bls12_381 as PairingEngine>::Fqk;

pub type SecretKey = Scalar;
pub type PublicKey = G1;
pub type Secret = Scalar;
pub type Share = G1;
pub type Proof = G2;

pub fn std_rng() -> StdRng {
    StdRng::from_entropy()
}

pub fn generate_keypair<R>(rng: &mut R) -> (SecretKey, PublicKey)
where
    R: Rng + ?Sized,
{
    let secret = Scalar::rand(rng);
    (
        secret,
        G1::prime_subgroup_generator().mul(secret).into_affine(),
    )
}

pub fn generate_shares<R>(
    n: usize,
    t: usize,
    secret: Secret,
    public_keys: &[PublicKey],
    rng: &mut R,
) -> (Vec<Share>, Vec<Proof>)
where
    R: Rng + ?Sized,
{
    let vec: Vec<Scalar> = (0..t)
        .map(|i| if i == 0 { secret } else { Scalar::rand(rng) })
        .collect();
    let polynomial = Polynomial::from_coefficients_vec(vec);
    let evaluations: Vec<Scalar> = (0..n)
        .map(|i| polynomial.evaluate(&Scalar::from(i as u64 + 1)))
        .collect();
    (
        (0..n)
            .map(|i| public_keys[i].mul(evaluations[i]).into_affine())
            .collect(),
        (0..n)
            .map(|i| {
                G2::prime_subgroup_generator()
                    .mul(evaluations[i])
                    .into_affine()
            })
            .collect(),
    )
}

#[derive(Debug)]
pub enum VerifyError {
    PairingDoesNotMatch,
    CodewordCheckFailed,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl Error for VerifyError {
    fn description(&self) -> &str {
        match self {
            VerifyError::PairingDoesNotMatch => "Pairing does not match",
            VerifyError::CodewordCheckFailed => "Codeword check failed",
        }
    }
}

pub fn verify<R>(
    n: usize,
    t: usize,
    id: usize,
    public_key: PublicKey,
    share: Share,
    proof: &[Proof],
    rng: &mut R,
) -> Result<(), VerifyError>
where
    R: Rng + ?Sized,
{
    if Bls12_381::pairing(share, G2::prime_subgroup_generator())
        != Bls12_381::pairing(public_key, proof[id])
    {
        return Result::Err(VerifyError::PairingDoesNotMatch);
    }
    let vec: Vec<Scalar> = (0..n - t - 1).map(|_| Scalar::rand(rng)).collect();
    let polynomial = Polynomial::from_coefficients_vec(vec);
    let codeword: Vec<Scalar> = (0..n)
        .map(|i| {
            let scalar_i = Scalar::from(i as u64 + 1);
            (0..n)
                .map(|j| {
                    if j == i {
                        Scalar::one()
                    } else {
                        (scalar_i - Scalar::from(j as u64 + 1)).inverse().unwrap()
                    }
                })
                .fold(Scalar::one(), |v, x| v * x)
                * polynomial.evaluate(&scalar_i)
        })
        .collect();
    if (0..n)
        .map(|i| proof[i].mul(codeword[i]))
        .fold(G2P::zero(), |acc, c| acc + c)
        != G2P::zero()
    {
        return Result::Err(VerifyError::CodewordCheckFailed);
    }
    Result::Ok(())
}

#[cfg(test)]
mod tests {

    use crate::*;

    const N: usize = 16;
    const T: usize = 12;

    #[test]
    fn test_verify() {
        let rng = &mut std_rng();
        let keys: Vec<(SecretKey, PublicKey)> = (0..N).map(|_| generate_keypair(rng)).collect();
        let public_keys: Vec<PublicKey> = (0..N).map(|i| keys[i].1).collect();
        let (shares, proof) = generate_shares(N, T, Scalar::rand(rng), &public_keys, rng);
        let _: Vec<()> = (0..N)
            .map(|i| verify(N, T, i, public_keys[i], shares[i], &proof, rng).unwrap())
            .collect();
    }

    #[test]
    fn test_verify_failure() {
        let rng = &mut std_rng();
        let keys: Vec<(SecretKey, PublicKey)> = (0..N).map(|_| generate_keypair(rng)).collect();
        let public_keys: Vec<PublicKey> = (0..N).map(|i| keys[i].1).collect();
        let (_, proof) = generate_shares(N, T, Scalar::rand(rng), &public_keys, rng);
        let _: Vec<VerifyError> = (0..N)
            .map(|i| {
                verify(
                    N,
                    T,
                    i,
                    public_keys[i],
                    G1::prime_subgroup_generator()
                        .mul(Scalar::rand(rng))
                        .into_affine(),
                    &proof,
                    rng,
                )
                .err()
                .unwrap()
            })
            .collect();
    }
}
