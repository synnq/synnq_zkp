/// A module for generating and verifying zero-knowledge proofs (ZKP) using
/// Bulletproofs.
///
/// The module provides two main functions:
///
/// - `generate_proof`: generates a ZKP proof for a given secret.
/// - `verify_proof`: verifies a ZKP proof for a given secret.
use bulletproofs::r1cs::{ ConstraintSystem, Prover, Verifier, R1CSProof };
use bulletproofs::{ BulletproofGens, PedersenGens };
use curve25519_dalek_ng::scalar::Scalar;
use merlin::Transcript;
use rand::prelude::*;
use sha2::{ Digest, Sha256 };

/// Converts a `&str` to a `Scalar`.
///
/// This function takes a string slice as an input and returns a `Scalar` that is
/// computed by hashing the input string using SHA-256 and then converting the
/// hash result to a `Scalar` using the `from_bytes_mod_order` method.
fn str_to_scalar(s: &str) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let hash_result = hasher.finalize();
    Scalar::from_bytes_mod_order(hash_result.into())
}

/// Generates a zero-knowledge proof for the given secret.
///
/// This function takes a secret string as an input and returns a tuple containing
/// the generated proof bytes and the blinding factor used in the proof
/// generation.
///
/// The function first converts the input string to a `Scalar` using the
/// `str_to_scalar` function. Then it generates a random blinding factor using the
/// `rand` crate. The function then creates a new `Prover` instance using the
/// `PedersenGens` and `BulletproofGens` instances. The `commit` method of the
/// `Prover` is used to commit the secret `Scalar` to a variable, and then the
/// `constrain` method is used to constrain the variable to be equal to the
/// secret `Scalar`. Finally, the `prove` method is used to generate the proof.
pub fn generate_proof(secret: String) -> Result<(Vec<u8>, Scalar), Box<dyn std::error::Error>> {
    let secret_scalar = str_to_scalar(&secret);

    let mut rng = thread_rng();
    let pedersen_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1);

    let mut transcript = Transcript::new(b"ExampleTranscript");
    let mut prover = Prover::new(&pedersen_gens, &mut transcript);

    let blinding = Scalar::random(&mut rng);
    let (_commitment, variable) = prover.commit(secret_scalar, blinding);

    prover.constrain(variable - secret_scalar);

    let proof = prover.prove(&bp_gens)?;

    Ok((proof.to_bytes(), blinding))
}

/// Verifies a zero-knowledge proof for the given secret.
///
/// This function takes the proof bytes, the secret string, and the blinding factor
/// as inputs and returns a boolean indicating whether the proof is valid or not.
///
/// The function first converts the input string to a `Scalar` using the
/// `str_to_scalar` function. Then it creates a new `Verifier` instance using the
/// `PedersenGens` and `BulletproofGens` instances. The `commit` method of the
/// `Verifier` is used to commit the secret `Scalar` to a variable, and then the
/// `constrain` method is used to constrain the variable to be equal to the
/// secret `Scalar`. Finally, the `verify` method is used to verify the proof.
pub fn verify_proof(
    proof: &[u8],
    secret: String,
    blinding: Scalar
) -> Result<bool, Box<dyn std::error::Error>> {
    let secret_scalar = str_to_scalar(&secret);

    let pedersen_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1);
    let mut transcript = Transcript::new(b"ExampleTranscript");
    let mut verifier = Verifier::new(&mut transcript);

    let proof = R1CSProof::from_bytes(proof)?;

    let commitment = pedersen_gens.commit(secret_scalar, blinding);
    let variable = verifier.commit(commitment.compress());

    verifier.constrain(variable - secret_scalar);

    Ok(verifier.verify(&proof, &pedersen_gens, &bp_gens).is_ok())
}
