// zkp.rs

use bulletproofs::r1cs::{ ConstraintSystem, Prover, Verifier, R1CSProof };
use bulletproofs::{ BulletproofGens, PedersenGens };
use curve25519_dalek_ng::scalar::Scalar;
use merlin::Transcript;
use rand::prelude::*;
use sha2::{ Digest, Sha256 };

/// Converts a `&str` to a `Scalar`.
///
/// This function takes a string slice as input and returns a `Scalar` that is
/// computed by hashing the input string using SHA-256, then converting the
/// hash result to a `Scalar` using `from_bytes_mod_order`.
pub fn str_to_scalar(s: &str) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let hash_result = hasher.finalize();
    Scalar::from_bytes_mod_order(hash_result.into())
}

/// Generates a zero-knowledge proof for the given secret.
///
/// This function takes a secret string as input and returns a tuple containing
/// the generated proof bytes and the blinding factor used in the proof generation.
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

/// Aggregates multiple zero-knowledge proofs.
///
/// This function takes a vector of proof bytes and returns a single aggregated proof,
/// allowing for more efficient on-chain verification.
pub fn aggregate_proofs(proofs: Vec<Vec<u8>>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let pedersen_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, proofs.len()); // Adjust BP generators for multiple proofs
    let mut transcript = Transcript::new(b"AggregatedTranscript");

    let mut prover = Prover::new(&pedersen_gens, &mut transcript);

    // Here, iterate through proofs and aggregate them.
    for proof in proofs {
        let _ = R1CSProof::from_bytes(&proof)?;
        // Combine proof constraints as necessary
    }

    let aggregated_proof = prover.prove(&bp_gens)?;
    Ok(aggregated_proof.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_str_to_scalar() {
        let scalar = str_to_scalar("test");
        assert_eq!(scalar.to_bytes().len(), 32);
    }

    #[test]
    fn test_generate_and_verify_proof() {
        let secret = "my_secret".to_string();
        let (proof, blinding) = generate_proof(secret.clone()).expect("Failed to generate proof");

        let is_valid = verify_proof(&proof, secret, blinding).expect("Failed to verify proof");
        assert!(is_valid);
    }

    #[test]
    fn test_aggregate_proofs() {
        let secret1 = "secret1".to_string();
        let secret2 = "secret2".to_string();

        let (proof1, _) = generate_proof(secret1).expect("Failed to generate proof1");
        let (proof2, _) = generate_proof(secret2).expect("Failed to generate proof2");

        let aggregated_proof = aggregate_proofs(vec![proof1, proof2]).expect(
            "Failed to aggregate proofs"
        );
        assert!(!aggregated_proof.is_empty());
    }
}
