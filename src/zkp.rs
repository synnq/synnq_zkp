use bulletproofs::r1cs::{ ConstraintSystem, Prover, Verifier, LinearCombination, R1CSProof };
use bulletproofs::{ BulletproofGens, PedersenGens };
use curve25519_dalek_ng::scalar::Scalar;
use merlin::Transcript;
use rand::rngs::OsRng;
use std::error::Error;

pub fn generate_proof(secret: u64) -> Result<(Vec<u8>, Scalar), Box<dyn Error>> {
    let mut rng = OsRng;
    let pedersen_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1);

    let mut transcript = Transcript::new(b"ExampleTranscript");
    let mut prover = Prover::new(&pedersen_gens, &mut transcript);

    let blinding = Scalar::random(&mut rng);
    let secret_scalar = Scalar::from(secret);
    let (secret_commit, secret_var) = prover.commit(secret_scalar, blinding);

    // Debug statements
    println!("Secret: {}", secret);
    println!("Secret Scalar: {:?}", secret_scalar);
    println!("Blinding: {:?}", blinding);
    println!("Secret Commitment: {:?}", secret_commit);

    // Enforce that the committed value equals the secret
    prover.constrain(secret_var - secret_scalar);

    let proof = prover.prove(&bp_gens)?;

    Ok((proof.to_bytes(), blinding))
}

pub fn verify_proof(proof: &[u8], secret: u64, blinding: Scalar) -> Result<bool, Box<dyn Error>> {
    let pedersen_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1);
    let mut transcript = Transcript::new(b"ExampleTranscript");
    let mut verifier = Verifier::new(&mut transcript);

    // Deserialize the proof from bytes
    let proof = R1CSProof::from_bytes(proof)?;

    let secret_scalar = Scalar::from(secret);

    // Create a commitment variable based on the secret and the provided blinding
    let secret_commit = pedersen_gens.commit(secret_scalar, blinding);
    let secret_var = verifier.commit(secret_commit.compress());

    // Debug statements
    println!("Secret: {}", secret);
    println!("Secret Scalar: {:?}", secret_scalar);
    println!("Secret Commitment: {:?}", secret_commit);

    // Enforce that the committed value equals the secret
    verifier.constrain(secret_var - secret_scalar);

    let result = verifier.verify(&proof, &pedersen_gens, &bp_gens).is_ok();
    println!("Verification result: {}", result); // Debug statement
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_generate_proof() {
        let secret: u64 = rand::thread_rng().gen_range(1..100);
        let proof_result = generate_proof(secret);
        assert!(proof_result.is_ok(), "Proof generation failed");
    }

    #[test]
    fn test_verify_proof() {
        let secret: u64 = rand::thread_rng().gen_range(1..100);
        let (proof_result, blinding) = generate_proof(secret).expect("Proof generation failed");
        let verify_result = verify_proof(&proof_result, secret, blinding);
        assert!(verify_result.is_ok(), "Proof verification failed");
        assert!(verify_result.unwrap(), "Proof is not valid");
    }

    #[test]
    fn test_invalid_proof() {
        let invalid_proof = vec![0u8; 64]; // An obviously invalid proof
        let secret: u64 = rand::thread_rng().gen_range(1..100);
        let blinding = Scalar::random(&mut rand::thread_rng());
        let verify_result = verify_proof(&invalid_proof, secret, blinding);
        assert!(verify_result.is_err(), "Invalid proof should fail verification");
    }
}
