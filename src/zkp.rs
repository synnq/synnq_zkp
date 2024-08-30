use bulletproofs::r1cs::{ ConstraintSystem, Prover, Verifier, R1CSProof };
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
    let (_secret_commit, secret_var) = prover.commit(secret_scalar, blinding);

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

    // Enforce that the committed value equals the secret
    verifier.constrain(secret_var - secret_scalar);

    let result = verifier.verify(&proof, &pedersen_gens, &bp_gens).is_ok();
    Ok(result)
}
