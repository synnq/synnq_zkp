#[macro_use]
extern crate rocket;

use rocket::serde::{ json::Json };
use serde::{ Deserialize, Serialize };
use rocksdb::{ DB, Options };
use std::sync::Mutex;
use curve25519_dalek_ng::scalar::Scalar;
use hex;
use rocket::serde::json::serde_json;
use chrono::{ Utc, DateTime };

mod zkp;

#[derive(Serialize, Deserialize)]
struct ProofRequest {
    secret: u64,
}

#[derive(Serialize, Deserialize)]
struct ProofResponse {
    proof: Vec<u8>,
    blinding: String,
}

#[derive(Serialize, Deserialize)]
struct VerifyRequest {
    proof: Vec<u8>,
    secret: u64,
    blinding: String,
}

#[derive(Serialize, Deserialize)]
struct VerifyResponse {
    valid: bool,
}

#[derive(Serialize, Deserialize)]
struct ReceiptResponse {
    proof: Vec<u8>,
    blinding: String,
    valid: bool,
    verified_at: Option<DateTime<Utc>>,
}

struct RocksDBWrapper {
    db: Mutex<DB>,
}

#[post("/generate", format = "json", data = "<proof_request>")]
fn generate_proof_route(
    db_wrapper: &rocket::State<RocksDBWrapper>,
    proof_request: Json<ProofRequest>
) -> Json<ProofResponse> {
    let (proof, blinding) = zkp::generate_proof(proof_request.secret).unwrap();

    // Convert blinding factor to a string for storage
    let blinding_str = blinding
        .to_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    // Create a key for storing in RocksDB (e.g., using secret)
    let key = format!("proof_{}", proof_request.secret);

    // Serialize and store the proof and blinding in RocksDB
    let proof_data = serde_json
        ::to_string(&(proof.clone(), blinding_str.clone(), None::<DateTime<Utc>>))
        .unwrap();
    db_wrapper.db.lock().unwrap().put(key.as_bytes(), proof_data.as_bytes()).unwrap();

    Json(ProofResponse {
        proof,
        blinding: blinding_str,
    })
}

#[post("/verify", format = "json", data = "<verify_request>")]
fn verify_proof_route(
    db_wrapper: &rocket::State<RocksDBWrapper>,
    verify_request: Json<VerifyRequest>
) -> Json<VerifyResponse> {
    // Create keys for proof and verification
    let proof_key = format!("proof_{}", verify_request.secret);

    // Try to retrieve the proof data from RocksDB
    let proof_data = match db_wrapper.db.lock().unwrap().get(proof_key.as_bytes()) {
        Ok(Some(data)) => data,
        Ok(None) => {
            // Proof not found, return a response indicating failure
            return Json(VerifyResponse { valid: false });
        }
        Err(_) => {
            // Handle RocksDB errors (optional logging or error response)
            return Json(VerifyResponse { valid: false });
        }
    };

    // Try to deserialize the proof, blinding, and verification timestamp
    let result: Result<(Vec<u8>, String, Option<DateTime<Utc>>), _> = serde_json::from_slice(
        &proof_data
    );

    let (stored_proof, stored_blinding, verified_at) = match result {
        Ok(data) => data,
        Err(_) => {
            // Fallback for old format: deserialize as a tuple of two elements (proof, blinding)
            let (stored_proof, stored_blinding): (Vec<u8>, String) = serde_json
                ::from_slice(&proof_data)
                .expect("Failed to deserialize proof data in old format");
            (stored_proof, stored_blinding, None)
        }
    };

    // Check if the proof has already been verified
    // if verified_at.is_some() {
    //     return Json(VerifyResponse { valid: false });
    // }

    // Convert blinding factor back to Scalar
    let blinding_bytes = hex::decode(&stored_blinding).expect("Failed to decode blinding");
    let blinding = Scalar::from_bits(
        blinding_bytes.try_into().expect("Failed to convert to scalar")
    );

    // Verify the proof
    let valid = zkp::verify_proof(&stored_proof, verify_request.secret, blinding).unwrap();

    if valid {
        // Update the proof data with the verification timestamp
        let new_data = serde_json
            ::to_string(&(stored_proof, stored_blinding, Some(Utc::now())))
            .unwrap();
        db_wrapper.db.lock().unwrap().put(proof_key.as_bytes(), new_data.as_bytes()).unwrap();
    }

    Json(VerifyResponse { valid })
}

#[get("/receipt/<secret>")]
fn get_receipt_route(
    db_wrapper: &rocket::State<RocksDBWrapper>,
    secret: u64
) -> Option<Json<ReceiptResponse>> {
    // Retrieve the proof and blinding using the secret as the key
    let proof_key = format!("proof_{}", secret);
    let proof_data = db_wrapper.db.lock().unwrap().get(proof_key.as_bytes()).ok()??;

    // Deserialize the data
    let (proof, blinding, verified_at): (Vec<u8>, String, Option<DateTime<Utc>>) = serde_json
        ::from_slice(&proof_data)
        .ok()?;

    let verification_key = format!("verification_{}", secret);
    let verification_data = db_wrapper.db.lock().unwrap().get(verification_key.as_bytes()).ok()??;
    let valid: bool = serde_json::from_slice(&verification_data).ok()?;

    Some(
        Json(ReceiptResponse {
            proof,
            blinding,
            valid,
            verified_at,
        })
    )
}

#[launch]
fn rocket() -> _ {
    // Initialize RocksDB
    let db_opts = Options::default();
    let db = DB::open_default("database/db").unwrap(); // Use a path that maps to a Docker volume

    rocket
        ::build()
        .manage(RocksDBWrapper {
            db: Mutex::new(db),
        })
        .mount("/", routes![generate_proof_route, verify_proof_route, get_receipt_route])
}
