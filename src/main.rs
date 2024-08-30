#[macro_use]
extern crate rocket;

use rocket::serde::json::Json;
use serde::{ Deserialize, Serialize };
use rocksdb::{ DB, Options };
use std::sync::RwLock;
use curve25519_dalek_ng::scalar::Scalar;
use hex;
use rocket::serde::json::serde_json;
use chrono::{ Utc, DateTime };

mod zkp;

#[derive(Serialize, Deserialize)]
struct ProofRequest {
    secret: String,
}

#[derive(Serialize, Deserialize)]
struct ProofResponse {
    proof: Vec<u8>,
    blinding: String,
}

#[derive(Serialize, Deserialize)]
struct VerifyRequest {
    secret: String,
    proof: Vec<u8>,
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

#[derive(Serialize, Deserialize)]
struct DeleteRequest {
    secret: String,
    proof: Vec<u8>,
    blinding: String,
}

struct RocksDBWrapper {
    db: RwLock<DB>,
}

/// Store the proof in the RocksDB database.
///
/// The proof is stored with the associated blinding factor and a
/// `None` timestamp, indicating that the proof has not been verified
/// yet.
///
/// # Errors
/// Returns an error if there is an issue serializing the proof data
/// or storing it in the database.
fn store_proof(db: &DB, key: &str, proof: Vec<u8>, blinding: String) -> Result<(), String> {
    let proof_data = serde_json
        ::to_string(&(proof, blinding, None::<DateTime<Utc>>))
        .map_err(|e| format!("Error serializing proof data: {}", e))?;
    db.put(key.as_bytes(), proof_data.as_bytes()).map_err(|e|
        format!("Error storing proof in database: {}", e)
    )
}

/// Retrieves a proof from the RocksDB database.
///
/// The proof is retrieved with its associated blinding factor and
/// verification timestamp.
///
/// # Errors
/// Returns an error if the proof is not found in the database or if
/// there is an issue deserializing the proof data.
fn retrieve_proof(db: &DB, key: &str) -> Result<(Vec<u8>, String, Option<DateTime<Utc>>), String> {
    let proof_data = db
        .get(key.as_bytes())
        .map_err(|e| format!("Error retrieving proof: {}", e))?
        .ok_or_else(|| "Proof not found".to_string())?;

    serde_json
        ::from_slice(&proof_data)
        .map_err(|e| { format!("Error deserializing proof data: {}", e) })
}

/// Handles the `/generate` endpoint.
///
/// This endpoint takes a `ProofRequest` JSON payload, generates a zero-knowledge
/// proof using the provided secret, stores the proof in the RocksDB database,
/// and returns a JSON response with the proof and blinding factor.
///
/// # Errors
/// Returns an error if the proof generation or storage fails.
#[post("/generate", format = "json", data = "<proof_request>")]
fn generate_proof_route(
    db_wrapper: &rocket::State<RocksDBWrapper>,
    proof_request: Json<ProofRequest>
) -> Result<Json<ProofResponse>, String> {
    // Generate a zero-knowledge proof using the provided secret
    let (proof, blinding) = zkp
        ::generate_proof(proof_request.secret.clone())
        .map_err(|e| format!("Error generating proof: {}", e))?;

    // Store the proof in the RocksDB database
    let blinding_str = hex::encode(blinding.to_bytes());
    let key = format!("proof_{}", proof_request.secret);
    store_proof(&db_wrapper.db.read().unwrap(), &key, proof.clone(), blinding_str.clone()).map_err(
        |e| format!("Error storing proof in database: {}", e)
    )?;

    // Return a JSON response with the proof and blinding factor
    Ok(Json(ProofResponse { proof, blinding: blinding_str }))
}

/// Handles the `/verify` endpoint.
///
/// This endpoint takes a `VerifyRequest` JSON payload, verifies the provided
/// proof using the stored blinding factor, and returns a JSON response with a
/// boolean indicating whether the proof is valid or not.
///
/// # Errors
/// Returns an error if the proof verification fails.
#[post("/verify", format = "json", data = "<verify_request>")]
fn verify_proof_route(
    db_wrapper: &rocket::State<RocksDBWrapper>,
    verify_request: Json<VerifyRequest>
) -> Json<VerifyResponse> {
    let proof_key = format!("proof_{}", verify_request.secret);
    let (stored_proof, stored_blinding, _verified_at) = match
        retrieve_proof(&db_wrapper.db.read().unwrap(), &proof_key)
    {
        Ok(data) => data,
        Err(_) => {
            return Json(VerifyResponse { valid: false });
        }
    };

    // Decode the stored blinding factor
    let blinding_bytes = hex::decode(&stored_blinding).expect("Failed to decode blinding");
    let blinding = Scalar::from_bits(
        blinding_bytes.try_into().expect("Failed to convert to scalar")
    );

    // Verify the proof
    let valid = zkp::verify_proof(&stored_proof, verify_request.secret.clone(), blinding).unwrap();

    // If the proof is valid, update the verification timestamp
    if valid {
        let new_data = serde_json
            ::to_string(&(stored_proof, stored_blinding, Some(Utc::now())))
            .unwrap();
        db_wrapper.db.write().unwrap().put(proof_key.as_bytes(), new_data.as_bytes()).unwrap();
    }

    // Return a JSON response with the verification result
    Json(VerifyResponse { valid })
}

/// Returns the receipt for the given secret, which includes the proof,
/// blinding factor, verification result, and timestamp.
///
/// The receipt is stored in RocksDB with the key format
/// `proof_<secret>` and `verification_<secret>`.
///
/// # Errors
/// Returns `None` if the receipt is not found in RocksDB.
#[get("/receipt/<secret>")]
fn get_receipt_route(
    db_wrapper: &rocket::State<RocksDBWrapper>,
    secret: u64
) -> Option<Json<ReceiptResponse>> {
    let proof_key = format!("proof_{}", secret);
    let (proof, blinding, verified_at) = retrieve_proof(
        &db_wrapper.db.read().unwrap(),
        &proof_key
    ).ok()?;
    let verification_key = format!("verification_{}", secret);
    let valid: bool = serde_json
        ::from_slice(&db_wrapper.db.read().unwrap().get(verification_key.as_bytes()).ok()??)
        .ok()?;
    Some(Json(ReceiptResponse { proof, blinding, valid, verified_at }))
}

/// Handles the `/delete` endpoint, which deletes a proof from the database.
///
/// The endpoint takes a `DeleteRequest` JSON payload, which contains the secret
/// and the proof to be deleted. The function first verifies the proof using the
/// stored blinding factor and the secret from the request. If the proof is valid,
/// it deletes the proof from the database. The function returns a JSON response
/// with the verification result.

#[delete("/delete", format = "json", data = "<delete_request>")]
fn delete_proof_route(
    db_wrapper: &rocket::State<RocksDBWrapper>,
    delete_request: Json<DeleteRequest>
) -> Json<VerifyResponse> {
    let proof_key = format!("proof_{}", delete_request.secret);
    let (_stored_proof, stored_blinding, _) = match
        retrieve_proof(&db_wrapper.db.read().unwrap(), &proof_key)
    {
        Ok(data) => data,
        Err(_) => {
            return Json(VerifyResponse { valid: false });
        }
    };
    let blinding_bytes = hex::decode(&stored_blinding).expect("Failed to decode blinding");
    let blinding = Scalar::from_bits(
        blinding_bytes.try_into().expect("Failed to convert to scalar")
    );
    let valid = zkp
        ::verify_proof(&delete_request.proof, delete_request.secret.clone(), blinding)
        .unwrap();
    if valid {
        db_wrapper.db.write().unwrap().delete(proof_key.as_bytes()).unwrap();
    }
    Json(VerifyResponse { valid })
}

// The main entry point of the application.
#[launch]
fn rocket() -> _ {
    // Initialize RocksDB options
    let _db_opts = Options::default();

    // Open the database in "database/db"
    let db = DB::open_default("database/db").unwrap();

    // Create a new instance of the RocksDB wrapper
    let db_wrapper = RocksDBWrapper { db: RwLock::new(db) };

    // Build the Rocket application
    rocket
        ::build()
        // Mount the routes at "/"
        .mount(
            "/",
            routes![generate_proof_route, verify_proof_route, get_receipt_route, delete_proof_route]
        )
        // Manage the RocksDB wrapper instance
        .manage(db_wrapper)
}
