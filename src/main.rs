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
use serde_json::json;
use uuid::Uuid;
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

#[derive(Serialize, Deserialize)]
struct AggregateRequest {
    secrets: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct AggregateResponse {
    aggregated_proof: Vec<u8>,
}

/// Store the proof in the RocksDB database.
fn store_proof(db: &DB, key: &str, proof: Vec<u8>, blinding: String) -> Result<(), String> {
    let proof_data = serde_json
        ::to_string(&(proof, blinding, None::<DateTime<Utc>>))
        .map_err(|e| format!("Error serializing proof data: {}", e))?;
    db.put(key.as_bytes(), proof_data.as_bytes()).map_err(|e|
        format!("Error storing proof in database: {}", e)
    )
}

/// Retrieves a proof from the RocksDB database.
fn retrieve_proof(db: &DB, key: &str) -> Result<(Vec<u8>, String, Option<DateTime<Utc>>), String> {
    let proof_data = db
        .get(key.as_bytes())
        .map_err(|e| format!("Error retrieving proof: {}", e))?
        .ok_or_else(|| "Proof not found".to_string())?;

    serde_json
        ::from_slice(&proof_data)
        .map_err(|e| format!("Error deserializing proof data: {}", e))
}

/// Handles the `/generate` endpoint.
#[post("/generate", format = "json", data = "<proof_request>")]
fn generate_proof_route(
    db_wrapper: &rocket::State<RocksDBWrapper>,
    proof_request: Json<ProofRequest>
) -> Result<Json<ProofResponse>, String> {
    // Validate the secret as a UUID
    if Uuid::parse_str(&proof_request.secret).is_err() {
        return Err("Invalid secret format".to_string());
    }

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
#[post("/verify", format = "json", data = "<verify_request>")]
fn verify_proof_route(
    db_wrapper: &rocket::State<RocksDBWrapper>,
    verify_request: Json<VerifyRequest>
) -> Json<VerifyResponse> {
    // Validate the secret as UUID
    if Uuid::parse_str(&verify_request.secret).is_err() {
        return Json(VerifyResponse { valid: false });
    }

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
    let blinding_bytes = match hex::decode(&stored_blinding) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Json(VerifyResponse { valid: false });
        }
    };
    let blinding = Scalar::from_bits(
        blinding_bytes.try_into().expect("Failed to convert to scalar")
    );

    // Verify the proof
    // main.rs

    let valid = match zkp::verify_proof(&stored_proof, verify_request.secret.clone(), blinding) {
        Ok(result) => result,
        Err(_) => {
            return Json(VerifyResponse { valid: false });
        }
    };

    // If the proof is valid, update the verification timestamp
    if valid {
        let new_data = serde_json
            ::to_string(&(stored_proof, stored_blinding, Some(Utc::now())))
            .unwrap();
        db_wrapper.db.write().unwrap().put(proof_key.as_bytes(), new_data.as_bytes()).unwrap();
    }

    Json(VerifyResponse { valid })
}

/// Returns the receipt for the given secret.
#[get("/receipt/<secret>")]
fn get_receipt_route(
    db_wrapper: &rocket::State<RocksDBWrapper>,
    secret: String
) -> Option<Json<ReceiptResponse>> {
    // Validate the secret as UUID
    if Uuid::parse_str(&secret).is_err() {
        return None;
    }

    let proof_key = format!("proof_{}", secret);
    let (proof, blinding, verified_at) = retrieve_proof(
        &db_wrapper.db.read().unwrap(),
        &proof_key
    ).ok()?;

    // Check if the proof was verified
    let verification_key = format!("verification_{}", secret);
    let valid: bool = db_wrapper.db
        .read()
        .unwrap()
        .get(verification_key.as_bytes())
        .ok()?
        .map(|data| serde_json::from_slice(&data).unwrap_or(false))
        .unwrap_or(false);

    Some(Json(ReceiptResponse { proof, blinding, valid, verified_at }))
}

/// Handles the `/delete` endpoint.
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

    // Decode the blinding factor
    let blinding_bytes = match hex::decode(&stored_blinding) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Json(VerifyResponse { valid: false });
        }
    };
    let blinding = Scalar::from_bits(
        blinding_bytes.try_into().expect("Failed to convert to scalar")
    );

    // Verify the proof before deletion
    let valid = zkp
        ::verify_proof(&delete_request.proof, delete_request.secret.clone(), blinding)
        .unwrap();

    if valid {
        db_wrapper.db.write().unwrap().delete(proof_key.as_bytes()).unwrap();
    }

    Json(VerifyResponse { valid })
}

/// Handles the `/aggregate` endpoint.
///
/// This endpoint takes an `AggregateRequest` JSON payload, retrieves the
/// corresponding proofs from the RocksDB database, aggregates them, and returns
/// a single aggregated proof.
///
/// # Errors
/// Returns an error if proof retrieval or aggregation fails.
#[post("/aggregate", format = "json", data = "<aggregate_request>")]
fn aggregate_proofs_route(
    db_wrapper: &rocket::State<RocksDBWrapper>,
    aggregate_request: Json<AggregateRequest>
) -> Result<Json<AggregateResponse>, String> {
    let mut proofs = Vec::new();

    // Loop over each secret, retrieve the associated proof, and add it to the list.
    for secret in &aggregate_request.secrets {
        let proof_key = format!("proof_{}", secret);
        let (stored_proof, _blinding, _verified_at) = match
            retrieve_proof(&db_wrapper.db.read().unwrap(), &proof_key)
        {
            Ok(data) => data,
            Err(_) => {
                return Err(format!("Failed to retrieve proof for secret: {}", secret));
            }
        };
        proofs.push(stored_proof);
    }

    // Aggregate the proofs
    let aggregated_proof = match zkp::aggregate_proofs(proofs) {
        Ok(proof) => proof,
        Err(e) => {
            return Err(format!("Error aggregating proofs: {}", e));
        }
    };

    // Return the aggregated proof
    Ok(Json(AggregateResponse { aggregated_proof }))
}

/// The main entry point of the application.
#[launch]
fn rocket() -> _ {
    let db_opts = Options::default();
    let db = DB::open_default("database/db").unwrap();
    let db_wrapper = RocksDBWrapper { db: RwLock::new(db) };

    rocket
        ::build()
        .mount(
            "/",
            routes![
                generate_proof_route,
                verify_proof_route,
                get_receipt_route,
                delete_proof_route,
                aggregate_proofs_route
            ]
        )
        .manage(db_wrapper)
}
