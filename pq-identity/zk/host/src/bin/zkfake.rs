//! TEST-ONLY tool: produces a RISC Zero dev-mode ("fake") receipt for the same guest
//! and inputs, so the production verifier path can be shown to REJECT it. It sets
//! RISC0_DEV_MODE itself and labels its output; it is never used by the honest worker.
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;

#[derive(Deserialize)]
struct Req { portfolio: String, version: u32, salt_hex: String, holdings: [u32; 4], challenge_hex: String }
#[derive(Serialize)]
struct Resp { ok: bool, fake: bool, image_id_hex: String, receipt_b64: String, receipt_sha256: String, journal_hex: String, error: Option<String> }

fn main() {
    std::env::set_var("RISC0_DEV_MODE", "1");
    let mut input = String::new();
    std::io::stdin().take(1 << 16).read_to_string(&mut input).unwrap();
    let req: Req = serde_json::from_str(&input).expect("bad request");
    let mut salt = [0u8; 32]; salt.copy_from_slice(&hex::decode(&req.salt_hex).unwrap());
    let mut challenge = [0u8; 16]; challenge.copy_from_slice(&hex::decode(&req.challenge_hex).unwrap());
    let env = ExecutorEnv::builder().write(&req.portfolio).unwrap().write(&req.version).unwrap().write(&salt).unwrap().write(&req.holdings).unwrap().write(&challenge).unwrap().build().unwrap();
    let receipt = default_prover().prove(env, a2aid_zk_methods::A2AID_ZK_GUEST_ELF).expect("dev prove").receipt;
    let is_fake = matches!(receipt.inner, InnerReceipt::Fake(_));
    let bytes = bincode::serialize(&receipt).unwrap();
    let mut id: [u8; 32] = [0u8; 32];
    for (i, w) in a2aid_zk_methods::A2AID_ZK_GUEST_ID.iter().enumerate() { id[i*4..i*4+4].copy_from_slice(&w.to_le_bytes()); }
    let resp = Resp { ok: true, fake: is_fake, image_id_hex: hex::encode(id), receipt_b64: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes), receipt_sha256: hex::encode(Sha256::digest(&bytes)), journal_hex: hex::encode(&receipt.journal.bytes), error: None };
    println!("{}", serde_json::to_string(&resp).unwrap());
}
