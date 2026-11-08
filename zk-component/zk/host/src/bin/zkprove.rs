//! Local prover CLI. Reads ONE JSON request on stdin, writes ONE JSON response on
//! stdout. Dev-mode proving is refused: a dev receipt is never produced here.
//!
//! stdin: {"portfolio":"...","version":1,"salt_hex":"...64 hex...","holdings":[u32;4],"challenge_hex":"...32 hex..."}
//! stdout: {"ok":true,"image_id_hex":"...","receipt_b64":"...","receipt_sha256":"...","journal_hex":"...","prove_ms":N,"cycles":N}
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, ProverOpts};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::time::Instant;

#[derive(Deserialize)]
struct Req {
    portfolio: String,
    version: u32,
    salt_hex: String,
    holdings: [u32; 4],
    challenge_hex: String,
}

#[derive(Serialize)]
struct Resp {
    ok: bool,
    image_id_hex: String,
    receipt_b64: String,
    receipt_sha256: String,
    journal_hex: String,
    prove_ms: u128,
    error: Option<String>,
}

fn fail(msg: &str) -> ! {
    let r = Resp { ok: false, image_id_hex: String::new(), receipt_b64: String::new(), receipt_sha256: String::new(), journal_hex: String::new(), prove_ms: 0, error: Some(msg.to_string()) };
    println!("{}", serde_json::to_string(&r).unwrap());
    std::process::exit(1);
}

fn main() {
    // `zkprove --image-id` prints the embedded guest image id (for local pinning) and exits.
    if std::env::args().any(|a| a == "--image-id") {
        println!("{}", serde_json::json!({"image_id_hex": hex::encode(image_id_bytes(a2aid_zk_methods::A2AID_ZK_GUEST_ID))}));
        return;
    }
    if std::env::var("RISC0_DEV_MODE").map(|v| v != "0" && !v.is_empty()).unwrap_or(false) {
        fail("RISC0_DEV_MODE is set; this prover refuses to run in dev mode");
    }
    let mut input = String::new();
    if std::io::stdin().take(1 << 16).read_to_string(&mut input).is_err() {
        fail("cannot read stdin");
    }
    let req: Req = match serde_json::from_str(&input) {
        Ok(r) => r,
        Err(e) => fail(&format!("bad request: {e}")),
    };
    let salt_v = hex::decode(&req.salt_hex).unwrap_or_default();
    let chal_v = hex::decode(&req.challenge_hex).unwrap_or_default();
    if salt_v.len() != 32 || chal_v.len() != 16 {
        fail("salt must be 32 bytes and challenge 16 bytes");
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&salt_v);
    let mut challenge = [0u8; 16];
    challenge.copy_from_slice(&chal_v);

    let env = ExecutorEnv::builder()
        .write(&req.portfolio).unwrap()
        .write(&req.version).unwrap()
        .write(&salt).unwrap()
        .write(&req.holdings).unwrap()
        .write(&challenge).unwrap()
        .build()
        .unwrap();
    let t0 = Instant::now();
    let info = match default_prover().prove_with_opts(env, a2aid_zk_methods::A2AID_ZK_GUEST_ELF, &ProverOpts::succinct()) {
        Ok(i) => i,
        Err(e) => fail(&format!("prove failed: {e}")),
    };
    let receipt = info.receipt;
    // Refuse to emit anything but a real (non-fake) receipt.
    if matches!(receipt.inner, InnerReceipt::Fake(_)) {
        fail("prover produced a fake receipt; refusing");
    }
    if let Err(e) = receipt.verify(a2aid_zk_methods::A2AID_ZK_GUEST_ID) {
        fail(&format!("self-verification failed: {e}"));
    }
    let bytes = bincode::serialize(&receipt).unwrap();
    let image_id_hex = hex::encode(image_id_bytes(a2aid_zk_methods::A2AID_ZK_GUEST_ID));
    let resp = Resp {
        ok: true,
        image_id_hex,
        receipt_b64: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes),
        receipt_sha256: hex::encode(Sha256::digest(&bytes)),
        journal_hex: hex::encode(&receipt.journal.bytes),
        prove_ms: t0.elapsed().as_millis(),
        error: None,
    };
    println!("{}", serde_json::to_string(&resp).unwrap());
}

fn image_id_bytes(id: [u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, w) in id.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}
