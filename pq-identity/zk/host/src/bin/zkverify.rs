//! Verification CLI. Reads ONE JSON request on stdin, writes ONE JSON response.
//! The expected image id comes from the CALLER's pinned configuration, never from
//! the worker; the journal is returned only after verification succeeds. Dev-mode
//! acceptance is refused regardless of environment.
//!
//! stdin:  {"receipt_b64":"...","expected_image_id_hex":"...64 hex..."}
//! stdout: {"ok":true,"verified":true,"journal_hex":"...","receipt_sha256":"...","verify_ms":N}
//!         or {"ok":true,"verified":false,"error":"..."} for a verification failure,
//!         or {"ok":false,"error":"..."} for malformed input (exit 2).
use risc0_zkvm::{InnerReceipt, Receipt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::time::Instant;

const MAX_RECEIPT_B64: usize = 4 << 20; // 4 MiB of base64 (~3 MiB receipt)

#[derive(Deserialize)]
struct Req {
    receipt_b64: String,
    expected_image_id_hex: String,
}

#[derive(Serialize)]
struct Resp {
    ok: bool,
    verified: bool,
    journal_hex: String,
    receipt_sha256: String,
    receipt_kind: String,
    verify_ms: u128,
    error: Option<String>,
}

fn out(r: Resp, code: i32) -> ! {
    println!("{}", serde_json::to_string(&r).unwrap());
    std::process::exit(code);
}

fn malformed(msg: &str) -> ! {
    out(Resp { ok: false, verified: false, journal_hex: String::new(), receipt_sha256: String::new(), receipt_kind: String::new(), verify_ms: 0, error: Some(msg.to_string()) }, 2)
}

fn main() {
    if std::env::var("RISC0_DEV_MODE").map(|v| v != "0" && !v.is_empty()).unwrap_or(false) {
        malformed("RISC0_DEV_MODE is set; this verifier refuses to run in dev mode");
    }
    let mut input = String::new();
    if std::io::stdin().take((MAX_RECEIPT_B64 + 4096) as u64).read_to_string(&mut input).is_err() {
        malformed("cannot read stdin");
    }
    let req: Req = match serde_json::from_str(&input) {
        Ok(r) => r,
        Err(e) => malformed(&format!("bad request: {e}")),
    };
    if req.receipt_b64.len() > MAX_RECEIPT_B64 {
        malformed("receipt too large");
    }
    let id_v = hex::decode(&req.expected_image_id_hex).unwrap_or_default();
    if id_v.len() != 32 {
        malformed("expected image id must be 32 bytes");
    }
    let mut id = [0u32; 8];
    for i in 0..8 {
        id[i] = u32::from_le_bytes([id_v[i * 4], id_v[i * 4 + 1], id_v[i * 4 + 2], id_v[i * 4 + 3]]);
    }
    let bytes = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, req.receipt_b64.as_bytes()) {
        Ok(b) => b,
        Err(e) => malformed(&format!("bad base64: {e}")),
    };
    let sha = hex::encode(Sha256::digest(&bytes));
    let t0 = Instant::now();
    let receipt: Receipt = match bincode::deserialize(&bytes) {
        Ok(r) => r,
        Err(e) => out(Resp { ok: true, verified: false, journal_hex: String::new(), receipt_sha256: sha, receipt_kind: String::new(), verify_ms: t0.elapsed().as_millis(), error: Some(format!("undecodable receipt: {e}")) }, 1),
    };
    let kind = if matches!(receipt.inner, InnerReceipt::Fake(_)) { "fake" } else if receipt.inner.succinct().is_ok() { "succinct" } else if receipt.inner.composite().is_ok() { "composite" } else { "other" };
    // A fake (dev-mode) receipt is rejected explicitly, before and independent of
    // whatever the library's dev-mode switch would do.
    if kind == "fake" {
        out(Resp { ok: true, verified: false, journal_hex: String::new(), receipt_sha256: sha, receipt_kind: kind.into(), verify_ms: t0.elapsed().as_millis(), error: Some("fake/dev receipt rejected".into()) }, 1);
    }
    match receipt.verify(id) {
        Ok(()) => out(Resp { ok: true, verified: true, journal_hex: hex::encode(&receipt.journal.bytes), receipt_sha256: sha, receipt_kind: kind.into(), verify_ms: t0.elapsed().as_millis(), error: None }, 0),
        Err(e) => out(Resp { ok: true, verified: false, journal_hex: String::new(), receipt_sha256: sha, receipt_kind: kind.into(), verify_ms: t0.elapsed().as_millis(), error: Some(format!("verification failed: {e}")) }, 1),
    }
}
