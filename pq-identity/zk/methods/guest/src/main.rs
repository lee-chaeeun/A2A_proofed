//! a2aid ZK guest (schema 1). Private witness: portfolio id, snapshot version,
//! 32-byte salt and four bounded u32 holdings. Public journal (little-endian, fixed
//! width): schema u32 ‖ challenge[16] ‖ commitment[32] ‖ limit u64 ‖ pass u8.
//!
//! The guest RECOMPUTES the commitment and the Boolean; it never accepts a Boolean
//! as input, and it publishes neither the holdings, their sum nor the salt.
use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};

const SCHEMA: u32 = 1;
const LIMIT: u64 = 100;
const MAX_HOLDING: u32 = 1 << 20;
const DOMAIN: &[u8] = b"a2aid-zk-commit-v1";

fn main() {
    // Private inputs (host writes them with env::write in this order).
    let portfolio: String = env::read();
    let version: u32 = env::read();
    let salt: [u8; 32] = env::read();
    let holdings: [u32; 4] = env::read();
    // Public context chosen by the requester, committed verbatim.
    let challenge: [u8; 16] = env::read();

    for h in holdings.iter() {
        assert!(*h <= MAX_HOLDING, "holding out of bounds");
    }
    let sum: u64 = holdings.iter().map(|h| *h as u64).sum();
    let pass: u8 = if sum <= LIMIT { 1 } else { 0 };

    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update([0u8]);
    hasher.update(portfolio.as_bytes());
    hasher.update([0u8]);
    hasher.update(version.to_le_bytes());
    hasher.update(salt);
    for h in holdings.iter() {
        hasher.update(h.to_le_bytes());
    }
    let commitment: [u8; 32] = hasher.finalize().into();

    let mut journal = Vec::with_capacity(4 + 16 + 32 + 8 + 1);
    journal.extend_from_slice(&SCHEMA.to_le_bytes());
    journal.extend_from_slice(&challenge);
    journal.extend_from_slice(&commitment);
    journal.extend_from_slice(&LIMIT.to_le_bytes());
    journal.push(pass);
    env::commit_slice(&journal);
}
