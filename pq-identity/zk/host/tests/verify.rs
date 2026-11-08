//! Host-side tests over a RETAINED genuine receipt (no proving in tests): the pinned
//! image id verifies it; a wrong image id, a flipped byte and dev-mode acceptance
//! are rejected; the journal decodes to the canonical schema.
use risc0_zkvm::{InnerReceipt, Receipt};

fn load() -> (Receipt, [u32; 8]) {
    let b64 = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/genuine-receipt-v1.b64")).unwrap();
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64.trim()).unwrap();
    let receipt: Receipt = bincode::deserialize(&bytes).unwrap();
    let id_hex = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/image-id.txt")).unwrap();
    let id_b = hex::decode(id_hex.trim()).unwrap();
    let mut id = [0u32; 8];
    for i in 0..8 { id[i] = u32::from_le_bytes([id_b[i*4], id_b[i*4+1], id_b[i*4+2], id_b[i*4+3]]); }
    (receipt, id)
}

#[test]
fn pinned_image_id_is_the_embedded_guest() {
    let (_, id) = load();
    assert_eq!(id, a2aid_zk_methods::A2AID_ZK_GUEST_ID, "testdata/image-id.txt must match the embedded guest; rebuild changes the guest id");
}

#[test]
fn genuine_receipt_verifies_and_journal_is_canonical() {
    let (r, id) = load();
    assert!(!matches!(r.inner, InnerReceipt::Fake(_)));
    r.verify(id).expect("genuine receipt verifies under the pinned id");
    let j = &r.journal.bytes;
    assert_eq!(j.len(), 4 + 16 + 32 + 8 + 1);
    assert_eq!(u32::from_le_bytes([j[0], j[1], j[2], j[3]]), 1, "schema");
    assert_eq!(u64::from_le_bytes(j[52..60].try_into().unwrap()), 100, "limit");
    assert!(j[60] == 0 || j[60] == 1);
}

#[test]
fn wrong_image_id_is_rejected() {
    let (r, mut id) = load();
    id[0] ^= 1;
    assert!(r.verify(id).is_err());
}

#[test]
fn flipped_byte_is_rejected() {
    let b64 = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/genuine-receipt-v1.b64")).unwrap();
    let mut bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64.trim()).unwrap();
    let n = bytes.len();
    bytes[n / 2] ^= 1;
    let (_, id) = load();
    match bincode::deserialize::<Receipt>(&bytes) {
        Err(_) => {}
        Ok(r) => assert!(r.verify(id).is_err(), "corrupted receipt must not verify"),
    }
}
