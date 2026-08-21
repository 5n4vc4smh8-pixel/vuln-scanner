#![allow(dead_code)]
pub mod sanitizer;
pub mod crypto;

use sha2::{Sha256, Digest};

/// Gera hash SHA-256 para verificação de integridade
pub fn generate_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}