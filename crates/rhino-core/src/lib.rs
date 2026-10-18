//! Núcleo de Rhino: lógica agnóstica de arquitectura y de sistema operativo.
//!
//! Todo lo que dependa de Windows o del tamaño de puntero vive fuera de este
//! crate (módulo `platform`), para que abandonar 32 bits en el futuro sea trivial.

use sha2::{Digest, Sha256};

/// Versión del núcleo, tomada de `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Devuelve el SHA-256 de `data` en hexadecimal minúsculas (64 caracteres).
pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector_abc() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_empty_input() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hex_has_64_chars() {
        assert_eq!(sha256_hex(b"rhino").len(), 64);
    }
}
