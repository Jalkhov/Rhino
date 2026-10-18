//! Hashing por streaming: el archivo nunca se carga completo en memoria.
//!
//! En 32 bits un archivo grande no cabe en el espacio de direcciones, así que
//! todo el hashing pasa por un búfer de tamaño fijo.

use std::io::{self, Read};

use sha2::{Digest, Sha256};

/// Tamaño del búfer de lectura. 64 KiB es un buen equilibrio en 32 bits.
const BUFFER_SIZE: usize = 64 * 1024;

/// Devuelve el SHA-256 de `data` en hexadecimal minúsculas (64 caracteres).
pub fn sha256_hex(data: &[u8]) -> String {
    to_hex(&Sha256::digest(data))
}

/// Devuelve el SHA-256 del flujo `reader`, leído por bloques.
pub fn sha256_hex_reader(mut reader: impl Read) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; BUFFER_SIZE];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(to_hex(&hasher.finalize()))
}

/// Convierte bytes en hexadecimal minúsculas.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Decodifica `N` bytes escritos en hexadecimal, con la longitud exacta.
pub fn decode_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 {
        return None;
    }

    let mut bytes = [0u8; N];
    for (index, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        bytes[index] = (high * 16 + low) as u8;
    }
    Some(bytes)
}

/// `true` si el texto es un SHA-256 en hexadecimal.
///
/// Es la forma que tienen los hashes en el manifiesto y en `hashes.bin`, así que
/// vale como filtro de entrada en todos los bordes de confianza.
pub fn is_sha256_hex(text: &str) -> bool {
    decode_hex::<32>(text).is_some()
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

    #[test]
    fn streaming_matches_one_shot_across_many_blocks() {
        // Supera el búfer varias veces, así que obliga a leer en bucle.
        let data = vec![0x5au8; 5 * BUFFER_SIZE + 7];
        assert_eq!(sha256_hex_reader(&data[..]).unwrap(), sha256_hex(&data));
    }

    #[test]
    fn streaming_handles_empty_input() {
        assert_eq!(sha256_hex_reader(&b""[..]).unwrap(), sha256_hex(b""));
    }
}
