//! Pruebas de propiedad sobre la superficie pública.
//!
//! El motor come archivos hostiles, así que ninguna entrada —por absurda que
//! sea— debería poder tumbarlo ni colarse. La lección viene del historial de CVE
//! de ClamAV: sus fallos graves están en los parsers de formato, no en el motor
//! de firmas. Rust quita la corrupción de memoria, pero no el pánico, así que
//! eso hay que probarlo aparte.

use proptest::prelude::*;
use rhino_core::db::verify_manifest;
use rhino_core::{
    Database, HashList, Verdict, decode_hex, is_sha256_hex, scan_bytes, sha256_hex,
    sha256_hex_reader, to_hex,
};

proptest! {
    /// Escanear debe terminar siempre, y el veredicto nunca puede ser mejor que
    /// el peor hallazgo: esa es la regla que impide que un archivo peligroso
    /// acabe reportado como limpio.
    #[test]
    fn scanning_arbitrary_bytes_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let report = scan_bytes("entrada", &data, &Database::empty());
        let worst = report.findings.iter().map(|finding| finding.verdict).max();
        prop_assert_eq!(report.verdict, worst.unwrap_or(Verdict::Clean));
    }

    /// El hash por *streaming* es el que se usa de verdad, para no cargar el
    /// archivo entero en memoria; debe dar exactamente lo mismo que el de una vez.
    #[test]
    fn streaming_hash_matches_one_shot(
        data in proptest::collection::vec(any::<u8>(), 0..50_000),
    ) {
        prop_assert_eq!(sha256_hex_reader(&data[..]).unwrap(), sha256_hex(&data));
    }

    /// La lista de hashes solo acepta múltiplos exactos de 32 bytes.
    #[test]
    fn hash_list_accepts_exactly_multiples_of_32(
        bytes in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        prop_assert_eq!(HashList::from_binary(&bytes).is_ok(), bytes.len() % 32 == 0);
    }

    /// Todo digest que entra en la lista tiene que salir. Esto prueba la
    /// búsqueda binaria, que es donde un orden mal hecho se lleva detecciones
    /// por delante en silencio.
    #[test]
    fn every_digest_in_the_list_is_found(
        bytes in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let complete = &bytes[..bytes.len() - bytes.len() % 32];
        let list = HashList::from_binary(complete).unwrap();
        for digest in complete.chunks(32) {
            prop_assert!(list.contains_hex(&to_hex(digest)));
        }
    }

    /// Un manifiesto sin firma válida no se acepta nunca, y ninguna entrada
    /// puede hacer entrar en pánico al verificador.
    #[test]
    fn verifying_arbitrary_manifests_never_panics(
        manifest in proptest::collection::vec(any::<u8>(), 0..2048),
        signature in "\\PC{0,200}",
    ) {
        prop_assert!(verify_manifest(&manifest, &signature, &[0u8; 32]).is_err());
    }

    /// El descifrado hexadecimal acepta exactamente 64 dígitos, en cualquier
    /// caja, y rechaza todo lo demás. Es el filtro de entrada de los bordes de
    /// confianza, así que no puede ser generoso de más.
    #[test]
    fn decode_hex_accepts_exactly_64_hex_digits(text in "\\PC{0,80}") {
        let is_hex = text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit());
        prop_assert_eq!(decode_hex::<32>(&text).is_some(), is_hex);
        prop_assert_eq!(is_sha256_hex(&text), is_hex);
    }
}
