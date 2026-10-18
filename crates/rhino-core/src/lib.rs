//! Núcleo de Rhino: lógica agnóstica de arquitectura y de sistema operativo.
//!
//! Todo lo que dependa de Windows o del tamaño de puntero vive fuera de este
//! crate (módulo `platform`), para que abandonar 32 bits en el futuro sea trivial.

pub mod corpus;
pub mod db;
mod hash;
mod pe;
pub mod rules;
mod scan;

pub use db::{Database, DbError, HashList, Manifest, Package};
pub use hash::{decode_hex, is_sha256_hex, sha256_hex, sha256_hex_reader, to_hex};
pub use pe::{PeFile, PeSection};
pub use rules::{RuleMatch, RuleSet};
pub use scan::{FileKind, Finding, Layer, ScanReport, Verdict, scan_bytes, scan_dir, scan_file};

/// Versión del núcleo, tomada de `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
