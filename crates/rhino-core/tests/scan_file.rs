//! Pruebas de integración: escaneo real de archivos en disco.

use std::fs;
use std::path::PathBuf;

use rhino_core::{Verdict, scan_file};

/// Contenido exacto del archivo de prueba estándar EICAR (inofensivo).
const EICAR: &str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/// Cada prueba usa un nombre distinto para que puedan correr en paralelo.
fn write_temp(name: &str, contents: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("rhino-test-{}-{name}", std::process::id()));
    fs::write(&path, contents).expect("no se pudo escribir el archivo de prueba");
    path
}

#[test]
fn flags_eicar_written_to_disk() {
    let path = write_temp("eicar.com", EICAR.as_bytes());

    let report = scan_file(&path).expect("el escaneo falló");

    assert_eq!(report.verdict, Verdict::Malicious);
    assert_eq!(report.size, EICAR.len() as u64);
    assert_eq!(report.sha256.len(), 64);

    fs::remove_file(&path).ok();
}

#[test]
fn benign_file_has_no_findings() {
    let path = write_temp("benigno.txt", b"contenido inofensivo");

    let report = scan_file(&path).expect("el escaneo falló");

    assert_eq!(report.verdict, Verdict::Clean);
    assert!(report.findings.is_empty());

    fs::remove_file(&path).ok();
}

#[test]
fn missing_file_is_an_error() {
    let path = std::env::temp_dir().join("rhino-no-existe-12345.bin");
    assert!(scan_file(&path).is_err());
}
