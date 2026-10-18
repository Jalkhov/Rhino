//! Pruebas de integración: escaneo real de archivos en disco.

use std::fs;
use std::path::PathBuf;

use rhino_core::corpus::{benign_text, eicar, packed_pe};
use rhino_core::{Layer, Verdict, scan_file};

/// Cada prueba usa un nombre distinto para que puedan correr en paralelo.
fn write_temp(name: &str, contents: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("rhino-test-{}-{name}", std::process::id()));
    fs::write(&path, contents).expect("no se pudo escribir el archivo de prueba");
    path
}

#[test]
fn flags_eicar_written_to_disk() {
    let contents = eicar();
    let path = write_temp("eicar.com", &contents);

    let report = scan_file(&path).expect("el escaneo falló");

    assert_eq!(report.verdict, Verdict::Malicious);
    assert_eq!(report.size, contents.len() as u64);
    assert_eq!(report.sha256.len(), 64);

    fs::remove_file(&path).ok();
}

#[test]
fn benign_file_has_no_findings() {
    let path = write_temp("benigno.txt", &benign_text());

    let report = scan_file(&path).expect("el escaneo falló");

    assert_eq!(report.verdict, Verdict::Clean);
    assert!(report.findings.is_empty());

    fs::remove_file(&path).ok();
}

#[test]
fn flags_a_packed_executable_written_to_disk() {
    let path = write_temp("empaquetado.exe", &packed_pe());

    let report = scan_file(&path).expect("el escaneo falló");

    assert_eq!(report.verdict, Verdict::Suspicious);
    assert!(!report.findings.is_empty());
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.layer == Layer::Heuristic)
    );

    fs::remove_file(&path).ok();
}

#[test]
fn missing_file_is_an_error() {
    let path = std::env::temp_dir().join("rhino-no-existe-12345.bin");
    assert!(scan_file(&path).is_err());
}
