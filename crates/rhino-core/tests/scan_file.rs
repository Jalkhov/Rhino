//! Pruebas de integración: escaneo real de archivos en disco.

use std::fs;
use std::path::PathBuf;

use rhino_core::corpus::{benign_text, eicar, eicar_sha256, packed_pe};
use rhino_core::{Database, HashList, Layer, RuleSet, Verdict, scan_file};

/// Regla propia, para probar la capa 2 sin descargar el paquete de YARA Forge.
const RULE: &str = r#"
rule rhino_test_eicar {
    meta:
        description = "Archivo de prueba EICAR"
        author = "Rhino"
        source_url = "https://example.invalid/reglas"
        score = 90
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}
"#;

fn database_with_rules() -> Database {
    let rules = RuleSet::compile(&[RULE]).expect("la regla de prueba no compiló");
    Database::from_parts(rules, HashList::empty())
}

/// Base de datos que solo conoce el hash del EICAR, como la capa 1 en producción.
fn database_with_hashes() -> Database {
    let hashes = HashList::from_hex([eicar_sha256()]).expect("el hash del EICAR es válido");
    Database::from_parts(RuleSet::empty(), hashes)
}

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

    let report = scan_file(&path, &database_with_hashes()).expect("el escaneo falló");

    assert_eq!(report.verdict, Verdict::Malicious);
    assert_eq!(report.size, contents.len() as u64);
    assert_eq!(report.sha256, eicar_sha256());
    assert_eq!(report.findings[0].layer, Layer::Hash);

    fs::remove_file(&path).ok();
}

#[test]
fn benign_file_has_no_findings() {
    let path = write_temp("benigno.txt", &benign_text());

    let report = scan_file(&path, &Database::empty()).expect("el escaneo falló");

    assert_eq!(report.verdict, Verdict::Clean);
    assert!(report.findings.is_empty());

    fs::remove_file(&path).ok();
}

#[test]
fn a_packed_executable_written_to_disk_is_not_suspicious_by_itself() {
    // Estar empaquetado no dice nada: AIDA64, GPU-Z y el propio Detect It Easy
    // llevan UPX. Se sigue leyendo el archivo entero, pero no se marca.
    let path = write_temp("empaquetado.exe", &packed_pe());

    let report = scan_file(&path, &Database::empty()).expect("el escaneo falló");

    assert_eq!(report.verdict, Verdict::Clean);
    assert!(report.findings.is_empty());

    fs::remove_file(&path).ok();
}

#[test]
fn flags_a_rule_match_written_to_disk() {
    // Solo el fragmento de texto, sin el archivo EICAR completo: así el veredicto
    // no puede venir de la capa de hash y se comprueba la capa de reglas entera,
    // desde el disco hasta el informe.
    let path = write_temp(
        "solo-regla.txt",
        b"prefijo EICAR-STANDARD-ANTIVIRUS-TEST-FILE sufijo",
    );

    let report = scan_file(&path, &database_with_rules()).expect("el escaneo falló");

    assert_eq!(report.findings.len(), 1, "{report:#?}");
    assert_eq!(report.findings[0].layer, Layer::Rules);
    assert_eq!(report.verdict, Verdict::Malicious);

    fs::remove_file(&path).ok();
}

#[test]
fn missing_file_is_an_error() {
    let path = std::env::temp_dir().join("rhino-no-existe-12345.bin");
    assert!(scan_file(&path, &Database::empty()).is_err());
}
