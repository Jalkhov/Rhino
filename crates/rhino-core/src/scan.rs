//! Orquestador de escaneo.
//!
//! Devuelve un informe estructurado y **nombra la capa que detectó** cada
//! hallazgo (ver "Capas de detección" en el README).

use std::fs::File;
use std::io::{self, Cursor};
use std::path::Path;

use crate::hash::{sha256_hex, sha256_hex_reader};
use crate::pe::{self, PeFile};

/// Capa de detección que produjo un hallazgo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// Capa 1: coincidencia exacta con la lista de hashes conocido-malo.
    Hash,
    /// Capa 2: reglas YARA-X (pendiente de integrar).
    Rules,
    /// Capa 3: heurística propia sobre la estructura del archivo.
    Heuristic,
}

impl Layer {
    pub fn label(self) -> &'static str {
        match self {
            Layer::Hash => "hash conocido",
            Layer::Rules => "regla",
            Layer::Heuristic => "heurística",
        }
    }
}

/// Gravedad de un hallazgo y, por extensión, del archivo analizado.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Clean => "limpio",
            Verdict::Suspicious => "sospechoso",
            Verdict::Malicious => "malicioso",
        }
    }
}

/// Tipo de archivo reconocido por su cabecera.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileKind {
    Pe(PeFile),
    Other,
}

impl FileKind {
    pub fn label(&self) -> String {
        match self {
            FileKind::Pe(image) => format!("ejecutable PE ({})", image.machine_name()),
            FileKind::Other => "tipo desconocido".to_string(),
        }
    }
}

/// Un motivo concreto de detección.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub layer: Layer,
    pub name: String,
    pub detail: String,
    pub verdict: Verdict,
}

/// Resultado completo de analizar un archivo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReport {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub kind: FileKind,
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
}

impl ScanReport {
    /// Texto corto y de una sola pieza para la interfaz.
    pub fn summary(&self) -> String {
        let mut text = format!("{}: {}", self.file_name(), self.verdict.label());
        for finding in &self.findings {
            text.push_str(&format!(
                "\n• [{}] {}",
                finding.layer.label(),
                finding.detail
            ));
        }
        text
    }

    fn file_name(&self) -> String {
        Path::new(&self.path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.path.clone())
    }
}

/// Analiza un archivo del disco sin cargarlo completo en memoria.
pub fn scan_file(path: impl AsRef<Path>) -> io::Result<ScanReport> {
    let path = path.as_ref();
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    let sha256 = sha256_hex_reader(&mut file)?;
    let kind = match pe::parse(&mut file)? {
        Some(image) => FileKind::Pe(image),
        None => FileKind::Other,
    };
    Ok(build_report(path, size, sha256, kind))
}

/// Analiza datos que ya están en memoria. Pensado para pruebas.
pub fn scan_bytes(name: &str, data: &[u8]) -> ScanReport {
    let mut cursor = Cursor::new(data);
    let kind = match pe::parse(&mut cursor) {
        Ok(Some(image)) => FileKind::Pe(image),
        _ => FileKind::Other,
    };
    build_report(Path::new(name), data.len() as u64, sha256_hex(data), kind)
}

fn build_report(path: &Path, size: u64, sha256: String, kind: FileKind) -> ScanReport {
    let mut findings = Vec::new();

    if let Some(known) = known_bad(&sha256) {
        findings.push(Finding {
            layer: Layer::Hash,
            name: known.name.to_string(),
            detail: known.detail.to_string(),
            verdict: Verdict::Malicious,
        });
    }

    if let FileKind::Pe(image) = &kind {
        findings.extend(pe_findings(image));
    }

    let verdict = findings
        .iter()
        .map(|finding| finding.verdict)
        .max()
        .unwrap_or(Verdict::Clean);

    ScanReport {
        path: path.to_string_lossy().into_owned(),
        size,
        sha256,
        kind,
        verdict,
        findings,
    }
}

fn pe_findings(image: &PeFile) -> Vec<Finding> {
    let mut findings = Vec::new();

    for section in image.packer_sections() {
        findings.push(Finding {
            layer: Layer::Heuristic,
            name: "PE-Packer".to_string(),
            detail: format!(
                "la sección «{}» es característica de un empaquetador",
                section.name
            ),
            verdict: Verdict::Suspicious,
        });
    }

    for section in image.writable_executable_sections() {
        findings.push(Finding {
            layer: Layer::Heuristic,
            name: "PE-Section-WX".to_string(),
            detail: format!(
                "la sección «{}» es ejecutable y escribible a la vez",
                section.name
            ),
            verdict: Verdict::Suspicious,
        });
    }

    findings
}

/// Entrada de la lista de hashes conocido-malo.
struct KnownBad {
    sha256: &'static str,
    name: &'static str,
    detail: &'static str,
}

/// Lista provisional embebida. La sustituirá `hashes.bin` dentro del paquete
/// de base de datos firmado (ver "Paquete de base de datos" en el README).
const KNOWN_BAD: &[KnownBad] = &[KnownBad {
    sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    name: "EICAR-Test-File",
    detail: "coincide con el archivo de prueba estándar EICAR",
}];

fn known_bad(sha256: &str) -> Option<&'static KnownBad> {
    KNOWN_BAD.iter().find(|entry| entry.sha256 == sha256)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::test_support::synthetic_pe;

    /// Contenido exacto del archivo de prueba estándar EICAR (inofensivo).
    const EICAR: &str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    const SECTION_EXEC_READ: u32 = 0x6000_0020;
    const SECTION_EXEC_READ_WRITE: u32 = 0xe000_0020;

    #[test]
    fn detects_eicar_by_hash() {
        let report = scan_bytes("eicar.com", EICAR.as_bytes());

        assert_eq!(report.verdict, Verdict::Malicious);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].layer, Layer::Hash);
        assert_eq!(report.findings[0].name, "EICAR-Test-File");
    }

    #[test]
    fn benign_text_is_clean() {
        let report = scan_bytes("notas.txt", b"hola mundo");

        assert_eq!(report.verdict, Verdict::Clean);
        assert!(report.findings.is_empty());
        assert_eq!(report.kind, FileKind::Other);
        assert_eq!(report.sha256.len(), 64);
    }

    #[test]
    fn benign_pe_is_clean() {
        let image = synthetic_pe(".text", SECTION_EXEC_READ);
        let report = scan_bytes("limpio.exe", &image);

        assert_eq!(report.verdict, Verdict::Clean);
        assert!(report.findings.is_empty());
        assert!(matches!(report.kind, FileKind::Pe(_)));
    }

    #[test]
    fn packer_section_is_suspicious() {
        let image = synthetic_pe("UPX0", SECTION_EXEC_READ);
        let report = scan_bytes("empaquetado.exe", &image);

        assert_eq!(report.verdict, Verdict::Suspicious);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].layer, Layer::Heuristic);
        assert_eq!(report.findings[0].name, "PE-Packer");
    }

    #[test]
    fn writable_executable_section_is_suspicious() {
        let image = synthetic_pe(".text", SECTION_EXEC_READ_WRITE);
        let report = scan_bytes("automod.exe", &image);

        assert_eq!(report.verdict, Verdict::Suspicious);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].name, "PE-Section-WX");
    }

    #[test]
    fn summary_names_the_detecting_layer() {
        let report = scan_bytes("eicar.com", EICAR.as_bytes());
        let summary = report.summary();

        assert!(summary.starts_with("eicar.com: malicioso"), "{summary}");
        assert!(summary.contains("[hash conocido]"), "{summary}");
    }
}
