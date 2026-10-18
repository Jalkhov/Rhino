//! Orquestador de escaneo.
//!
//! Devuelve un informe estructurado y **nombra la capa que detectó** cada
//! hallazgo (ver "Capas de detección" en el README).

use std::fs::{self, File};
use std::io::{self, Cursor, Seek, SeekFrom};
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
    // Hashear deja el cursor al final; el parseo PE empieza por la cabecera.
    file.seek(SeekFrom::Start(0))?;
    let kind = match pe::parse(&mut file)? {
        Some(image) => FileKind::Pe(image),
        None => FileKind::Other,
    };
    Ok(build_report(path, size, sha256, kind))
}

/// Analiza recursivamente todos los archivos de un directorio.
///
/// Los enlaces simbólicos no se siguen (evita ciclos) y solo se miran archivos
/// regulares, para no bloquearse en un FIFO o un dispositivo. Una carpeta sin
/// permisos no aborta el escaneo: se omite.
///
/// shortcut: acumula todos los informes en memoria; pasar a resultados por lote
/// cuando se escaneen discos completos.
pub fn scan_dir(root: impl AsRef<Path>) -> io::Result<Vec<ScanReport>> {
    let mut reports = Vec::new();
    collect_files(root.as_ref(), &mut reports)?;
    Ok(reports)
}

fn collect_files(directory: &Path, reports: &mut Vec<ScanReport>) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let Ok(entry) = entry else { continue };
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let path = entry.path();

        if file_type.is_symlink() {
            continue;
        } else if file_type.is_dir() {
            collect_files(&path, reports).ok();
        } else if file_type.is_file()
            && let Ok(report) = scan_file(&path)
        {
            reports.push(report);
        }
    }
    Ok(())
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
    use crate::corpus::{
        EICAR_TEXT, benign_pe, benign_text, eicar, packed_pe, truncated_pe, writable_executable_pe,
    };

    #[test]
    fn detects_eicar_by_hash() {
        let report = scan_bytes("eicar.com", &eicar());

        assert_eq!(report.verdict, Verdict::Malicious);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].layer, Layer::Hash);
        assert_eq!(report.findings[0].name, "EICAR-Test-File");
    }

    #[test]
    fn benign_text_is_clean() {
        let report = scan_bytes("notas.txt", &benign_text());

        assert_eq!(report.verdict, Verdict::Clean);
        assert!(report.findings.is_empty());
        assert_eq!(report.kind, FileKind::Other);
        assert_eq!(report.sha256.len(), 64);
    }

    #[test]
    fn benign_pe_is_clean() {
        let report = scan_bytes("limpio.exe", &benign_pe());

        assert_eq!(report.verdict, Verdict::Clean);
        assert!(report.findings.is_empty());
        assert!(matches!(report.kind, FileKind::Pe(_)));
    }

    #[test]
    fn packer_sections_are_suspicious() {
        let report = scan_bytes("empaquetado.exe", &packed_pe());

        assert_eq!(report.verdict, Verdict::Suspicious);
        assert_eq!(report.findings.len(), 2);
        assert!(
            report.findings.iter().all(|finding| {
                finding.layer == Layer::Heuristic && finding.name == "PE-Packer"
            })
        );
    }

    #[test]
    fn writable_executable_section_is_suspicious() {
        let report = scan_bytes("automod.exe", &writable_executable_pe());

        assert_eq!(report.verdict, Verdict::Suspicious);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].name, "PE-Section-WX");
    }

    #[test]
    fn truncated_image_is_not_an_executable() {
        let report = scan_bytes("cortado.exe", &truncated_pe());

        assert_eq!(report.kind, FileKind::Other);
        assert_eq!(report.verdict, Verdict::Clean);
    }

    #[test]
    fn summary_names_the_detecting_layer() {
        let report = scan_bytes("eicar.com", &eicar());
        let summary = report.summary();

        assert!(summary.starts_with("eicar.com: malicioso"), "{summary}");
        assert!(summary.contains("[hash conocido]"), "{summary}");
    }

    #[test]
    fn scans_a_directory_tree() {
        let root = std::env::temp_dir().join(format!("rhino-dir-{}", std::process::id()));
        std::fs::create_dir_all(root.join("sub")).expect("no se pudo crear el árbol de prueba");
        std::fs::write(root.join("eicar.com"), EICAR_TEXT.as_bytes()).unwrap();
        std::fs::write(root.join("sub").join("notas.txt"), benign_text()).unwrap();

        let reports = scan_dir(&root).expect("el escaneo del directorio falló");

        assert_eq!(reports.len(), 2, "{reports:#?}");
        assert!(
            reports
                .iter()
                .any(|report| report.verdict == Verdict::Malicious)
        );
        assert!(
            reports
                .iter()
                .any(|report| report.verdict == Verdict::Clean)
        );

        std::fs::remove_dir_all(&root).ok();
    }
}
