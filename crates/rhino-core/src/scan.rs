//! Orquestador de escaneo.
//!
//! Devuelve un informe estructurado y **nombra la capa que detectó** cada
//! hallazgo (ver "Capas de detección" en el README).

use std::fs::{self, File};
use std::io::{self, Cursor, Seek, SeekFrom};
use std::path::Path;

use crate::db::Database;
use crate::hash::{sha256_hex, sha256_hex_reader};
use crate::pe::{self, PeFile};
use crate::rules::{RuleMatch, RuleSet, SCORE_MALICIOUS};

/// Capa de detección que produjo un hallazgo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// Capa 1: coincidencia exacta con la lista de hashes conocido-malo.
    Hash,
    /// Capa 2: coincidencia con una regla YARA-X.
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
    /// Versión del paquete con el que se analizó, o `None` si se escaneó sin base
    /// de datos: entonces no se aplicaron ni los hashes ni las reglas.
    pub database: Option<String>,
}

impl ScanReport {
    /// Texto corto y de una sola pieza para la interfaz.
    pub fn summary(&self) -> String {
        let mut text = format!("{}: {}", self.file_name(), self.verdict.label());
        // «Limpio» sin base de datos no significa lo mismo que «limpio» con ella.
        if self.database.is_none() {
            text.push_str(" (sin base de datos: no se comprobaron hashes ni reglas)");
        }
        for finding in &self.findings {
            text.push_str(&format!(
                "\n• [{}] {}",
                finding.layer.label(),
                finding.detail
            ));
        }
        text
    }

    pub fn file_name(&self) -> String {
        Path::new(&self.path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.path.clone())
    }
}

/// Analiza un archivo del disco.
///
/// Nada se carga entero en memoria: el hash usa un búfer fijo, la cabecera PE se
/// lee acotada y la capa de reglas recibe la ruta, no los bytes (el motor decide
/// entre leer y mapear, con tope de tamaño).
pub fn scan_file(path: impl AsRef<Path>, database: &Database) -> io::Result<ScanReport> {
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

    let rules = database.rules();
    let rule_findings = if rules.is_empty() {
        Vec::new()
    } else {
        rule_findings_for_path(path, rules)
    };

    Ok(build_report(
        path,
        size,
        sha256,
        kind,
        rule_findings,
        database,
    ))
}

/// Analiza recursivamente todos los archivos de un directorio, entregando cada
/// informe a `on_report` en cuanto está listo.
///
/// No acumula nada: quien llama decide qué guardar. Un disco entero produce
/// cientos de miles de informes, y guardarlos todos es justo lo que Rhino no
/// puede hacer en un equipo modesto.
///
/// Los enlaces simbólicos no se siguen (evita ciclos) y solo se miran archivos
/// regulares, para no bloquearse en un FIFO o un dispositivo. Una carpeta sin
/// permisos no aborta el escaneo: se omite.
pub fn scan_dir(
    root: impl AsRef<Path>,
    database: &Database,
    mut on_report: impl FnMut(ScanReport),
) -> io::Result<()> {
    collect_files(root.as_ref(), database, &mut on_report)
}

fn collect_files(
    directory: &Path,
    database: &Database,
    on_report: &mut impl FnMut(ScanReport),
) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let Ok(entry) = entry else { continue };
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let path = entry.path();

        if file_type.is_symlink() {
            continue;
        } else if file_type.is_dir() {
            collect_files(&path, database, on_report).ok();
        } else if file_type.is_file()
            && let Ok(report) = scan_file(&path, database)
        {
            on_report(report);
        }
    }
    Ok(())
}

/// Analiza datos que ya están en memoria. Pensado para pruebas.
pub fn scan_bytes(name: &str, data: &[u8], database: &Database) -> ScanReport {
    let mut cursor = Cursor::new(data);
    let kind = match pe::parse(&mut cursor) {
        Ok(Some(image)) => FileKind::Pe(image),
        _ => FileKind::Other,
    };
    let rule_findings = rule_findings(data, database.rules());
    build_report(
        Path::new(name),
        data.len() as u64,
        sha256_hex(data),
        kind,
        rule_findings,
        database,
    )
}

fn build_report(
    path: &Path,
    size: u64,
    sha256: String,
    kind: FileKind,
    rule_findings: Vec<Finding>,
    database: &Database,
) -> ScanReport {
    let mut findings = Vec::new();

    if database.hashes().contains_hex(&sha256) {
        findings.push(Finding {
            layer: Layer::Hash,
            name: "Hash conocido".to_string(),
            detail: "coincide con la lista de hashes conocido-malo".to_string(),
            verdict: Verdict::Malicious,
        });
    }

    findings.extend(rule_findings);

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
        database: if database.is_empty() {
            None
        } else {
            Some(database.version().unwrap_or("sin versión").to_string())
        },
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

/// Convierte las coincidencias de la capa 2 en hallazgos.
///
/// Si el motor de reglas falla —por ejemplo, por tiempo agotado— el resultado se
/// marca como sospechoso. Reportar «limpio» un archivo que no llegó a analizarse
/// sería un falso negativo causado por nosotros.
fn rule_findings(data: &[u8], rules: &RuleSet) -> Vec<Finding> {
    match rules.scan(data) {
        Ok(matches) => matches.iter().map(rule_finding).collect(),
        Err(error) => vec![rule_error(error)],
    }
}

/// Igual que [`rule_findings`], pero dejando que el motor lea el archivo.
fn rule_findings_for_path(path: &Path, rules: &RuleSet) -> Vec<Finding> {
    match rules.scan_path(path) {
        Ok(matches) => matches.iter().map(rule_finding).collect(),
        Err(error) => vec![rule_error(error)],
    }
}

fn rule_error(error: String) -> Finding {
    Finding {
        layer: Layer::Rules,
        name: "Reglas no aplicadas".to_string(),
        detail: format!("el motor de reglas falló: {error}"),
        verdict: Verdict::Suspicious,
    }
}

fn rule_finding(matched: &RuleMatch) -> Finding {
    let mut detail = matched
        .description
        .clone()
        .unwrap_or_else(|| format!("coincide con la regla {}", matched.identifier));

    // La licencia DRL 1.1 exige conservar el autor y un enlace al conjunto de
    // reglas en el mensaje de coincidencia.
    if let Some(author) = &matched.author {
        detail.push_str(&format!(" · autor: {author}"));
    }
    if let Some(url) = &matched.source_url {
        detail.push_str(&format!(" · {url}"));
    }

    Finding {
        layer: Layer::Rules,
        name: matched.identifier.clone(),
        detail,
        verdict: match matched.score {
            Some(score) if score < SCORE_MALICIOUS => Verdict::Suspicious,
            // Sin puntaje declarado la regla es nuestra, y se asume de confianza.
            _ => Verdict::Malicious,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HashList;
    use crate::corpus::{
        EICAR_TEXT, benign_pe, benign_text, eicar, eicar_sha256, packed_pe, truncated_pe,
        writable_executable_pe,
    };

    /// Regla mínima propia: prueba la capa 2 sin descargar YARA Forge.
    const TEST_RULE: &str = r#"
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

    fn test_rules() -> RuleSet {
        RuleSet::compile(&[TEST_RULE]).expect("la regla de prueba no compiló")
    }

    fn test_database() -> Database {
        Database::from_parts(test_rules(), HashList::empty())
    }

    /// Base de datos que solo conoce el hash del EICAR, para probar la capa 1.
    fn hash_database() -> Database {
        Database::from_parts(
            RuleSet::empty(),
            HashList::from_hex([eicar_sha256()]).expect("el hash del EICAR es válido"),
        )
    }

    /// Solo el fragmento que busca la regla: así la capa de hash no interviene y
    /// lo que se mide es exclusivamente la capa de reglas.
    const MARKER: &[u8] = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE";

    #[test]
    fn detects_eicar_by_hash() {
        let report = scan_bytes("eicar.com", &eicar(), &hash_database());

        assert_eq!(report.verdict, Verdict::Malicious);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].layer, Layer::Hash);
        assert_eq!(report.findings[0].name, "Hash conocido");
    }

    #[test]
    fn an_empty_database_does_not_know_the_eicar_hash() {
        let report = scan_bytes("eicar.com", &eicar(), &Database::empty());

        assert_eq!(report.verdict, Verdict::Clean);
    }

    #[test]
    fn benign_text_is_clean() {
        let report = scan_bytes("notas.txt", &benign_text(), &Database::empty());

        assert_eq!(report.verdict, Verdict::Clean);
        assert!(report.findings.is_empty());
        assert_eq!(report.kind, FileKind::Other);
        assert_eq!(report.sha256.len(), 64);
    }

    #[test]
    fn benign_pe_is_clean() {
        let report = scan_bytes("limpio.exe", &benign_pe(), &Database::empty());

        assert_eq!(report.verdict, Verdict::Clean);
        assert!(report.findings.is_empty());
        assert!(matches!(report.kind, FileKind::Pe(_)));
    }

    #[test]
    fn packer_sections_are_suspicious() {
        let report = scan_bytes("empaquetado.exe", &packed_pe(), &Database::empty());

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
        let report = scan_bytes("automod.exe", &writable_executable_pe(), &Database::empty());

        assert_eq!(report.verdict, Verdict::Suspicious);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].name, "PE-Section-WX");
    }

    #[test]
    fn truncated_image_is_not_an_executable() {
        let report = scan_bytes("cortado.exe", &truncated_pe(), &Database::empty());

        assert_eq!(report.kind, FileKind::Other);
        assert_eq!(report.verdict, Verdict::Clean);
    }

    #[test]
    fn summary_names_the_detecting_layer() {
        let report = scan_bytes("eicar.com", &eicar(), &hash_database());
        let summary = report.summary();

        assert!(summary.starts_with("eicar.com: malicioso"), "{summary}");
        assert!(summary.contains("[hash conocido]"), "{summary}");
    }

    #[test]
    fn a_matching_rule_is_a_detection_and_carries_its_attribution() {
        let report = scan_bytes("solo-regla.txt", MARKER, &test_database());

        assert_eq!(report.findings.len(), 1, "{report:#?}");
        let finding = &report.findings[0];

        assert_eq!(finding.layer, Layer::Rules);
        assert_eq!(finding.name, "rhino_test_eicar");
        assert_eq!(finding.verdict, Verdict::Malicious);
        assert!(finding.detail.contains("Rhino"), "{}", finding.detail);
        assert!(
            finding.detail.contains("https://example.invalid/reglas"),
            "{}",
            finding.detail
        );
        assert_eq!(report.verdict, Verdict::Malicious);
    }

    #[test]
    fn a_low_score_rule_is_only_suspicious() {
        let source = TEST_RULE.replace("score = 90", "score = 65");
        let rules = RuleSet::compile(&[source.as_str()]).unwrap();
        let database = Database::from_parts(rules, HashList::empty());

        let report = scan_bytes("solo-regla.txt", MARKER, &database);

        assert_eq!(report.verdict, Verdict::Suspicious);
    }

    #[test]
    fn rules_that_do_not_match_leave_the_file_clean() {
        let report = scan_bytes("notas.txt", &benign_text(), &test_database());

        assert_eq!(report.verdict, Verdict::Clean);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn summary_names_the_rules_layer() {
        let report = scan_bytes("solo-regla.txt", MARKER, &test_database());
        let summary = report.summary();

        assert!(summary.contains("[regla]"), "{summary}");
    }

    #[test]
    fn scans_a_file_on_disk_with_rules() {
        let path = std::env::temp_dir().join(format!("rhino-reglas-{}.txt", std::process::id()));
        std::fs::write(&path, MARKER).expect("no se pudo escribir el archivo de prueba");

        let report = scan_file(&path, &test_database()).expect("el escaneo falló");

        assert_eq!(report.verdict, Verdict::Malicious);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.layer == Layer::Rules),
            "{report:#?}"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_report_without_a_database_says_so() {
        let sin_base = scan_bytes("eicar.com", &eicar(), &Database::empty());
        assert_eq!(sin_base.database, None);
        assert!(
            sin_base.summary().contains("sin base de datos"),
            "un «limpio» sin base de datos debe avisarlo: {}",
            sin_base.summary()
        );

        let con_base = scan_bytes("notas.txt", &benign_text(), &test_database());
        assert!(con_base.database.is_some());
        assert!(!con_base.summary().contains("sin base de datos"));
    }

    #[test]
    fn scans_a_directory_tree_and_reports_each_file() {
        let root = std::env::temp_dir().join(format!("rhino-dir-{}", std::process::id()));
        std::fs::create_dir_all(root.join("sub")).expect("no se pudo crear el árbol de prueba");
        std::fs::write(root.join("eicar.com"), EICAR_TEXT.as_bytes()).unwrap();
        std::fs::write(root.join("sub").join("notas.txt"), benign_text()).unwrap();

        let mut reports = Vec::new();
        scan_dir(&root, &hash_database(), |report| reports.push(report))
            .expect("el escaneo del directorio falló");

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
