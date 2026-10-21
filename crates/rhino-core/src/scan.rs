//! Orquestador de escaneo.
//!
//! Devuelve un informe estructurado y **nombra la capa que detectó** cada
//! hallazgo (ver "Capas de detección" en el README).

use std::fs::{self, File};
use std::io::{self, Cursor, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;

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
    /// El archivo no se pudo analizar: el motor entró en pánico con él.
    Internal,
}

impl Layer {
    pub fn label(self) -> &'static str {
        match self {
            Layer::Hash => "hash conocido",
            Layer::Rules => "regla",
            Layer::Heuristic => "heurística",
            Layer::Internal => "error interno",
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

/// De dónde salió una regla que coincidió.
///
/// La licencia DRL 1.1 obliga a conservar y mostrar la autoría, así que la
/// interfaz necesita estos tres datos por separado y no dentro del texto del
/// hallazgo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleOrigin {
    pub identifier: String,
    pub author: String,
    pub source: String,
}

/// Un motivo concreto de detección.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub layer: Layer,
    pub name: String,
    pub detail: String,
    pub verdict: Verdict,
    /// Presente solo si el hallazgo viene de una regla.
    pub rule: Option<RuleOrigin>,
}

/// Lo que dejó un recorrido de directorios.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScanSummary {
    /// La bandera de parada se levantó antes de terminar.
    pub stopped: bool,
    /// Carpetas que no se pudieron listar y archivos que no se pudieron leer.
    pub failed: u64,
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

    // Solo la interpretación del contenido puede entrar en pánico: ni abrir ni
    // hashear dependen de lo que el archivo diga. Aislarla es lo que permite que
    // un archivo raro no tumbe el escaneo entero.
    let analysed = isolate(|| -> io::Result<(FileKind, Vec<Finding>)> {
        let kind = match pe::parse(&mut file)? {
            Some(image) => FileKind::Pe(image),
            None => FileKind::Other,
        };

        let rules = database.rules();
        let findings = if rules.is_empty() || !rules_are_worth_reading(path) {
            Vec::new()
        } else {
            rule_findings_for_path(path, rules)
        };

        Ok((kind, findings))
    });

    let (kind, findings) = match analysed {
        Ok(analysed) => analysed?,
        Err(message) => (FileKind::Other, vec![internal_error(message)]),
    };

    Ok(build_report(path, size, sha256, kind, findings, database))
}

/// ¿Merece este archivo pasar por la capa de reglas?
///
/// No en las imágenes rasterizadas, el audio ni el vídeo. Medido en `/usr/bin`
/// (2.395 archivos): la capa de reglas pone unos 20 s de los 29 s, y en un árbol
/// como `/usr/share/icons` (80.520 archivos) el motor recorre entero lo que es
/// casi todo decoración. Lo que **no** se corta: documentos (PDF, Office, SVG),
/// fuentes ni ejecutables, porque ahí las reglas sí encuentran cosas.
///
/// El hash de la capa 1 se calcula siempre: es barato y es cómo se reconoce el
/// malware ya conocido. Este corte solo evita la segunda pasada de lectura.
fn rules_are_worth_reading(path: &Path) -> bool {
    const MEDIA: [&str; 33] = [
        "png", "jpg", "jpeg", "gif", "bmp", "webp", "ico", "tif", "tiff", "heic", "cr2", "nef",
        "dng", "arw", "mp3", "m4a", "aac", "ogg", "flac", "wav", "wma", "opus", "mp4", "m4v",
        "mkv", "avi", "mov", "wmv", "webm", "flv", "mpg", "mpeg", "3gp",
    ];
    let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
        return true;
    };
    !MEDIA
        .iter()
        .any(|candidate| extension.eq_ignore_ascii_case(candidate))
}

/// Ejecuta `work` aislando cualquier pánico y devolviendo su mensaje.
///
/// El motor interpreta archivos que el usuario no escribió, y ClamAV lleva años
/// demostrando que ahí está la superficie de ataque real: casi todos sus CVE son
/// parsers que caen con una entrada manipulada. Rust elimina la corrupción de
/// memoria, pero no el pánico, así que aquí se captura.
///
/// shortcut: aísla el pánico pero no repara el estado del motor; si aparece un
/// pánico reproducible habrá que mover el análisis a un proceso aparte.
fn isolate<T>(work: impl FnOnce() -> T) -> Result<T, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)).map_err(|payload| {
        if let Some(text) = payload.downcast_ref::<&str>() {
            (*text).to_string()
        } else if let Some(text) = payload.downcast_ref::<String>() {
            text.clone()
        } else {
            "causa desconocida".to_string()
        }
    })
}

/// Hallazgo de un archivo que no se pudo analizar.
///
/// Se marca sospechoso y no limpio: no haber podido mirar no es prueba de
/// inocencia, y un antivirus que falla hacia "limpio" es peor que no tenerlo.
fn internal_error(message: String) -> Finding {
    Finding {
        layer: Layer::Internal,
        name: "Archivo no analizado".to_string(),
        detail: format!("el motor entró en pánico: {message}"),
        verdict: Verdict::Suspicious,
        rule: None,
    }
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
    // Sin bandera, pero la misma ruta: quien no necesita detener no paga por un
    // analizador más lento.
    let nunca = AtomicBool::new(false);
    scan_parallel(root.as_ref(), database, &nunca, &mut on_report, &mut || {}).map(|_| ())
}

/// Igual que [`scan_dir`], pero se puede detener a mitad y devuelve cuánto falló.
///
/// `stopped` se levanta si `stop` se activó antes de terminar. `failed` cuenta las
/// carpetas que no se pudieron listar y los archivos que no se pudieron leer: lo
/// que el escaneo no miró no puede desaparecer del recuento.
pub fn scan_dir_cancellable(
    root: impl AsRef<Path>,
    database: &Database,
    stop: &AtomicBool,
    on_report: impl FnMut(ScanReport),
) -> io::Result<ScanSummary> {
    scan_dir_cancellable_with_failure(root, database, stop, on_report, || {})
}

/// Igual que [`scan_dir_cancellable`], avisando de cada fallo en cuanto ocurre.
///
/// El resumen solo llega al final; la interfaz necesita el aviso para poder
/// enseñar los fallos mientras el análisis sigue.
pub fn scan_dir_cancellable_with_failure(
    root: impl AsRef<Path>,
    database: &Database,
    stop: &AtomicBool,
    mut on_report: impl FnMut(ScanReport),
    mut on_failure: impl FnMut(),
) -> io::Result<ScanSummary> {
    scan_parallel(root.as_ref(), database, stop, &mut on_report, &mut on_failure)
}

/// Lo que viaja de un trabajador al hilo que llama.
enum Work {
    Report(ScanReport),
    Failed,
}

/// Cuántos archivos se analizan a la vez.
///
/// Cuatro como mucho: el trabajo es sobre todo de CPU, pero en un equipo modesto
/// más hilos se pelean por el mismo disco y cada archivo en vuelo puede mapear
/// hasta 64 MB. Medido en Windows, cuatro hilos sobre `C:\Program Files` más que
/// triplican los archivos por segundo de uno.
fn worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|nucleos| nucleos.get())
        .unwrap_or(1)
        .clamp(1, 4)
}

/// Recorre un árbol y analiza sus archivos en varios hilos.
///
/// Un hilo recorre y reparte rutas; varios analizan; el hilo que llama recibe los
/// informes en orden de llegada, así que `on_report` y `on_failure` siguen siendo
/// suyos y no necesitan ser `Send`. Los canales van acotados: si un trabajador se
/// atrasa, el recorrido espera en vez de llenar la memoria con rutas.
fn scan_parallel(
    root: &Path,
    database: &Database,
    stop: &AtomicBool,
    on_report: &mut impl FnMut(ScanReport),
    on_failure: &mut impl FnMut(),
) -> io::Result<ScanSummary> {
    let workers = worker_count();
    if workers == 1 {
        // Un solo núcleo: los canales solo añadirían latencia.
        return walk_files(root, Some(stop), &mut |path| {
            if let Ok(report) = scan_file(&path, database) {
                on_report(report);
            }
        }, on_failure);
    }

    let (path_tx, path_rx) = mpsc::sync_channel::<PathBuf>(workers * 8);
    let path_rx = Mutex::new(path_rx);
    let (work_tx, work_rx) = mpsc::sync_channel::<Work>(workers * 8);
    let mut summary = ScanSummary::default();

    let recorrido = thread::scope(|scope| {
        let recorredor = {
            let work_tx = work_tx.clone();
            let path_tx = path_tx;
            scope.spawn(move || {
                let mut avisar = || {
                    let _ = work_tx.send(Work::Failed);
                };
                walk_files(root, Some(stop), &mut |path| {
                    let _ = path_tx.send(path);
                }, &mut avisar)
            })
        };

        for _ in 0..workers {
            let work_tx = work_tx.clone();
            let path_rx = &path_rx;
            scope.spawn(move || loop {
                // El cerrojo se suelta antes de analizar. En `while let Ok(path) =
                // path_rx.lock()…recv()` el guardia vive hasta el final del cuerpo, así
                // que cada trabajador se quedaba con el reparto durante todo el
                // `scan_file` y se turnaban: medido, 28,5 s de CPU para 29,1 s de pared,
                // o sea un solo núcleo trabajando.
                let siguiente = path_rx.lock().expect("el reparto se envenenó").recv();
                let Ok(path) = siguiente else {
                    break;
                };
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let work = match scan_file(&path, database) {
                    Ok(report) => Work::Report(report),
                    Err(_) => Work::Failed,
                };
                if work_tx.send(work).is_err() {
                    break;
                }
            });
        }
        // El original sobra: el canal se cierra cuando acaban el recorrido y los
        // trabajadores, y entonces el bucle de abajo termina.
        drop(work_tx);

        while let Ok(work) = work_rx.recv() {
            match work {
                Work::Report(report) => on_report(report),
                Work::Failed => {
                    summary.failed += 1;
                    on_failure();
                }
            }
        }

        match recorredor.join() {
            Ok(result) => result,
            Err(_) => Err(io::Error::other("el recorrido del árbol se cayó")),
        }
    })?;

    summary.failed += recorrido.failed;
    summary.stopped = recorrido.stopped;
    Ok(summary)
}

/// El paseo: recorre el árbol y entrega cada archivo a `on_file`.
///
/// Los fallos de lectura y de listado se cuentan aquí; los de análisis, en quien
/// analiza.
fn walk_files(
    directory: &Path,
    stop: Option<&AtomicBool>,
    on_file: &mut dyn FnMut(PathBuf),
    on_failure: &mut dyn FnMut(),
) -> io::Result<ScanSummary> {
    let mut summary = ScanSummary::default();

    for entry in fs::read_dir(directory)? {
        if stop.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            summary.stopped = true;
            return Ok(summary);
        }

        let Ok(entry) = entry else {
            summary.failed += 1;
            on_failure();
            continue;
        };
        let Ok(file_type) = entry.file_type() else {
            summary.failed += 1;
            on_failure();
            continue;
        };
        let path = entry.path();

        if file_type.is_symlink() {
            continue;
        } else if file_type.is_dir() {
            // Una subcarpeta sin permisos no aborta el escaneo, pero se cuenta.
            match walk_files(&path, stop, &mut *on_file, &mut *on_failure) {
                Ok(child) => {
                    summary.failed += child.failed;
                    if child.stopped {
                        summary.stopped = true;
                        return Ok(summary);
                    }
                }
                Err(_) => {
                    summary.failed += 1;
                    on_failure();
                }
            }
        } else if file_type.is_file() {
            on_file(path);
        }
    }

    Ok(summary)
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
            rule: None,
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

    for section in image.writable_executable_sections() {
        findings.push(Finding {
            layer: Layer::Heuristic,
            name: "PE-Section-WX".to_string(),
            detail: format!(
                "la sección «{}» es ejecutable y escribible a la vez",
                section.name
            ),
            verdict: Verdict::Suspicious,
            rule: None,
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
        rule: None,
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
        rule: Some(RuleOrigin {
            identifier: matched.identifier.clone(),
            author: matched.author.clone().unwrap_or_default(),
            source: matched.source_url.clone().unwrap_or_default(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HashList;
    use crate::corpus::{
        CHARACTERISTICS_WRITABLE_CODE, EICAR_TEXT, benign_pe, benign_text, eicar, eicar_sha256,
        packed_pe, pe_with_section, truncated_pe, writable_executable_pe,
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
    fn a_packed_file_is_not_suspicious_by_itself() {
        // Un binario empaquetado con UPX no dice nada: AIDA64, GPU-Z y el propio
        // Detect It Easy lo están. Medido en un C:\Program Files real.
        let report = scan_bytes("empaquetado.exe", &packed_pe(), &Database::empty());

        assert_eq!(report.verdict, Verdict::Clean);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn a_driver_init_section_is_not_suspicious() {
        // La `INIT` de un controlador es W+X a propósito: el cargador la usa al
        // arrancar y la descarta.
        let image = pe_with_section("INIT", CHARACTERISTICS_WRITABLE_CODE);
        let report = scan_bytes("controlador.sys", &image, &Database::empty());

        assert_eq!(report.verdict, Verdict::Clean);
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

        // La autoría viaja también aparte del texto: es lo que muestra la ficha
        // de la comprobación y lo que exige la licencia.
        let origin = finding.rule.as_ref().expect("la regla no dejó su origen");
        assert_eq!(origin.identifier, "rhino_test_eicar");
        assert_eq!(origin.author, "Rhino");
        assert_eq!(origin.source, "https://example.invalid/reglas");
    }

    #[test]
    fn a_finding_that_is_not_a_rule_has_no_origin() {
        let report = scan_bytes("eicar.com", &eicar(), &hash_database());

        assert_eq!(report.findings[0].rule, None);
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

    #[test]
    fn media_is_skipped_and_documents_are_not() {
        for name in ["foto.png", "FOTO.PNG", "clip.mp4", "sonido.mp3"] {
            assert!(!rules_are_worth_reading(Path::new(name)), "{name}");
        }
        for name in [
            "manual.pdf",
            "hoja.xlsx",
            "dibujo.svg",
            "fuente.ttf",
            "programa.exe",
            "comprimido.zip",
            "sin-extension",
        ] {
            assert!(rules_are_worth_reading(Path::new(name)), "{name}");
        }
    }

    #[test]
    fn every_file_in_a_tree_is_reported_exactly_once() {
        let root = std::env::temp_dir().join(format!("rhino-hilos-{}", std::process::id()));
        std::fs::create_dir_all(root.join("a").join("b")).expect("no se pudo crear el árbol");
        for index in 0..20 {
            std::fs::write(root.join(format!("nota-{index}.txt")), benign_text()).unwrap();
            std::fs::write(
                root.join("a").join(format!("otra-{index}.txt")),
                benign_text(),
            )
            .unwrap();
        }
        for index in 0..10 {
            std::fs::write(
                root.join("a").join("b").join(format!("tercera-{index}.txt")),
                benign_text(),
            )
            .unwrap();
        }

        let running = AtomicBool::new(false);
        let mut paths = Vec::new();
        let summary = scan_dir_cancellable(&root, &Database::empty(), &running, |report| {
            paths.push(report.path)
        })
        .expect("el escaneo del directorio falló");

        // Varios hilos reparten las rutas: lo que no puede pasar es que un archivo
        // se pierda por el camino ni que llegue dos veces.
        let unicos: std::collections::HashSet<&String> = paths.iter().collect();
        assert_eq!(paths.len(), 50, "{paths:#?}");
        assert_eq!(unicos.len(), 50, "hay informes repetidos: {paths:#?}");
        assert_eq!(summary.failed, 0, "{summary:?}");
        assert!(!summary.stopped);

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_stopped_scan_delivers_fewer_reports_and_says_so() {
        let root = std::env::temp_dir().join(format!("rhino-parada-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("no se pudo crear el árbol de prueba");
        for index in 0..8 {
            std::fs::write(root.join(format!("nota-{index}.txt")), benign_text()).unwrap();
        }

        let running = AtomicBool::new(false);
        let mut completed = Vec::new();
        let finished = scan_dir_cancellable(&root, &Database::empty(), &running, |report| {
            completed.push(report)
        })
        .expect("el escaneo del directorio falló");
        assert!(!finished.stopped);
        assert_eq!(finished.failed, 0);
        assert_eq!(completed.len(), 8, "{completed:#?}");

        let stopped = AtomicBool::new(true);
        let mut partial = Vec::new();
        let finished = scan_dir_cancellable(&root, &Database::empty(), &stopped, |report| {
            partial.push(report)
        })
        .expect("el escaneo del directorio falló");
        assert!(finished.stopped);
        assert!(
            partial.len() < completed.len(),
            "con la bandera levantada no puede entregar los mismos informes: {} de {}",
            partial.len(),
            completed.len()
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_folder_counts_as_a_failure() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!("rhino-fallos-{}", std::process::id()));
        let locked = root.join("sin-permiso");
        std::fs::create_dir_all(&locked).expect("no se pudo crear el árbol de prueba");
        std::fs::write(root.join("notas.txt"), benign_text()).unwrap();
        std::fs::write(locked.join("oculto.txt"), benign_text()).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

        // Como root se puede listar igual: la prueba no tendría nada que medir.
        if std::fs::read_dir(&locked).is_ok() {
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::remove_dir_all(&root).ok();
            return;
        }

        let running = AtomicBool::new(false);
        let mut reports = Vec::new();
        let summary = scan_dir_cancellable(&root, &Database::empty(), &running, |report| {
            reports.push(report)
        })
        .expect("el escaneo del directorio falló");

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&root).ok();

        assert_eq!(reports.len(), 1, "{reports:#?}");
        assert!(summary.failed >= 1, "{summary:?}");
        assert!(!summary.stopped);
    }

    #[test]
    fn isolate_returns_the_value_when_nothing_panics() {
        assert_eq!(isolate(|| 42), Ok(42));
    }

    #[test]
    fn isolate_turns_a_panic_into_a_message() {
        let caught = isolate(|| -> u8 { panic!("entrada hostil") });

        assert_eq!(caught, Err("entrada hostil".to_string()));
    }

    #[test]
    fn an_unanalysed_file_is_suspicious_never_clean() {
        let finding = internal_error("entrada hostil".to_string());

        assert_eq!(finding.layer, Layer::Internal);
        assert_eq!(finding.verdict, Verdict::Suspicious);
        assert!(finding.detail.contains("entrada hostil"));
    }
}
