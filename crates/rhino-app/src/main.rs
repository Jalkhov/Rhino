#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use slint::{ComponentHandle, Model, ModelRc, VecModel};

use rhino_core::{Database, Quarantine, ScanReport, Verdict};

slint::include_modules!();

/// Qué se ha mandado analizar.
enum ScanTarget {
    WholeComputer,
    Folder(PathBuf),
    File(PathBuf),
}

impl ScanTarget {
    /// Lo que se dice en pantalla mientras esto se analiza, en lenguaje llano.
    fn message(&self) -> &'static str {
        match self {
            ScanTarget::WholeComputer => "Analizando tu equipo…",
            ScanTarget::Folder(_) => "Analizando esa carpeta…",
            ScanTarget::File(_) => "Analizando ese archivo…",
        }
    }
}

/// Lo que hace falta para poner a salvo un hallazgo: su ruta y su huella. La fila
/// `i` de la lista de la ventana se corresponde con `rows[i]`.
struct RowTarget {
    path: String,
    sha256: String,
}

/// Lo que comparten el hilo del análisis y los botones de la ventana.
#[derive(Clone)]
struct ScanShared {
    database: Arc<Database>,
    /// La levanta «Detener»; el recorrido la mira entre archivo y archivo.
    stop: Arc<AtomicBool>,
    scanned: Arc<AtomicUsize>,
    rows: Arc<Mutex<Vec<RowTarget>>>,
}

fn main() -> Result<(), slint::PlatformError> {
    let window = MainWindow::new()?;
    window.set_version(rhino_core::VERSION.into());

    let database = Arc::new(load_database());
    window.set_has_database(!database.is_empty());
    window.set_status(status_for(database.version()).into());

    // La lista de hallazgos vive en un VecModel: la interfaz la pinta y Rust la
    // llena desde el hilo de la interfaz, nunca desde el hilo del análisis.
    let findings_model = Rc::new(VecModel::<FindingItem>::default());
    window.set_findings(ModelRc::from(findings_model.clone()));

    let shared = ScanShared {
        database,
        stop: Arc::new(AtomicBool::new(false)),
        scanned: Arc::new(AtomicUsize::new(0)),
        rows: Arc::new(Mutex::new(Vec::new())),
    };

    let weak_window = window.as_weak();
    let scan_shared = shared.clone();
    let scan_model = findings_model.clone();
    window.on_scan_requested(move || {
        let Some(window) = weak_window.upgrade() else {
            return;
        };

        let target = match window.get_scope() {
            1 => match chosen_path(&window, "Elige primero una carpeta") {
                Some(path) => ScanTarget::Folder(path),
                None => return,
            },
            2 => match chosen_path(&window, "Elige primero un archivo") {
                Some(path) => ScanTarget::File(path),
                None => return,
            },
            _ => ScanTarget::WholeComputer,
        };

        start_scan(&window, scan_shared.clone(), scan_model.clone(), target);
    });

    let weak_window = window.as_weak();
    let scan_shared = shared.clone();
    let scan_model = findings_model.clone();
    window.on_pick_folder(move || {
        let Some(window) = weak_window.upgrade() else {
            return;
        };
        let Some(folder) = rfd::FileDialog::new()
            .set_title("Elige la carpeta que quieres analizar")
            .pick_folder()
        else {
            return;
        };

        window.set_scope(1);
        window.set_file_path(folder.to_string_lossy().into_owned().into());
        start_scan(
            &window,
            scan_shared.clone(),
            scan_model.clone(),
            ScanTarget::Folder(folder),
        );
    });

    let weak_window = window.as_weak();
    let scan_shared = shared.clone();
    let scan_model = findings_model.clone();
    window.on_pick_file(move || {
        let Some(window) = weak_window.upgrade() else {
            return;
        };
        let Some(file) = rfd::FileDialog::new()
            .set_title("Elige el archivo que quieres analizar")
            .pick_file()
        else {
            return;
        };

        window.set_scope(2);
        window.set_file_path(file.to_string_lossy().into_owned().into());
        start_scan(
            &window,
            scan_shared.clone(),
            scan_model.clone(),
            ScanTarget::File(file),
        );
    });

    let weak_window = window.as_weak();
    let stop = Arc::clone(&shared.stop);
    let scanned = Arc::clone(&shared.scanned);
    window.on_cancel_scan(move || {
        stop.store(true, Ordering::Relaxed);

        let Some(window) = weak_window.upgrade() else {
            return;
        };
        window.set_scanning(false);
        window.set_status(detained_status(scanned.load(Ordering::Relaxed)).into());
    });

    let weak_window = window.as_weak();
    let rows = Arc::clone(&shared.rows);
    window.on_quarantine(move |index| {
        let Some(window) = weak_window.upgrade() else {
            return;
        };
        let index = index as usize;

        let target = rows.lock().ok().and_then(|rows| {
            rows.get(index).map(|row| RowTarget {
                path: row.path.clone(),
                sha256: row.sha256.clone(),
            })
        });
        let Some(target) = target else {
            return;
        };

        match Quarantine::open().and_then(|shelter| shelter.store(&target.path, &target.sha256)) {
            Ok(_) => {
                remove_row(&rows, index);
                remove_finding(&window, index);
                window.set_status(
                    format!(
                        "{} está a salvo: ya no puede hacer nada.",
                        file_name(&target.path)
                    )
                    .into(),
                );
            }
            Err(error) => {
                window.set_status(format!("No se pudo poner a salvo: {error}").into());
            }
        }
    });

    let weak_window = window.as_weak();
    let rows = Arc::clone(&shared.rows);
    window.on_ignore(move |index| {
        let Some(window) = weak_window.upgrade() else {
            return;
        };
        let index = index as usize;

        // shortcut: lo ignorado no se recuerda al cerrar el programa; la lista de
        // exclusiones de verdad es otra rebanada.
        remove_row(&rows, index);
        remove_finding(&window, index);
        window.set_status("Lo hemos ignorado esta vez.".into());
    });

    window.run()
}

/// Arranca un análisis: limpia lo anterior y lanza el recorrido fuera del hilo de
/// la interfaz, para que la ventana nunca se congele.
fn start_scan(
    window: &MainWindow,
    shared: ScanShared,
    findings_model: Rc<VecModel<FindingItem>>,
    target: ScanTarget,
) {
    shared.stop.store(false, Ordering::Relaxed);
    shared.scanned.store(0, Ordering::Relaxed);
    findings_model.clear();
    if let Ok(mut rows) = shared.rows.lock() {
        rows.clear();
    }

    window.set_expanded_row(-1);
    window.set_scanned(0);
    window.set_current_file("".into());
    window.set_scanning(true);
    window.set_status(target.message().into());

    let has_database = !shared.database.is_empty();
    let weak_window = window.as_weak();
    std::thread::spawn(move || run_scan(&weak_window, &shared, &target, has_database));
}

/// El recorrido completo, ya en su propio hilo: informa de cada archivo a la
/// interfaz y deja el resumen al terminar.
fn run_scan(
    weak_window: &slint::Weak<MainWindow>,
    shared: &ScanShared,
    target: &ScanTarget,
    has_database: bool,
) {
    let mut suspects = 0usize;
    let mut stopped = false;
    let failure;

    {
        let mut on_report =
            |report: ScanReport| report_to_ui(weak_window, shared, report, &mut suspects);

        let outcome = match target {
            ScanTarget::File(path) => {
                rhino_core::scan_file(path, &shared.database).map(&mut on_report)
            }
            ScanTarget::Folder(root) => rhino_core::scan_dir_cancellable(
                root,
                &shared.database,
                &shared.stop,
                &mut on_report,
            )
            .map(|finished| stopped = !finished),
            ScanTarget::WholeComputer => rhino_core::scan_dir_cancellable(
                system_drive(),
                &shared.database,
                &shared.stop,
                &mut on_report,
            )
            .map(|finished| stopped = !finished),
        };

        failure = outcome.err().map(|error| error.to_string());
    }

    let scanned = Arc::clone(&shared.scanned);
    let _ = weak_window.upgrade_in_event_loop(move |window| {
        window.set_scanning(false);
        window.set_has_database(has_database);
        window.set_status(
            match failure {
                Some(error) => format!("No se pudo analizar: {error}"),
                None if stopped => detained_status(scanned.load(Ordering::Relaxed)),
                None => format!(
                    "{} archivos analizados, {suspects} sospechosos",
                    scanned.load(Ordering::Relaxed)
                ),
            }
            .into(),
        );
    });
}

/// Cuenta un informe, actualiza «el que se está mirando» y, si trae hallazgos, lo
/// añade a la lista.
///
/// Todo lo que toca la ventana pasa por `upgrade_in_event_loop`: el modelo de
/// Slint no cruza hilos.
fn report_to_ui(
    weak_window: &slint::Weak<MainWindow>,
    shared: &ScanShared,
    report: ScanReport,
    suspects: &mut usize,
) {
    let count = shared.scanned.fetch_add(1, Ordering::Relaxed) + 1;
    let current = report.path.clone();
    let finding = (!report.findings.is_empty()).then(|| {
        *suspects += 1;
        (finding_item(&report), report.sha256.clone())
    });

    let rows = Arc::clone(&shared.rows);
    let _ = weak_window.upgrade_in_event_loop(move |window| {
        window.set_scanned(count as i32);
        window.set_current_file(current.into());

        if let Some((item, sha256)) = finding {
            if let Ok(mut rows) = rows.lock() {
                rows.push(RowTarget {
                    path: item.path.to_string(),
                    sha256,
                });
            }
            push_finding(&window, item);
        }
    });
}

/// Un informe con hallazgos, tal como lo pinta la lista.
///
/// Un archivo con varios motivos es una sola fila: los motivos van juntos en el
/// texto. La autoría sale del primer motivo que venga de una regla.
fn finding_item(report: &ScanReport) -> FindingItem {
    let origin = report
        .findings
        .iter()
        .find_map(|finding| finding.rule.as_ref());
    let reason = report
        .findings
        .iter()
        .map(|finding| finding.detail.as_str())
        .collect::<Vec<_>>()
        .join("\n\n");

    FindingItem {
        name: report.file_name().into(),
        path: report.path.clone().into(),
        level: if report.verdict == Verdict::Malicious {
            "PELIGROSO"
        } else {
            "SOSPECHOSO"
        }
        .into(),
        reason: reason.into(),
        rule_id: origin
            .map(|rule| rule.identifier.clone())
            .unwrap_or_default()
            .into(),
        rule_author: origin
            .map(|rule| rule.author.clone())
            .unwrap_or_default()
            .into(),
        rule_source: origin
            .map(|rule| rule.source.clone())
            .unwrap_or_default()
            .into(),
    }
}

fn push_finding(window: &MainWindow, finding: FindingItem) {
    if let Some(model) = window
        .get_findings()
        .as_any()
        .downcast_ref::<VecModel<FindingItem>>()
    {
        model.push(finding);
    }
}

fn remove_finding(window: &MainWindow, index: usize) {
    if let Some(model) = window
        .get_findings()
        .as_any()
        .downcast_ref::<VecModel<FindingItem>>()
        && index < model.row_count()
    {
        model.remove(index);
    }
}

fn remove_row(rows: &Mutex<Vec<RowTarget>>, index: usize) {
    if let Ok(mut rows) = rows.lock()
        && index < rows.len()
    {
        rows.remove(index);
    }
}

/// La ruta que el usuario eligió antes, o un aviso si todavía no hay ninguna.
fn chosen_path(window: &MainWindow, warning: &str) -> Option<PathBuf> {
    let path = PathBuf::from(window.get_file_path().to_string());
    if path.as_os_str().is_empty() {
        window.set_status(warning.into());
        return None;
    }
    Some(path)
}

fn file_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string())
}

fn detained_status(scanned: usize) -> String {
    if scanned == 1 {
        "Análisis detenido: 1 archivo mirado".to_string()
    } else {
        format!("Análisis detenido: {scanned} archivos mirados")
    }
}

/// La raíz del disco donde vive Windows.
///
/// shortcut: solo mira ese disco (C: por defecto); los demás habrá que recorrerlos
/// cuando el análisis de todo el equipo los tenga en cuenta.
fn system_drive() -> PathBuf {
    let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    PathBuf::from(format!("{drive}{}", std::path::MAIN_SEPARATOR))
}

/// Carga el paquete de base de datos que acompaña al ejecutable.
///
/// Si no está, o si no supera la verificación de firma, Rhino arranca igual y lo
/// dice en pantalla: escanea con las capas 1 y 3. Lo que nunca hace es caer en
/// silencio a «limpio» sin haber podido mirar.
fn load_database() -> Database {
    let Some(directory) = rhino_core::db::default_directory() else {
        return Database::empty();
    };

    match Database::load(&directory) {
        Ok(database) => database,
        Err(error) => {
            eprintln!("base de datos no cargada: {error}");
            Database::empty()
        }
    }
}

fn status_for(version: Option<&str>) -> String {
    match version {
        Some(version) => format!("Listo · base de datos {version}"),
        None => "Listo · sin base de datos".to_string(),
    }
}
