#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::Arc;

use slint::ComponentHandle;

use rhino_core::Database;

slint::include_modules!();

fn main() -> Result<(), slint::PlatformError> {
    let window = MainWindow::new()?;
    window.set_version(rhino_core::VERSION.into());

    let database = Arc::new(load_database());
    window.set_status(status_for(database.version()).into());

    let weak_window = window.as_weak();
    window.on_scan_requested(move || {
        let Some(window) = weak_window.upgrade() else {
            return;
        };

        let path = PathBuf::from(window.get_file_path().to_string());
        if path.as_os_str().is_empty() {
            window.set_status("Escribe la ruta de un archivo".into());
            return;
        }

        window.set_scanning(true);
        window.set_status(format!("Analizando {}…", path.display()).into());

        // El escaneo corre fuera del hilo de la interfaz: la ventana nunca se congela.
        let weak_window = window.as_weak();
        let database = Arc::clone(&database);
        std::thread::spawn(move || {
            let status = match rhino_core::scan_file(&path, &database) {
                Ok(report) => report.summary(),
                Err(error) => format!("No se pudo analizar: {error}"),
            };
            let _ = weak_window.upgrade_in_event_loop(move |window| {
                window.set_scanning(false);
                window.set_status(status.into());
            });
        });
    });

    window.run()
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
