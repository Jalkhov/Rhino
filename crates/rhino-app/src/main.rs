#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::Arc;

use slint::ComponentHandle;

slint::include_modules!();

fn main() -> Result<(), slint::PlatformError> {
    let window = MainWindow::new()?;
    window.set_version(rhino_core::VERSION.into());

    // Todavía no hay paquete de base de datos que cargar (ver "Paquete de base de
    // datos" en el README); cuando exista, aquí se leerán `rules.yarc` y `hashes.bin`.
    let rules = Arc::new(rhino_core::RuleSet::empty());

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
        let rules = Arc::clone(&rules);
        std::thread::spawn(move || {
            let status = match rhino_core::scan_file(&path, &rules) {
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
