#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use slint::ComponentHandle;

slint::include_modules!();

fn main() -> Result<(), slint::PlatformError> {
    let window = MainWindow::new()?;
    window.set_version(rhino_core::VERSION.into());
    window.run()
}
