//! Dónde guarda Rhino lo suyo en el equipo del usuario.
//!
//! Nada de esto va junto al ejecutable: en Windows el programa vive en una carpeta
//! donde un usuario normal no puede escribir (`Archivos de programa`), así que los
//! datos van al perfil del usuario. Es la misma costumbre que sigue cualquier
//! programa instalado.

use std::io;
use std::path::PathBuf;

/// Carpeta de datos de Rhino para este usuario: `%LOCALAPPDATA%\Rhino` en Windows,
/// `~/.local/share/Rhino` (o `$XDG_DATA_HOME/Rhino`) en el resto.
pub fn data_directory() -> io::Result<PathBuf> {
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);

    #[cfg(not(windows))]
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")));

    base.map(|base| base.join("Rhino")).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "este equipo no dice dónde guardar los datos del usuario",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_data_directory_lives_under_the_user_profile() {
        // En el equipo donde corren las pruebas hay perfil de usuario; si no lo
        // hubiera, la respuesta honesta es un error y no una ruta inventada.
        let directory = data_directory().expect("hay perfil de usuario");

        assert!(directory.ends_with("Rhino"), "{directory:?}");
    }
}
