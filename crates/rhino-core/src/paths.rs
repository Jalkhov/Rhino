//! Dónde guarda Rhino lo suyo en el equipo del usuario.
//!
//! Nada de esto va junto al ejecutable: en Windows el programa vive en una carpeta
//! donde un usuario normal no puede escribir (`Archivos de programa`), así que los
//! datos van al perfil del usuario. Es la misma costumbre que sigue cualquier
//! programa instalado.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

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

/// Borra todo lo que Rhino guarda del usuario. El ejecutable no se toca.
/// Devuelve si había algo que borrar.
pub fn remove_user_data() -> io::Result<bool> {
    remove_tree(&data_directory()?)
}

/// Borra un árbol si existe; si no existe, no es un error. Así, pulsar dos veces
/// «Quitar Rhino» no falla la segunda.
fn remove_tree(directory: &Path) -> io::Result<bool> {
    match directory.try_exists() {
        Ok(false) => Ok(false),
        Ok(true) => {
            fs::remove_dir_all(directory)?;
            Ok(true)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tree_with_a_file_disappears() {
        let directory = std::env::temp_dir().join(format!(
            "rhino-datos-{}-desinstalar",
            std::process::id()
        ));
        fs::create_dir_all(directory.join("apartados")).expect("se crea el árbol");
        fs::write(directory.join("apartados/archivo.txt"), b"hola").expect("se escribe");

        assert!(remove_tree(&directory).expect("se borra"));
        assert!(!directory.exists());
        assert!(!remove_tree(&directory).expect("no falla"));
    }

    #[test]
    fn the_data_directory_lives_under_the_user_profile() {
        // En el equipo donde corren las pruebas hay perfil de usuario; si no lo
        // hubiera, la respuesta honesta es un error y no una ruta inventada.
        let directory = data_directory().expect("hay perfil de usuario");

        assert!(directory.ends_with("Rhino"), "{directory:?}");
    }
}
