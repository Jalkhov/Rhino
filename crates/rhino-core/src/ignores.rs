//! Archivos que el usuario ha decidido ignorar.
//!
//! Se guarda el SHA-256, no la ruta: si el archivo cambia, vuelve a analizarse. Ignorar
//! «este contenido» es lo que el usuario cree que ha hecho, y es lo que un antivirus puede
//! prometer sin dejar un agujero: ignorar una ruta permitiría sustituir el archivo y seguir
//! pasando por debajo del radar.
//!
//! La ruta se guarda solo para poder enseñar la lista en Ajustes con un nombre legible.
//!
//! El archivo se reescribe entero (la lista es pequeña) y siempre por relevo: primero
//! `<archivo>.nuevo` y después el renombrado, así un corte de corriente no deja media lista.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Formato del archivo en disco.
pub const LIST_FORMAT: u32 = 1;

const FILE: &str = "ignorados.json";

/// Un archivo que el usuario ha decidido no volver a ver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IgnoredFile {
    pub format: u32,
    /// Ruta de donde se ignoró, solo para enseñarla.
    pub path: String,
    pub sha256: String,
    /// Segundos UNIX.
    pub when: u64,
}

/// Lo que hay en disco. Es un objeto y no una lista para poder crecer sin romper lo escrito.
#[derive(Debug, Serialize, Deserialize)]
struct Stored {
    format: u32,
    items: Vec<IgnoredFile>,
}

/// La lista de ignorados.
pub struct Ignored {
    file: PathBuf,
}

impl Ignored {
    /// Abre la lista del perfil del usuario, creando la carpeta si hace falta.
    pub fn open() -> io::Result<Self> {
        let directory = crate::paths::data_directory()?;
        fs::create_dir_all(&directory)?;
        Ok(Self::at(directory.join(FILE)))
    }

    /// Abre la lista en una ruta concreta (pruebas).
    pub fn at(file: impl Into<PathBuf>) -> Self {
        Self { file: file.into() }
    }

    pub fn file(&self) -> &Path {
        &self.file
    }

    /// Añade un archivo y devuelve la ficha guardada. Si ya estaba, actualiza la ruta y la
    /// fecha en vez de duplicarla.
    pub fn add(
        &self,
        path: impl AsRef<Path>,
        sha256: &str,
        when: u64,
    ) -> io::Result<IgnoredFile> {
        let entry = IgnoredFile {
            format: LIST_FORMAT,
            path: path.as_ref().to_string_lossy().into_owned(),
            sha256: sha256.to_ascii_lowercase(),
            when,
        };

        let mut items = self.read()?;
        items.insert(entry.sha256.clone(), entry.clone());
        self.write(&items)?;

        Ok(entry)
    }

    /// Todo lo ignorado, lo más reciente primero.
    pub fn list(&self) -> io::Result<Vec<IgnoredFile>> {
        let mut items: Vec<IgnoredFile> = self.read()?.into_values().collect();
        items.sort_by_key(|entry| std::cmp::Reverse(entry.when));
        Ok(items)
    }

    /// ¿Está ya ignorado este contenido?
    pub fn contains(&self, sha256: &str) -> io::Result<bool> {
        Ok(self
            .read()?
            .contains_key(&sha256.to_ascii_lowercase()))
    }

    /// Deja de ignorarlo. Devuelve si estaba.
    pub fn remove(&self, sha256: &str) -> io::Result<bool> {
        let mut items = self.read()?;
        let was_there = items.remove(&sha256.to_ascii_lowercase()).is_some();
        if was_there {
            self.write(&items)?;
        }
        Ok(was_there)
    }

    /// Vacía la lista. Borrar lo que no está no es un error.
    pub fn clear(&self) -> io::Result<()> {
        match fs::remove_file(&self.file) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Lee la lista. Un archivo que no está es una lista vacía; uno ilegible también: se
    /// pierden las excepciones (vuelven a analizarse), que es el fallo seguro, antes que
    /// dejar la app sin arrancar.
    fn read(&self) -> io::Result<BTreeMap<String, IgnoredFile>> {
        let text = match fs::read_to_string(&self.file) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(error) => return Err(error),
        };

        let stored: Stored = match serde_json::from_str(&text) {
            Ok(stored) => stored,
            Err(_) => return Ok(BTreeMap::new()),
        };

        Ok(stored
            .items
            .into_iter()
            .map(|entry| (entry.sha256.clone(), entry))
            .collect())
    }

    fn write(&self, items: &BTreeMap<String, IgnoredFile>) -> io::Result<()> {
        let stored = Stored {
            format: LIST_FORMAT,
            items: items.values().cloned().collect(),
        };
        let text = serde_json::to_string_pretty(&stored)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

        if let Some(parent) = self.file.parent() {
            fs::create_dir_all(parent)?;
        }

        let staging = self.file.with_extension("json.nuevo");
        fs::write(&staging, text)?;
        fs::rename(&staging, &self.file)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(name: &str) -> Ignored {
        let directory = std::env::temp_dir().join(format!(
            "rhino-ignorados-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        Ignored::at(directory.join(FILE))
    }

    const FIRST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECOND: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn adding_saves_it_and_contains_finds_it() {
        let list = list("guarda");
        assert!(!list.contains(FIRST).unwrap());

        list.add("C:\\Descargas\\instalador.exe", FIRST, 100).unwrap();

        assert!(list.contains(FIRST).unwrap());
        assert_eq!(list.list().unwrap().len(), 1);
    }

    #[test]
    fn the_hash_is_matched_regardless_of_case() {
        let list = list("mayusculas");
        list.add("C:\\a.exe", FIRST, 100).unwrap();

        assert!(list.contains(&FIRST.to_ascii_uppercase()).unwrap());
        assert!(list.remove(&FIRST.to_ascii_uppercase()).unwrap());
    }

    #[test]
    fn adding_the_same_content_twice_does_not_duplicate_it() {
        let list = list("repetido");
        list.add("C:\\primero.exe", FIRST, 100).unwrap();
        list.add("C:\\segundo.exe", FIRST, 200).unwrap();

        let items = list.list().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].path, "C:\\segundo.exe");
        assert_eq!(items[0].when, 200);
    }

    #[test]
    fn the_most_recent_comes_first() {
        let list = list("orden");
        list.add("C:\\viejo.exe", FIRST, 100).unwrap();
        list.add("C:\\nuevo.exe", SECOND, 200).unwrap();

        let items = list.list().unwrap();
        assert_eq!(items[0].sha256, SECOND);
        assert_eq!(items[1].sha256, FIRST);
    }

    #[test]
    fn removing_says_whether_it_was_there() {
        let list = list("quitar");
        list.add("C:\\a.exe", FIRST, 100).unwrap();

        assert!(list.remove(FIRST).unwrap());
        assert!(!list.remove(FIRST).unwrap());
        assert!(list.list().unwrap().is_empty());
    }

    #[test]
    fn clearing_twice_is_not_an_error() {
        let list = list("vaciar");
        list.add("C:\\a.exe", FIRST, 100).unwrap();

        list.clear().unwrap();
        list.clear().unwrap();
        assert!(list.list().unwrap().is_empty());
    }

    #[test]
    fn a_list_that_does_not_exist_is_empty() {
        let list = list("inexistente");
        assert!(list.list().unwrap().is_empty());
        assert!(!list.contains(FIRST).unwrap());
    }

    #[test]
    fn a_broken_list_reads_as_empty_instead_of_failing() {
        let list = list("roto");
        if let Some(parent) = list.file().parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(list.file(), "{ esto no es json").unwrap();

        assert!(list.list().unwrap().is_empty());

        // Y se puede volver a escribir encima.
        list.add("C:\\a.exe", FIRST, 100).unwrap();
        assert_eq!(list.list().unwrap().len(), 1);
    }

    #[test]
    fn odd_paths_survive_the_round_trip() {
        let list = list("rutas");
        let odd = "C:\\Usuarios\\Ana\\«raro» \\\"x\\\".exe";
        list.add(odd, FIRST, 100).unwrap();

        assert_eq!(list.list().unwrap()[0].path, odd);
    }
}
