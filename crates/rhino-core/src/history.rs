//! Historial: una línea por análisis, en el orden en que se hicieron.
//!
//! Se guarda como JSON por línea porque añadir al final nunca reescribe lo que ya
//! había: si el equipo se apaga a mitad de escritura, lo único que se pierde es la
//! última línea. Una línea ilegible se salta al leer, así que un historial a medias
//! sigue siendo un historial.
//!
//! `shortcut: solo se añade, nunca se poda. Un análisis al día son unos 20 KB al año;
//! si algún día se analiza el equipo cada hora, hay que podar al añadir.`
//!
//! Lo que se apunta no es de nadie más: el historial no sale del equipo (`PRODUCT.md`).

use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::paths;

/// Versión del formato de cada línea. Un cambio que rompa la lectura se nota aquí.
pub const RUN_FORMAT: u32 = 1;

/// Carpeta dentro de los datos del usuario.
const DIRECTORY: &str = "historial.jsonl";

/// Un análisis terminado.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRun {
    pub format: u32,
    /// Segundos desde la época, en UTC.
    pub when: u64,
    /// Qué se analizó, en palabras: «Todo el equipo», una carpeta, un archivo.
    pub scope: String,
    /// Cuántos archivos se miraron.
    pub files: u64,
    /// Cuántos dieron algo: es lo único que le importa a quien lee el historial.
    pub findings: u64,
}

/// El archivo del historial.
pub struct History {
    file: PathBuf,
}

impl History {
    /// Abre el historial del usuario, creando la carpeta si hace falta. El archivo,
    /// en cambio, no se crea hasta que hay algo que apuntar.
    pub fn open() -> io::Result<Self> {
        let directory = paths::data_directory()?;
        fs::create_dir_all(&directory)?;

        Ok(Self {
            file: directory.join(DIRECTORY),
        })
    }

    /// Apunta en un archivo concreto. Para pruebas.
    pub fn at(file: impl Into<PathBuf>) -> Self {
        Self { file: file.into() }
    }

    pub fn file(&self) -> &Path {
        &self.file
    }

    /// Añade un análisis al final.
    pub fn append(&self, run: &ScanRun) -> io::Result<()> {
        let mut line = serde_json::to_string(run)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        line.push('\n');

        // Si el equipo se apagó a mitad de una escritura, el archivo queda sin salto
        // de línea final. Sin cerrar esa línea, la nuestra se pegaría a la rota y se
        // perderían las dos.
        if ends_without_newline(&self.file)? {
            line.insert(0, '\n');
        }

        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file)?;
        file.write_all(line.as_bytes())
    }

    /// Los últimos `limit` análisis, del más reciente al más antiguo. Un historial
    /// que todavía no existe es un historial vacío, no un error.
    pub fn recent(&self, limit: usize) -> io::Result<Vec<ScanRun>> {
        let text = match fs::read_to_string(&self.file) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };

        let mut runs: Vec<ScanRun> = text
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        runs.reverse();
        runs.truncate(limit);

        Ok(runs)
    }

    /// Borra el historial entero.
    pub fn clear(&self) -> io::Result<()> {
        match fs::remove_file(&self.file) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// ¿El archivo termina sin salto de línea? Un archivo que no existe o está vacío
/// responde que no.
fn ends_without_newline(file: &Path) -> io::Result<bool> {
    let mut handle = match fs::File::open(file) {
        Ok(handle) => handle,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };

    if handle.metadata()?.len() == 0 {
        return Ok(false);
    }

    handle.seek(SeekFrom::End(-1))?;
    let mut last = [0u8; 1];
    handle.read_exact(&mut last)?;

    Ok(last[0] != b'\n')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(when: u64, scope: &str, files: u64, findings: u64) -> ScanRun {
        ScanRun {
            format: RUN_FORMAT,
            when,
            scope: scope.to_string(),
            files,
            findings,
        }
    }

    #[test]
    fn the_last_one_written_is_the_first_one_read() {
        let history = History::at(temp_file("orden"));
        history
            .append(&run(100, "Todo el equipo", 18_204, 0))
            .expect("apuntar el primero");
        history
            .append(&run(200, "Tu carpeta de descargas", 312, 2))
            .expect("apuntar el segundo");

        let recent = history.recent(10).expect("leer");

        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].when, 200);
        assert_eq!(recent[0].findings, 2);
        assert_eq!(recent[1].when, 100);
    }

    #[test]
    fn only_the_asked_for_are_returned() {
        let history = History::at(temp_file("limite"));
        for when in 0..5 {
            history
                .append(&run(when, "Todo el equipo", 10, 0))
                .expect("apuntar");
        }

        let recent = history.recent(2).expect("leer");

        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].when, 4);
        assert_eq!(recent[1].when, 3);
    }

    #[test]
    fn a_line_that_cannot_be_read_does_not_hide_the_rest() {
        let file = temp_file("rota");
        let history = History::at(file.clone());
        history.append(&run(100, "Todo el equipo", 10, 0)).expect("apuntar");
        // Como si el equipo se hubiera apagado a mitad de escritura.
        fs::OpenOptions::new()
            .append(true)
            .open(&file)
            .expect("abrir")
            .write_all(b"{\"format\":1,\"whe")
            .expect("escribir a medias");
        history.append(&run(300, "Todo el equipo", 10, 1)).expect("apuntar");

        let recent = history.recent(10).expect("leer");

        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].when, 300);
        assert_eq!(recent[1].when, 100);
    }

    #[test]
    fn a_history_that_does_not_exist_yet_is_empty() {
        let history = History::at(temp_file("inexistente"));

        assert!(history.recent(10).expect("leer").is_empty());
    }

    #[test]
    fn clearing_leaves_it_empty_and_is_not_an_error_twice() {
        let history = History::at(temp_file("vaciar"));
        history.append(&run(100, "Todo el equipo", 10, 0)).expect("apuntar");

        history.clear().expect("vaciar");
        history.clear().expect("vaciar otra vez");

        assert!(history.recent(10).expect("leer").is_empty());
    }

    fn temp_file(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("rhino-historial-{}-{name}.jsonl", std::process::id()));
        let _ = fs::remove_file(&path);

        path
    }
}
