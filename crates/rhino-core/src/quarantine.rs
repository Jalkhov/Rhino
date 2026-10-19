//! Poner a salvo lo que resulta sospechoso: sacarlo de su sitio y dejarlo donde no
//! pueda hacer nada.
//!
//! Lo apartado se guarda como datos, con extensión `.bin`: Windows no asocia esa
//! extensión a nada, así que nadie puede ejecutar por costumbre lo que hay aquí
//! dentro. El nombre y la ruta de origen viven en una ficha aparte, en `.json`, que
//! es lo único que hace falta para devolverlo a su sitio.
//!
//! Ni una operación de este módulo borra el archivo sin que se lo pidan: apartar es
//! mover, y borrar es borrar.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::hash::is_sha256_hex;
use crate::time;
use crate::paths;

/// Versión del formato de la ficha. Un cambio que rompa la lectura se nota aquí.
pub const ENTRY_FORMAT: u32 = 1;

/// Carpeta dentro de los datos del usuario.
const DIRECTORY: &str = "apartados";
const PAYLOAD_EXTENSION: &str = "bin";
const ENTRY_EXTENSION: &str = "json";

/// Lo que se sabe de un archivo apartado. El `sha256` es también su identificador:
/// dos archivos con el mismo contenido son el mismo archivo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredFile {
    pub format: u32,
    pub name: String,
    /// Ruta completa donde estaba, para poder devolverlo.
    pub origin: String,
    pub size: u64,
    pub sha256: String,
    /// Segundos desde la época, en UTC.
    pub when: u64,
}

#[derive(Debug)]
pub enum QuarantineError {
    Io(io::Error),
    /// Ya no está apartado: o se recuperó, o se borró, o la ficha se perdió.
    Missing(String),
    /// Hay que decidir qué hacer con lo que ya ocupa la ruta de origen.
    Occupied(String),
    /// Un identificador que no es un SHA-256 no se acepta nunca: se usa para
    /// componer nombres de archivo.
    Invalid(String),
}

impl std::fmt::Display for QuarantineError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Missing(sha256) => {
                write!(formatter, "el archivo {sha256} ya no está apartado")
            }
            Self::Occupied(path) => {
                write!(formatter, "ya hay un archivo en {path}")
            }
            Self::Invalid(sha256) => {
                write!(formatter, "{sha256} no es un identificador válido")
            }
        }
    }
}

impl std::error::Error for QuarantineError {}

impl From<io::Error> for QuarantineError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// La carpeta donde se aparta. Todas las operaciones pasan por aquí.
pub struct Quarantine {
    directory: PathBuf,
}

impl Quarantine {
    /// Abre la carpeta del usuario, creándola si hace falta.
    pub fn open() -> Result<Self, QuarantineError> {
        let directory = paths::data_directory()?.join(DIRECTORY);
        fs::create_dir_all(&directory)?;

        Ok(Self { directory })
    }

    /// Abre una carpeta concreta. Para pruebas y para el día que el usuario pueda
    /// elegir dónde se aparta.
    pub fn at(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Aparta un archivo: lo saca de su sitio y lo deja aquí.
    ///
    /// El `sha256` lo calcula quien llama (el análisis ya lo tiene hecho). No se
    /// vuelve a leer el archivo para comprobarlo: sería leer dos veces cada hallazgo.
    pub fn store(&self, path: impl AsRef<Path>, sha256: &str) -> Result<StoredFile, QuarantineError> {
        self.check_id(sha256)?;
        fs::create_dir_all(&self.directory)?;

        let origin = path.as_ref();
        let metadata = fs::metadata(origin)?;

        if !metadata.is_file() {
            return Err(QuarantineError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "solo se puede apartar un archivo",
            )));
        }

        let entry = StoredFile {
            format: ENTRY_FORMAT,
            name: origin
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
            origin: origin.to_string_lossy().into_owned(),
            size: metadata.len(),
            sha256: sha256.to_string(),
            when: time::now_unix(),
        };

        let payload = self.payload_path(sha256);
        move_file(origin, &payload)?;

        if let Err(error) = self.write_entry(&entry) {
            // Sin ficha no hay forma de saber de dónde salió: mejor dejarlo donde
            // estaba que dejar un archivo del que no se sabe nada.
            let _ = move_file(&payload, origin);
            return Err(error);
        }

        Ok(entry)
    }

    /// Lo que hay apartado, del más reciente al más antiguo.
    pub fn list(&self) -> Result<Vec<StoredFile>, QuarantineError> {
        let mut entries = Vec::new();

        for item in fs::read_dir(&self.directory)? {
            let path = item?.path();

            if path.extension().and_then(|extension| extension.to_str()) != Some(ENTRY_EXTENSION) {
                continue;
            }

            // Una ficha ilegible no puede tumbar la pantalla: se salta. El archivo
            // sigue ahí y se puede recuperar a mano.
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            let Ok(entry) = serde_json::from_str::<StoredFile>(&text) else {
                continue;
            };

            entries.push(entry);
        }

        entries.sort_by_key(|entry| std::cmp::Reverse(entry.when));

        Ok(entries)
    }

    /// Lo apartado vuelve a donde estaba. No pisa nada: si hay algo en esa ruta, lo
    /// dice y no toca nada.
    pub fn restore(&self, sha256: &str) -> Result<PathBuf, QuarantineError> {
        self.check_id(sha256)?;

        let entry = self.read_entry(sha256)?;
        let origin = PathBuf::from(&entry.origin);

        if origin.as_os_str().is_empty() {
            return Err(QuarantineError::Invalid(sha256.to_string()));
        }

        if origin.exists() {
            return Err(QuarantineError::Occupied(entry.origin));
        }

        if let Some(parent) = origin.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }

        move_file(&self.payload_path(sha256), &origin)?;
        let _ = fs::remove_file(self.entry_path(sha256));

        Ok(origin)
    }

    /// Borra lo apartado, y con ello el archivo. No hay vuelta atrás.
    pub fn erase(&self, sha256: &str) -> Result<(), QuarantineError> {
        self.check_id(sha256)?;
        self.read_entry(sha256)?;

        fs::remove_file(self.payload_path(sha256))?;
        let _ = fs::remove_file(self.entry_path(sha256));

        Ok(())
    }

    fn payload_path(&self, sha256: &str) -> PathBuf {
        self.directory.join(format!("{sha256}.{PAYLOAD_EXTENSION}"))
    }

    fn entry_path(&self, sha256: &str) -> PathBuf {
        self.directory.join(format!("{sha256}.{ENTRY_EXTENSION}"))
    }

    fn check_id(&self, sha256: &str) -> Result<(), QuarantineError> {
        if is_sha256_hex(sha256) {
            Ok(())
        } else {
            Err(QuarantineError::Invalid(sha256.to_string()))
        }
    }

    fn write_entry(&self, entry: &StoredFile) -> Result<(), QuarantineError> {
        let text = serde_json::to_string(entry).map_err(|error| {
            QuarantineError::Io(io::Error::new(io::ErrorKind::InvalidData, error))
        })?;
        fs::write(self.entry_path(&entry.sha256), text)?;

        Ok(())
    }

    fn read_entry(&self, sha256: &str) -> Result<StoredFile, QuarantineError> {
        let text = match fs::read_to_string(self.entry_path(sha256)) {
            Ok(text) => text,
            // Que no esté la ficha no es un fallo del programa: es que ya no está
            // apartado, y eso la pantalla tiene que saber decirlo.
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(QuarantineError::Missing(sha256.to_string()));
            }
            Err(error) => return Err(QuarantineError::Io(error)),
        };

        serde_json::from_str(&text).map_err(|_| QuarantineError::Missing(sha256.to_string()))
    }
}

/// Mueve un archivo aunque esté en otra unidad: `rename` solo funciona dentro del
/// mismo sistema de archivos, y lo que se aparta puede estar en cualquier disco.
fn move_file(from: &Path, to: &Path) -> io::Result<()> {
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::CrossesDevices => {
            fs::copy(from, to)?;
            fs::remove_file(from)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256_hex;

    #[test]
    fn storing_takes_the_file_away_and_leaves_a_note() {
        let place = temp_directory("apartar");
        let origin = place.join("instalador.exe");
        let data = b"esto no es un programa, pero da igual";
        fs::write(&origin, data).expect("escribir el original");
        let quarantine = Quarantine::at(place.join("apartados"));

        let entry = quarantine
            .store(&origin, &sha256_hex(data))
            .expect("apartar");

        assert_eq!(entry.name, "instalador.exe");
        assert_eq!(entry.origin, origin.to_string_lossy());
        assert_eq!(entry.size, data.len() as u64);
        assert!(!origin.exists(), "ya no está en su sitio");
        // El contenido se guarda sin extensión: Windows no lo ejecuta por costumbre.
        let payload = quarantine.directory().join(format!("{}.bin", entry.sha256));
        assert_eq!(fs::read(&payload).expect("leer lo apartado"), data);

        let _ = fs::remove_dir_all(place);
    }

    #[test]
    fn the_most_recent_goes_first() {
        let place = temp_directory("orden");
        let quarantine = Quarantine::at(place.join("apartados"));
        fs::create_dir_all(quarantine.directory()).expect("crear la carpeta");

        let older = b"primero";
        let newer = b"segundo";
        for (name, data) in [("uno.exe", older), ("dos.exe", newer)] {
            let origin = place.join(name);
            fs::write(&origin, data).expect("escribir el original");
            quarantine
                .store(&origin, &sha256_hex(data))
                .expect("apartar");
        }

        let listed = quarantine.list().expect("listar");

        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].name, "dos.exe");
        assert_eq!(listed[1].name, "uno.exe");

        let _ = fs::remove_dir_all(place);
    }

    #[test]
    fn restoring_puts_it_back_where_it_was() {
        let place = temp_directory("recuperar");
        let origin = place.join("crack_v3.zip");
        let data = b"contenido";
        fs::write(&origin, data).expect("escribir el original");
        let quarantine = Quarantine::at(place.join("apartados"));
        let entry = quarantine
            .store(&origin, &sha256_hex(data))
            .expect("apartar");

        let returned = quarantine.restore(&entry.sha256).expect("recuperar");

        assert_eq!(returned, origin);
        assert_eq!(fs::read(&origin).expect("leer el recuperado"), data);
        assert!(quarantine.list().expect("listar").is_empty());

        let _ = fs::remove_dir_all(place);
    }

    #[test]
    fn restoring_refuses_to_overwrite_whatever_is_there_now() {
        let place = temp_directory("ocupado");
        let origin = place.join("instalador.exe");
        let data = b"malo";
        fs::write(&origin, data).expect("escribir el original");
        let quarantine = Quarantine::at(place.join("apartados"));
        let entry = quarantine
            .store(&origin, &sha256_hex(data))
            .expect("apartar");

        fs::write(&origin, b"otra cosa").expect("volver a crear el original");

        match quarantine.restore(&entry.sha256) {
            Err(QuarantineError::Occupied(path)) => assert_eq!(path, origin.to_string_lossy()),
            other => panic!("se esperaba Occupied y llegó {other:?}"),
        }
        assert_eq!(fs::read(&origin).expect("leer el de ahora"), b"otra cosa");

        let _ = fs::remove_dir_all(place);
    }

    #[test]
    fn erasing_leaves_nothing_behind() {
        let place = temp_directory("borrar");
        let origin = place.join("instalador.exe");
        let data = b"malo";
        fs::write(&origin, data).expect("escribir el original");
        let quarantine = Quarantine::at(place.join("apartados"));
        let entry = quarantine
            .store(&origin, &sha256_hex(data))
            .expect("apartar");

        quarantine.erase(&entry.sha256).expect("borrar");

        assert!(quarantine.list().expect("listar").is_empty());
        assert!(!quarantine.directory().join(format!("{}.bin", entry.sha256)).exists());

        let _ = fs::remove_dir_all(place);
    }

    #[test]
    fn an_identifier_that_is_not_a_sha256_is_rejected() {
        let place = temp_directory("identificador");
        let quarantine = Quarantine::at(place.join("apartados"));
        fs::create_dir_all(quarantine.directory()).expect("crear la carpeta");

        for identifier in ["../../algo", "no-es-un-hash", ""] {
            assert!(
                matches!(
                    quarantine.erase(identifier),
                    Err(QuarantineError::Invalid(_))
                ),
                "{identifier} no puede usarse como nombre de archivo"
            );
        }

        let _ = fs::remove_dir_all(place);
    }

    #[test]
    fn what_is_not_there_cannot_be_recovered() {
        let place = temp_directory("ausente");
        let quarantine = Quarantine::at(place.join("apartados"));
        fs::create_dir_all(quarantine.directory()).expect("crear la carpeta");

        let ausente = sha256_hex(b"nunca se aparto");

        assert!(matches!(
            quarantine.restore(&ausente),
            Err(QuarantineError::Missing(_))
        ));

        let _ = fs::remove_dir_all(place);
    }

    fn temp_directory(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("rhino-apartados-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("crear el directorio de prueba");

        path
    }
}
