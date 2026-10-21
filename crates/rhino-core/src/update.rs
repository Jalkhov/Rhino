//! Actualización de la base de datos desde un servidor.
//!
//! El reparto de responsabilidades es deliberado: este módulo **solo descarga**.
//! Quien decide si lo descargado vale es [`crate::db::Package`], que ya comprueba
//! la firma y el hash de cada archivo. Así el código con red no tiene autoridad
//! para aceptar nada, ni siquiera si el servidor miente.
//!
//! La URL base es configurable (`RHINO_DB_URL`) porque todavía no hay un servidor
//! público. El canal y la arquitectura se resuelven eligiendo la URL: el paquete
//! es neutral respecto a la arquitectura, y lo que se sirve por canal es la ruta.
//!
//! El reemplazo es por directorio completo: se descarga al lado
//! (`rhino-db.nuevo`), se verifica entero y solo entonces se intercambia con el
//! instalado (`rhino-db.anterior`). Nunca queda a medias un paquete a medio
//! escribir.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::db::{
    self, DB_PUBLIC_KEY, DbError, HASHES_FILE, MANIFEST_FILE, Package, RULES_FILE, SIGNATURE_FILE,
};

/// Variable de entorno con la URL base del canal.
pub const URL_ENV: &str = "RHINO_DB_URL";

/// De dónde se descarga la protección cuando no hay nada configurado.
///
/// Es una etiqueta fija y no `latest` a propósito: `latest` apunta a la release
/// más nueva de todas y el programa también publica, así que en cuanto saliera
/// una versión del ejecutable la descarga de la base se iría a un 404.
/// `db-latest` se sobrescribe cada semana con el paquete del día.
pub const DEFAULT_URL: &str = "https://github.com/Jalkhov/Rhino/releases/download/db-latest";

/// Tiempo máximo para la descarga completa.
const TIMEOUT: Duration = Duration::from_secs(600);

/// Tope por archivo descargado. El mayor es `rules.yarc`, de unos 9 MB.
const MAX_FILE: u64 = 64 * 1024 * 1024;

/// Lo que puede salir mal al actualizar.
#[derive(Debug)]
pub enum UpdateError {
    /// No se pudo descargar. Incluye la URL, que es lo que hace falta para
    /// entender el fallo.
    Network(String),
    /// Lo descargado no es un paquete válido: firma, hash o formato.
    Db(DbError),
    /// No se pudo escribir en disco.
    Io(io::Error),
}

impl fmt::Display for UpdateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdateError::Network(detail) => write!(formatter, "no se pudo descargar: {detail}"),
            UpdateError::Db(error) => error.fmt(formatter),
            UpdateError::Io(error) => write!(formatter, "no se pudo escribir el paquete: {error}"),
        }
    }
}

impl std::error::Error for UpdateError {}

impl From<DbError> for UpdateError {
    fn from(error: DbError) -> Self {
        UpdateError::Db(error)
    }
}

impl From<io::Error> for UpdateError {
    fn from(error: io::Error) -> Self {
        UpdateError::Io(error)
    }
}

/// Descarga el paquete de `base` sobre `destination` si no es el mismo que ya hay.
///
/// Devuelve la versión instalada, o `None` cuando ya estaba al día. Comprueba la
/// firma con la clave pública de Rhino.
pub fn update(base: &str, destination: impl AsRef<Path>) -> Result<Option<String>, UpdateError> {
    update_signed_by(base, destination, &DB_PUBLIC_KEY)
}

/// Igual que [`update`], pero con una clave concreta. Lo usan las pruebas.
pub fn update_signed_by(
    base: &str,
    destination: impl AsRef<Path>,
    key: &[u8; 32],
) -> Result<Option<String>, UpdateError> {
    let destination = destination.as_ref();
    let staging = sibling(destination, "nuevo");
    remove(&staging)?;
    fs::create_dir_all(&staging)?;

    let result = install(base, destination, &staging, key);

    if result.is_err() {
        // Un paquete a medias no se queda en el disco.
        remove(&staging).ok();
    }

    result
}

/// El trabajo de [`update_signed_by`], con el temporal ya preparado.
fn install(
    base: &str,
    destination: &Path,
    staging: &Path,
    key: &[u8; 32],
) -> Result<Option<String>, UpdateError> {
    let agent = agent();

    // El manifiesto y su firma son pequeños: con ellos se sabe la versión antes
    // de gastar la descarga de casi 9 MB de reglas.
    let manifest_bytes = fetch(&agent, base, MANIFEST_FILE)?;
    let signature = String::from_utf8_lossy(&fetch(&agent, base, SIGNATURE_FILE)?).to_string();
    let manifest = db::verify_manifest(&manifest_bytes, &signature, key)?;

    if db::installed_version(destination).as_deref() == Some(manifest.version.as_str()) {
        remove(staging)?;
        return Ok(None);
    }

    fs::write(staging.join(MANIFEST_FILE), &manifest_bytes)?;
    fs::write(staging.join(SIGNATURE_FILE), signature.as_bytes())?;
    for name in [RULES_FILE, HASHES_FILE] {
        fs::write(staging.join(name), fetch(&agent, base, name)?)?;
    }

    // Aquí no se decide nada nuevo: se reutiliza la verificación del paquete.
    let package = Package::open_signed_by(staging, key)?;
    package.verify_files()?;
    let version = package.version().to_string();

    swap(staging, destination)?;
    Ok(Some(version))
}

/// URL base configurada, si la hay.
pub fn configured_url() -> Option<String> {
    std::env::var(URL_ENV).ok().filter(|url| !url.is_empty())
}

/// Une la URL base con el nombre del archivo, sin duplicar la barra.
fn endpoint(base: &str, name: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), name)
}

/// Cliente HTTP. Incrusta los certificados raíz de Mozilla, así que no depende
/// del almacén de Windows: importa en equipos sin actualizar.
fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .user_agent(concat!("Rhino/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

fn fetch(agent: &ureq::Agent, base: &str, name: &str) -> Result<Vec<u8>, UpdateError> {
    let url = endpoint(base, name);
    let mut response = agent
        .get(&url)
        .call()
        .map_err(|error| UpdateError::Network(format!("{url}: {error}")))?;

    response
        .body_mut()
        .with_config()
        .limit(MAX_FILE)
        .read_to_vec()
        .map_err(|error| UpdateError::Network(format!("{url}: {error}")))
}

/// Reemplaza `destination` por `staging`, devolviéndolo a su sitio si el
/// intercambio falla. El paquete viejo solo desaparece cuando el nuevo ya está.
fn swap(staging: &Path, destination: &Path) -> Result<(), io::Error> {
    let previous = sibling(destination, "anterior");
    remove(&previous)?;

    if destination.exists() {
        fs::rename(destination, &previous)?;
    }

    if let Err(error) = fs::rename(staging, destination) {
        if previous.exists() {
            fs::rename(&previous, destination).ok();
        }
        return Err(error);
    }

    // El paquete nuevo ya está en su sitio; no poder borrar el viejo no es un
    // fallo de la actualización.
    remove(&previous).ok();
    Ok(())
}

/// Directorio temporal hermano del destino, para no escribirlo hasta el final.
fn sibling(directory: &Path, suffix: &str) -> PathBuf {
    let name = directory
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("rhino-db");
    directory.with_file_name(format!("{name}.{suffix}"))
}

fn remove(path: &Path) -> io::Result<()> {
    match fs::remove_dir_all(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{Counts, FORMAT, FileEntry, HashList, Manifest};
    use crate::hash::{sha256_hex, to_hex};
    use crate::rules::RuleSet;
    use ed25519_dalek::{Signer, SigningKey};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    /// Semilla de prueba: las claves de verdad no entran en las pruebas.
    const TEST_SEED: [u8; 32] = [9u8; 32];

    const OTHER_SEED: [u8; 32] = [8u8; 32];

    const TEST_RULE: &str = r#"rule prueba { strings: $a = "marcador" condition: $a }"#;

    fn public_key(seed: [u8; 32]) -> [u8; 32] {
        SigningKey::from_bytes(&seed).verifying_key().to_bytes()
    }

    /// Los cuatro archivos de un paquete firmado, como los serviría un canal.
    fn package_files(seed: [u8; 32], version: &str) -> Vec<(String, Vec<u8>)> {
        let rules = RuleSet::compile(&[TEST_RULE])
            .expect("regla de prueba")
            .to_compiled()
            .expect("reglas compiladas");
        let hashes = HashList::empty().to_binary();

        let manifest = Manifest {
            format: FORMAT,
            version: version.to_string(),
            created: "2026.10.18".to_string(),
            channel: "prueba".to_string(),
            source: "prueba".to_string(),
            counts: Counts {
                rules: 1,
                hashes: 0,
            },
            files: vec![
                FileEntry {
                    name: RULES_FILE.to_string(),
                    size: rules.len() as u64,
                    sha256: sha256_hex(&rules),
                },
                FileEntry {
                    name: HASHES_FILE.to_string(),
                    size: hashes.len() as u64,
                    sha256: sha256_hex(&hashes),
                },
            ],
        };

        let manifest_bytes = serde_json::to_vec(&manifest).expect("manifiesto");
        let signature = SigningKey::from_bytes(&seed).sign(&manifest_bytes);

        vec![
            (MANIFEST_FILE.to_string(), manifest_bytes),
            (
                SIGNATURE_FILE.to_string(),
                format!("{}\n", to_hex(&signature.to_bytes())).into_bytes(),
            ),
            (RULES_FILE.to_string(), rules),
            (HASHES_FILE.to_string(), hashes),
        ]
    }

    /// Servidor HTTP mínimo: solo atiende GET de los archivos que se le dan. El
    /// puerto lo elige el sistema, así que las pruebas pueden correr en paralelo.
    fn serve(files: Vec<(String, Vec<u8>)>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("puerto libre");
        let base = format!("http://{}", listener.local_addr().expect("dirección"));

        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };

                let mut request = Vec::new();
                let mut chunk = [0u8; 512];
                loop {
                    let read = stream.read(&mut chunk).unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }

                let path = String::from_utf8_lossy(&request)
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/")
                    .trim_start_matches('/')
                    .to_string();

                match files.iter().find(|(name, _)| *name == path) {
                    Some((_, body)) => {
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        stream.write_all(header.as_bytes()).ok();
                        stream.write_all(body).ok();
                    }
                    None => {
                        stream
                            .write_all(
                                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .ok();
                    }
                }
            }
        });

        base
    }

    /// Destino limpio para una prueba: cada una usa un nombre distinto.
    fn fresh(name: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("rhino-update-{}-{name}", std::process::id()));
        fs::remove_dir_all(&directory).ok();
        directory
    }

    #[test]
    fn endpoint_does_not_double_the_slash() {
        assert_eq!(
            endpoint("https://ejemplo.com/db/", MANIFEST_FILE),
            "https://ejemplo.com/db/manifest.json"
        );
        assert_eq!(
            endpoint("https://ejemplo.com/db", MANIFEST_FILE),
            "https://ejemplo.com/db/manifest.json"
        );
    }

    #[test]
    fn swap_replaces_the_installed_package() {
        let destination = fresh("swap");
        fs::create_dir_all(&destination).unwrap();
        fs::write(destination.join("viejo"), b"viejo").unwrap();

        let staging = sibling(&destination, "nuevo");
        fs::create_dir_all(&staging).unwrap();
        fs::write(staging.join("nuevo"), b"nuevo").unwrap();

        swap(&staging, &destination).unwrap();

        assert!(destination.join("nuevo").exists());
        assert!(!destination.join("viejo").exists());
        assert!(!staging.exists());
        assert!(!sibling(&destination, "anterior").exists());

        // Y también cuando no hay nada instalado todavía.
        let empty = fresh("swap-nuevo");
        let staging = sibling(&empty, "nuevo");
        fs::create_dir_all(&staging).unwrap();
        swap(&staging, &empty).unwrap();
        assert!(empty.exists());
    }

    #[test]
    fn an_unreachable_server_is_an_error() {
        let destination = fresh("sin-servidor");
        // El puerto 9 no tiene a nadie escuchando: la conexión se rechaza.
        let error = update("http://127.0.0.1:9/", &destination).unwrap_err();

        assert!(matches!(error, UpdateError::Network(_)));
        assert!(!destination.exists());
    }

    #[test]
    fn a_signed_package_is_downloaded_and_installed() {
        let base = serve(package_files(TEST_SEED, "2026.10.19"));
        let destination = fresh("instalado");

        let version = update_signed_by(&base, &destination, &public_key(TEST_SEED)).unwrap();

        assert_eq!(version.as_deref(), Some("2026.10.19"));
        assert_eq!(
            db::installed_version(&destination).as_deref(),
            Some("2026.10.19")
        );
        assert!(!sibling(&destination, "nuevo").exists());

        // La segunda vez ya no hay nada que bajar.
        assert_eq!(
            update_signed_by(&base, &destination, &public_key(TEST_SEED)).unwrap(),
            None
        );
    }

    #[test]
    fn a_package_signed_by_another_key_is_rejected() {
        let base = serve(package_files(TEST_SEED, "2026.10.19"));
        let destination = fresh("ajeno");

        let error = update_signed_by(&base, &destination, &public_key(OTHER_SEED)).unwrap_err();

        assert!(matches!(error, UpdateError::Db(DbError::Signature)));
        assert!(!destination.exists());
        assert!(!sibling(&destination, "nuevo").exists());
    }

    #[test]
    fn a_file_changed_on_the_way_is_rejected() {
        let mut files = package_files(TEST_SEED, "2026.10.19");
        for (name, body) in files.iter_mut() {
            if name == RULES_FILE {
                body.extend_from_slice(b"alterado por el camino");
            }
        }
        let base = serve(files);
        let destination = fresh("alterado");

        let error = update_signed_by(&base, &destination, &public_key(TEST_SEED)).unwrap_err();

        assert!(matches!(error, UpdateError::Db(DbError::Corrupt(_))));
        assert!(!destination.exists());
    }

    #[test]
    fn a_missing_file_is_an_error() {
        let mut files = package_files(TEST_SEED, "2026.10.19");
        files.retain(|(name, _)| name != RULES_FILE);
        let base = serve(files);
        let destination = fresh("incompleto");

        let error = update_signed_by(&base, &destination, &public_key(TEST_SEED)).unwrap_err();

        assert!(matches!(error, UpdateError::Network(_)));
        assert!(!destination.exists());
    }
}
