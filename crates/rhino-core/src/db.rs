//! Paquete de base de datos firmado.
//!
//! Un paquete es un directorio `rhino-db-AAAA.MM.DD/` con cuatro archivos:
//!
//! - `manifest.json`: versión, canal, recuentos y el SHA-256 de cada archivo.
//! - `manifest.sig`: firma Ed25519 del manifiesto, en hexadecimal.
//! - `rules.yarc`: reglas YARA-X ya compiladas (capa 2).
//! - `hashes.bin`: hashes conocido-malo ordenados, 32 bytes por entrada (capa 1).
//!
//! La firma es la frontera de seguridad del proyecto: sin ella, quien pueda
//! interceptar una actualización apaga el antivirus. La clave privada vive en
//! los secretos de la CI y nunca en el repositorio. Ver "Paquete de base de
//! datos" en el README.
//!
//! El paquete es neutral respecto a la arquitectura: los mismos archivos sirven
//! para 32 y 64 bits. Lo que se sirve por arquitectura es el canal.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::hash::{decode_hex, is_sha256_hex, sha256_hex};
use crate::rules::RuleSet;

/// Clave pública que firma los paquetes de base de datos.
///
/// Se genera con `rhino-db keygen` y se publica aquí. La privada es el activo
/// más sensible del proyecto: quien la tenga puede emitir un paquete que apague
/// Rhino en todos los equipos.
pub const DB_PUBLIC_KEY: [u8; 32] = [0u8; 32];

/// Bytes por entrada de la lista de hashes.
pub const HASH_BYTES: usize = 32;

/// Versión del formato del manifiesto que entiende este Rhino.
pub const FORMAT: u32 = 1;

/// Nombre de las reglas compiladas dentro del paquete.
pub const RULES_FILE: &str = "rules.yarc";

/// Nombre de la lista de hashes conocido-malo dentro del paquete.
pub const HASHES_FILE: &str = "hashes.bin";

/// Nombre del manifiesto dentro del paquete.
pub const MANIFEST_FILE: &str = "manifest.json";
/// Nombre del archivo de firma dentro del paquete.
pub const SIGNATURE_FILE: &str = "manifest.sig";

/// Lo que puede salir mal al leer un paquete.
#[derive(Debug)]
pub enum DbError {
    Io(io::Error),
    /// La firma no corresponde a este manifiesto. El paquete no lo emitió Rhino
    /// o fue alterado por el camino.
    Signature,
    /// Un archivo no coincide con el hash y el tamaño que declara el manifiesto.
    Corrupt(String),
    /// El paquete no se entiende.
    Format(String),
}

impl fmt::Display for DbError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbError::Io(error) => write!(formatter, "no se pudo leer el paquete: {error}"),
            DbError::Signature => write!(formatter, "la firma del paquete no es válida"),
            DbError::Corrupt(name) => {
                write!(
                    formatter,
                    "{name} no coincide con lo que declara el manifiesto"
                )
            }
            DbError::Format(detail) => write!(formatter, "el paquete no se entiende: {detail}"),
        }
    }
}

impl std::error::Error for DbError {}

impl From<io::Error> for DbError {
    fn from(error: io::Error) -> Self {
        DbError::Io(error)
    }
}

/// Descripción de un paquete, tal como viaja en `manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Versión del formato, para poder cambiar el diseño sin romper lo viejo.
    pub format: u32,
    /// Versión legible del contenido, del tipo `2026.10.18`.
    pub version: String,
    /// Momento de construcción, en UTC.
    pub created: String,
    /// Canal de publicación (`stable`, `beta`…). El actualizador sirve un canal
    /// por arquitectura.
    pub channel: String,
    /// De dónde salieron las reglas.
    pub source: String,
    pub counts: Counts,
    /// Un registro por archivo del paquete, con su tamaño y su SHA-256.
    pub files: Vec<FileEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counts {
    pub rules: usize,
    pub hashes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

/// Paquete ya abierto: el manifiesto existe y su firma es válida.
///
/// Abrirlo no carga las reglas, así que sirve para consultar la versión antes de
/// gastar memoria.
#[derive(Debug, Clone)]
pub struct Package {
    directory: PathBuf,
    manifest: Manifest,
}

impl Package {
    /// Lee el manifiesto y comprueba su firma con la clave pública de Rhino.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, DbError> {
        Self::open_signed_by(directory, &DB_PUBLIC_KEY)
    }

    /// Igual que [`Package::open`], pero con una clave concreta.
    ///
    /// Lo usan las pruebas y la verificación de artefactos de la CI, que
    /// comprueba el paquete con la clave pública antes de publicarlo.
    pub fn open_signed_by(directory: impl AsRef<Path>, key: &[u8; 32]) -> Result<Self, DbError> {
        let directory = directory.as_ref().to_path_buf();
        let manifest_bytes = fs::read(directory.join(MANIFEST_FILE))?;

        verify_signature(&directory, &manifest_bytes, key)?;

        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|error| DbError::Format(error.to_string()))?;

        if manifest.format != FORMAT {
            return Err(DbError::Format(format!(
                "el manifiesto declara el formato {}, y este Rhino entiende el {FORMAT}",
                manifest.format
            )));
        }

        Ok(Self {
            directory,
            manifest,
        })
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn version(&self) -> &str {
        &self.manifest.version
    }

    /// Carga las reglas y los hashes, comprobando cada archivo contra el
    /// manifiesto. La firma del manifiesto solo prueba que la lista es de Rhino;
    /// el hash de cada archivo prueba que lo descargado es lo listado.
    pub fn load(self) -> Result<Database, DbError> {
        let rules_bytes = self.verified_file(RULES_FILE)?;
        let hashes_bytes = self.verified_file(HASHES_FILE)?;

        let rules = RuleSet::from_compiled(&rules_bytes).map_err(DbError::Format)?;
        let hashes = HashList::from_binary(&hashes_bytes)?;

        Ok(Database {
            rules,
            hashes,
            version: Some(self.manifest.version),
        })
    }

    fn verified_file(&self, name: &str) -> Result<Vec<u8>, DbError> {
        let entry = self
            .manifest
            .files
            .iter()
            .find(|entry| entry.name == name)
            .ok_or_else(|| DbError::Format(format!("el manifiesto no declara {name}")))?;

        let bytes = fs::read(self.directory.join(name))?;
        if bytes.len() as u64 != entry.size || sha256_hex(&bytes) != entry.sha256 {
            return Err(DbError::Corrupt(name.to_string()));
        }
        Ok(bytes)
    }
}

/// Comprueba la firma del manifiesto.
fn verify_signature(directory: &Path, manifest: &[u8], key: &[u8; 32]) -> Result<(), DbError> {
    let text = fs::read_to_string(directory.join(SIGNATURE_FILE))?;
    let bytes = decode_hex::<64>(text.trim()).ok_or(DbError::Signature)?;
    let signature = Signature::from_bytes(&bytes);

    let key = VerifyingKey::from_bytes(key).map_err(|_| DbError::Signature)?;
    key.verify_strict(manifest, &signature)
        .map_err(|_| DbError::Signature)
}

/// Directorio por defecto de la base de datos: junto al ejecutable.
pub fn default_directory() -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    Some(executable.parent()?.join("rhino-db"))
}

/// Todo lo que el escaneo necesita de la base de datos.
pub struct Database {
    rules: RuleSet,
    hashes: HashList,
    version: Option<String>,
}

impl Database {
    /// Base de datos vacía: el escaneo sigue funcionando con las capas 1 y 3.
    pub fn empty() -> Self {
        Self {
            rules: RuleSet::empty(),
            hashes: HashList::empty(),
            version: None,
        }
    }

    /// Arma una base de datos a partir de sus partes, sin pasar por el paquete
    /// firmado. Para pruebas y para construir.
    pub fn from_parts(rules: RuleSet, hashes: HashList) -> Self {
        Self {
            rules,
            hashes,
            version: None,
        }
    }

    /// Abre, verifica y carga un paquete de base de datos.
    pub fn load(directory: impl AsRef<Path>) -> Result<Self, DbError> {
        Package::open(directory)?.load()
    }

    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }

    pub fn hashes(&self) -> &HashList {
        &self.hashes
    }

    /// Versión del paquete cargado, o `None` si no hay ninguno.
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
}

/// Lista de hashes conocido-malo, ordenada para búsqueda binaria.
///
/// Se guarda como digests crudos y no como texto: un millón de hashes ocupa
/// 32 MB así, y bastante más en hexadecimal con el envoltorio de cada `String`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HashList {
    digests: Vec<[u8; HASH_BYTES]>,
}

impl HashList {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Lista a partir de la representación binaria de `hashes.bin`.
    pub fn from_binary(bytes: &[u8]) -> Result<Self, DbError> {
        if !bytes.len().is_multiple_of(HASH_BYTES) {
            return Err(DbError::Format(format!(
                "la lista de hashes tiene {} bytes, que no es múltiplo de {HASH_BYTES}",
                bytes.len()
            )));
        }

        let mut digests: Vec<[u8; HASH_BYTES]> = bytes.as_chunks::<HASH_BYTES>().0.to_vec();
        digests.sort_unstable();
        digests.dedup();

        Ok(Self { digests })
    }

    /// Representación binaria, lista para escribir `hashes.bin`.
    pub fn to_binary(&self) -> Vec<u8> {
        self.digests.concat()
    }

    /// Lista a partir de hashes en hexadecimal, ordenada y sin repetidos.
    pub fn from_hex<I, S>(digests: I) -> Result<Self, DbError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut list = Self::empty();
        for text in digests {
            let text = text.as_ref();
            let digest = decode_hex::<HASH_BYTES>(text)
                .ok_or_else(|| DbError::Format(format!("{text} no es un SHA-256")))?;
            list.digests.push(digest);
        }
        list.digests.sort_unstable();
        list.digests.dedup();
        Ok(list)
    }

    pub fn len(&self) -> usize {
        self.digests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.digests.is_empty()
    }

    /// `true` si el hash en hexadecimal está en la lista.
    pub fn contains_hex(&self, sha256: &str) -> bool {
        let Some(digest) = decode_hex::<HASH_BYTES>(sha256) else {
            return false;
        };
        self.digests.binary_search(&digest).is_ok()
    }

    /// `true` si el texto parece un hash de los que acepta la lista.
    pub fn accepts(text: &str) -> bool {
        is_sha256_hex(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::{Signer, SigningKey};

    /// Semilla de la clave de prueba. No es la de producción.
    const TEST_SEED: [u8; 32] = [7u8; 32];

    const EICAR_RULE: &str = r#"
rule rhino_test_eicar {
    meta:
        description = "Archivo de prueba EICAR"
        author = "Rhino"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}
"#;

    #[test]
    fn empty_list_finds_nothing() {
        let list = HashList::empty();

        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
        assert!(!list.contains_hex(&crate::corpus::eicar_sha256()));
    }

    #[test]
    fn hex_list_finds_what_it_holds() {
        let list = HashList::from_hex([
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
        ])
        .expect("no se pudo armar la lista");

        assert_eq!(list.len(), 2);
        // En mayúsculas también, porque el manifiesto y las reglas no se ponen de
        // acuerdo en el caso.
        assert!(
            list.contains_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert!(
            !list.contains_hex("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd00")
        );
    }

    #[test]
    fn repeated_hashes_are_stored_once() {
        let one = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let list = HashList::from_hex([one, one]).unwrap();

        assert_eq!(list.len(), 1);
    }

    #[test]
    fn binary_round_trip_keeps_the_hashes() {
        let list = HashList::from_hex([crate::corpus::eicar_sha256()]).unwrap();

        let restored = HashList::from_binary(&list.to_binary()).unwrap();

        assert_eq!(restored.len(), 1);
        assert!(restored.contains_hex(&crate::corpus::eicar_sha256()));
    }

    #[test]
    fn binary_length_must_be_a_multiple_of_the_digest_size() {
        assert!(HashList::from_binary(&[0u8; HASH_BYTES + 1]).is_err());
        assert!(HashList::from_binary(&[]).is_ok());
    }

    #[test]
    fn a_non_sha256_text_is_rejected() {
        assert!(HashList::from_hex(["no soy un hash"]).is_err());
        assert!(!HashList::accepts("no soy un hash"));
        assert!(!HashList::empty().contains_hex("no soy un hash"));
    }

    #[test]
    fn an_unsigned_package_is_rejected() {
        let directory = temp_directory("sin-firma");
        write_package(&directory, &rules_bytes(), &hashes_bytes(), "{}", false);

        let error = Package::open_signed_by(&directory, &test_public_key()).unwrap_err();

        assert!(matches!(error, DbError::Io(_)), "{error}");
        fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn a_forged_signature_is_rejected() {
        let directory = temp_directory("falsificada");
        write_package(&directory, &rules_bytes(), &hashes_bytes(), "", true);
        // Se firma de nuevo con otra clave: el manifiesto es válido, la firma no.
        sign(&directory, &SigningKey::from_bytes(&[9u8; 32]));

        let error = Package::open_signed_by(&directory, &test_public_key()).unwrap_err();

        assert!(matches!(error, DbError::Signature), "{error}");
        fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn a_manifest_tampered_after_signing_is_rejected() {
        let directory = temp_directory("alterado-despues");
        write_package(&directory, &rules_bytes(), &hashes_bytes(), "", true);
        // Un byte cambiado en el manifiesto tiene que invalidar la firma.
        let manifest = fs::read(directory.join(MANIFEST_FILE)).unwrap();
        let mut altered = manifest.clone();
        altered.push(b' ');
        fs::write(directory.join(MANIFEST_FILE), &altered).unwrap();

        let error = Package::open_signed_by(&directory, &test_public_key()).unwrap_err();

        assert!(matches!(error, DbError::Signature), "{error}");
        fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn a_file_that_does_not_match_the_manifest_is_rejected() {
        let directory = temp_directory("alterado-archivo");
        write_package(&directory, &rules_bytes(), &hashes_bytes(), "", true);
        // El manifiesto sigue firmado, pero las reglas ya no son las que declara.
        fs::write(directory.join(RULES_FILE), b"reglas cambiadas").unwrap();

        let result = load_signed(&directory);

        assert!(matches!(result, Err(DbError::Corrupt(name)) if name == RULES_FILE));
        fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn a_signed_package_round_trips() {
        let directory = temp_directory("redondo");
        write_package(&directory, &rules_bytes(), &hashes_bytes(), "", true);

        let database = load_signed(&directory).expect("el paquete debería cargar");

        assert_eq!(database.version(), Some("2026.10.18"));
        assert_eq!(database.rules().len(), 1);
        assert_eq!(database.hashes().len(), 1);
        assert!(
            database
                .hashes()
                .contains_hex(&crate::corpus::eicar_sha256())
        );
        assert_eq!(
            database
                .rules()
                .scan(crate::corpus::eicar().as_slice())
                .unwrap()
                .len(),
            1
        );

        fs::remove_dir_all(&directory).ok();
    }

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&TEST_SEED)
    }

    fn test_public_key() -> [u8; 32] {
        test_key().verifying_key().to_bytes()
    }

    fn load_signed(directory: &Path) -> Result<Database, DbError> {
        Package::open_signed_by(directory, &test_public_key())?.load()
    }

    fn rules_bytes() -> Vec<u8> {
        RuleSet::compile(&[EICAR_RULE])
            .unwrap()
            .to_compiled()
            .unwrap()
    }

    fn hashes_bytes() -> Vec<u8> {
        HashList::from_hex([crate::corpus::eicar_sha256()])
            .unwrap()
            .to_binary()
    }

    /// Escribe los archivos y el manifiesto; firma solo si se pide.
    ///
    /// `manifest_override` sustituye el manifiesto cuando no es `""`, para poder
    /// probar un manifiesto que no se puede deserializar.
    fn write_package(
        directory: &Path,
        rules: &[u8],
        hashes: &[u8],
        manifest_override: &str,
        signed: bool,
    ) {
        fs::write(directory.join(RULES_FILE), rules).unwrap();
        fs::write(directory.join(HASHES_FILE), hashes).unwrap();

        let text = if manifest_override.is_empty() {
            serde_json::to_string(&manifest_for(rules, hashes)).unwrap()
        } else {
            manifest_override.to_string()
        };
        fs::write(directory.join(MANIFEST_FILE), &text).unwrap();

        if signed {
            sign(directory, &test_key());
        }
    }

    fn manifest_for(rules: &[u8], hashes: &[u8]) -> Manifest {
        Manifest {
            format: FORMAT,
            version: "2026.10.18".to_string(),
            created: "2026-10-18T00:00:00Z".to_string(),
            channel: "stable".to_string(),
            source: "prueba".to_string(),
            counts: Counts {
                rules: 1,
                hashes: 1,
            },
            files: vec![
                FileEntry {
                    name: RULES_FILE.to_string(),
                    size: rules.len() as u64,
                    sha256: sha256_hex(rules),
                },
                FileEntry {
                    name: HASHES_FILE.to_string(),
                    size: hashes.len() as u64,
                    sha256: sha256_hex(hashes),
                },
            ],
        }
    }

    fn sign(directory: &Path, key: &SigningKey) {
        let manifest = fs::read(directory.join(MANIFEST_FILE)).unwrap();
        let signature = key.sign(&manifest);
        fs::write(
            directory.join(SIGNATURE_FILE),
            crate::hash::to_hex(&signature.to_bytes()),
        )
        .unwrap();
    }

    fn temp_directory(name: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("rhino-db-{}-{name}", std::process::id()));
        fs::remove_dir_all(&directory).ok();
        fs::create_dir_all(&directory).unwrap();
        directory
    }
}
