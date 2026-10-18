//! Construcción de la base de datos de Rhino.
//!
//! Es el trabajo que corre en la CI: toma las reglas de YARA Forge, les saca los
//! hashes que declaran, compila el conjunto, arma el manifiesto y lo firma. El
//! resultado es un paquete `rhino-db-AAAA.MM.DD/` que la aplicación verifica
//! antes de usar (ver "Paquete de base de datos" en el README).
//!
//! La clave privada es el activo más sensible del proyecto: quien la tenga puede
//! emitir un paquete que apague Rhino en todos los equipos.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};

use rhino_core::db::{
    Counts, FORMAT, FileEntry, HASHES_FILE, MANIFEST_FILE, Manifest, RULES_FILE, SIGNATURE_FILE,
};
use rhino_core::{HashList, Package, RuleSet, sha256_hex, to_hex};

const USAGE: &str = "\
uso:
  rhino-db keygen <clave-privada>     genera un par de claves
  rhino-db public-key <clave-privada> imprime la clave pública
  rhino-db build --rules <reglas.yar> --out <directorio> --channel <canal> --key <clave-privada> [--source <origen>]
  rhino-db verify --package <directorio> [--public-key <clave-pública>]
  rhino-db update <url> <directorio>  descarga el paquete publicado en esa URL";

/// De dónde salen las reglas, salvo que se diga otra cosa.
const DEFAULT_SOURCE: &str =
    "https://github.com/YARAHQ/yara-forge/releases (paquete core, semanal)";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let Some(command) = args.first() else {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    };

    let result = match command.as_str() {
        "keygen" => keygen(args.get(1)),
        "public-key" => print_public_key(args.get(1)),
        "build" => build(&args[1..]),
        "verify" => verify(&args[1..]),
        "update" => update_package(&args[1..]),
        other => Err(format!("orden desconocida: {other}\n\n{USAGE}")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn keygen(path: Option<&String>) -> Result<(), String> {
    let Some(path) = path else {
        return Err(format!("falta la ruta de la clave privada\n\n{USAGE}"));
    };
    let path = Path::new(path);

    if path.exists() {
        return Err(format!(
            "{} ya existe: una clave privada no se sobrescribe",
            path.display()
        ));
    }

    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|error| format!("no hay entropía disponible: {error}"))?;
    let key = SigningKey::from_bytes(&seed);

    fs::write(path, format!("{}\n", to_hex(&seed)))
        .map_err(|error| format!("no se pudo escribir {}: {error}", path.display()))?;
    restrict(path)?;

    println!("clave privada: {}", path.display());
    println!("clave pública: {}", to_hex(&key.verifying_key().to_bytes()));
    println!(
        "\nLa privada no se versiona y conviene respaldarla fuera del equipo: si se\n\
         pierde, no se pueden firmar más paquetes. La pública se copia en\n\
         DB_PUBLIC_KEY (crates/rhino-core/src/db.rs)."
    );
    Ok(())
}

fn print_public_key(path: Option<&String>) -> Result<(), String> {
    let Some(path) = path else {
        return Err(format!("falta la ruta de la clave privada\n\n{USAGE}"));
    };

    println!("{}", to_hex(&read_key(path)?.verifying_key().to_bytes()));
    Ok(())
}

/// Descarga el paquete publicado en `url` y lo deja instalado en `directorio`.
fn update_package(args: &[String]) -> Result<(), String> {
    let [base, destination] = args else {
        return Err(format!(
            "faltan la URL y el directorio de destino\n\n{USAGE}"
        ));
    };

    let destination = Path::new(destination);
    match rhino_core::update(base, destination) {
        Ok(Some(version)) => {
            println!("paquete {version} instalado en {}", destination.display());
            Ok(())
        }
        Ok(None) => {
            println!("ya estaba al día en {}", destination.display());
            Ok(())
        }
        Err(error) => Err(error.to_string()),
    }
}

fn build(args: &[String]) -> Result<(), String> {
    let options = Options::parse(args)?;

    let source = fs::read_to_string(&options.rules)
        .map_err(|error| format!("no se pudo leer {}: {error}", options.rules.display()))?;

    let started = std::time::Instant::now();
    let rules = RuleSet::compile(&[source.as_str()])?;
    let rules_bytes = rules.to_compiled()?;

    // La capa 1 se alimenta de los hashes que las propias reglas declaran, más el
    // EICAR, que todo antivirus tiene que detectar.
    let mut declared = rules.known_hashes();
    declared.push(rhino_core::corpus::eicar_sha256());
    let hashes = HashList::from_hex(declared).map_err(|error| error.to_string())?;
    let hashes_bytes = hashes.to_binary();

    let (version, created) = utc_now();
    let manifest = Manifest {
        format: FORMAT,
        version: version.clone(),
        created,
        channel: options.channel.clone(),
        source: options.source.clone(),
        counts: Counts {
            rules: rules.len(),
            hashes: hashes.len(),
        },
        files: vec![
            entry(RULES_FILE, &rules_bytes),
            entry(HASHES_FILE, &hashes_bytes),
        ],
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("no se pudo serializar el manifiesto: {error}"))?;

    let key = read_key(&options.key)?;
    let signature = key.sign(&manifest_bytes);

    // Una firma que no se puede verificar es peor que ninguna: se comprueba aquí
    // mismo antes de publicar el paquete.
    key.verifying_key()
        .verify_strict(&manifest_bytes, &signature)
        .map_err(|error| format!("la firma recién hecha no verifica: {error}"))?;

    fs::create_dir_all(&options.out)
        .map_err(|error| format!("no se pudo crear {}: {error}", options.out.display()))?;
    write(&options.out, RULES_FILE, &rules_bytes)?;
    write(&options.out, HASHES_FILE, &hashes_bytes)?;
    write(&options.out, MANIFEST_FILE, &manifest_bytes)?;
    write(
        &options.out,
        SIGNATURE_FILE,
        format!("{}\n", to_hex(&signature.to_bytes())).as_bytes(),
    )?;

    println!(
        "{} reglas y {} hashes en {:.1} s",
        manifest.counts.rules,
        manifest.counts.hashes,
        started.elapsed().as_secs_f32()
    );
    println!(
        "paquete {} (canal {}, formato {}): {:.1} MB de reglas, {:.1} MB de hashes",
        version,
        options.channel,
        FORMAT,
        rules_bytes.len() as f32 / (1024.0 * 1024.0),
        hashes_bytes.len() as f32 / (1024.0 * 1024.0)
    );
    println!("firmado con {} y verificado", options.key);
    Ok(())
}

/// Verifica un paquete y lo carga, sin escribir nada.
///
/// Es el paso que la CI corre sobre el artefacto ya publicado: si esto pasa, lo
/// que se sirve a los usuarios es exactamente lo que Rhino firmó.
fn verify(args: &[String]) -> Result<(), String> {
    let (mut directory, mut public_key) = (None, None);

    let mut arguments = args.iter();
    while let Some(flag) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| format!("{flag} espera un valor\n\n{USAGE}"))?;
        match flag.as_str() {
            "--package" => directory = Some(PathBuf::from(value)),
            "--public-key" => public_key = Some(value.clone()),
            other => return Err(format!("opción desconocida: {other}\n\n{USAGE}")),
        }
    }

    let directory = directory.ok_or("falta --package")?;
    let key = match public_key {
        Some(text) => rhino_core::decode_hex::<32>(text.trim())
            .ok_or_else(|| format!("{text} no es una clave de 32 bytes en hexadecimal"))?,
        None => rhino_core::db::DB_PUBLIC_KEY,
    };

    let package = Package::open_signed_by(&directory, &key).map_err(|error| error.to_string())?;
    let manifest = package.manifest().clone();
    let database = package.load().map_err(|error| error.to_string())?;

    println!(
        "paquete {} (canal {}, formato {})",
        manifest.version, manifest.channel, manifest.format
    );
    println!(
        "construido el {} desde {}",
        manifest.created, manifest.source
    );
    println!(
        "{} reglas y {} hashes cargados, con la firma y los hashes verificados",
        database.rules().len(),
        database.hashes().len()
    );
    for file in &manifest.files {
        println!("  {} · {} bytes · {}", file.name, file.size, file.sha256);
    }
    Ok(())
}

/// Opciones de `build`, tal como llegan de la línea de órdenes.
struct Options {
    rules: PathBuf,
    out: PathBuf,
    channel: String,
    source: String,
    key: String,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self, String> {
        let (mut rules, mut out, mut channel, mut source, mut key) = (None, None, None, None, None);

        let mut arguments = args.iter();
        while let Some(flag) = arguments.next() {
            let value = arguments
                .next()
                .ok_or_else(|| format!("{flag} espera un valor\n\n{USAGE}"))?;
            match flag.as_str() {
                "--rules" => rules = Some(PathBuf::from(value)),
                "--out" => out = Some(PathBuf::from(value)),
                "--channel" => channel = Some(value.clone()),
                "--source" => source = Some(value.clone()),
                "--key" => key = Some(value.clone()),
                other => return Err(format!("opción desconocida: {other}\n\n{USAGE}")),
            }
        }

        Ok(Self {
            rules: rules.ok_or("falta --rules")?,
            out: out.ok_or("falta --out")?,
            channel: channel.ok_or("falta --channel")?,
            source: source.unwrap_or_else(|| DEFAULT_SOURCE.to_string()),
            key: key.ok_or("falta --key")?,
        })
    }
}

fn entry(name: &str, bytes: &[u8]) -> FileEntry {
    FileEntry {
        name: name.to_string(),
        size: bytes.len() as u64,
        sha256: sha256_hex(bytes),
    }
}

fn write(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    let path = directory.join(name);
    fs::write(&path, bytes)
        .map_err(|error| format!("no se pudo escribir {}: {error}", path.display()))
}

fn read_key(path: &str) -> Result<SigningKey, String> {
    let text =
        fs::read_to_string(path).map_err(|error| format!("no se pudo leer {path}: {error}"))?;

    let seed = rhino_core::decode_hex::<32>(text.trim())
        .ok_or_else(|| format!("{path} no contiene una clave de 32 bytes en hexadecimal"))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Deja la clave privada solo para su dueño, cuando el sistema lo permite.
#[cfg(unix)]
fn restrict(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("no se pudieron ajustar los permisos: {error}"))
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// Fecha y hora actual en UTC: `AAAA.MM.DD` y RFC 3339.
///
/// La conversión de días desde la época al calendario es el algoritmo de Howard
/// Hinnant. Está aquí, y no en una dependencia, porque es lo único que hacía
/// falta de una biblioteca de fechas.
fn utc_now() -> (String, String) {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (year, month, day) = civil_from_days((seconds / 86_400) as i64);

    let time = seconds % 86_400;
    (
        format!("{year:04}.{month:02}.{day:02}"),
        format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            time / 3600,
            (time % 3600) / 60,
            time % 60
        ),
    )
}

/// Días desde el 1 de enero de 1970 al año, mes y día del calendario gregoriano.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = (shifted - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;

    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;

    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_is_the_first_of_january_1970() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn a_leap_day_is_handled() {
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
    }

    #[test]
    fn a_recent_date_lines_up() {
        assert_eq!(civil_from_days(20_744), (2026, 10, 18));
    }

    #[test]
    fn the_manifest_version_is_a_date_and_the_timestamp_is_rfc3339() {
        let (version, created) = utc_now();

        assert_eq!(version.len(), 10, "{version}");
        assert_eq!(version.matches('.').count(), 2, "{version}");
        assert!(created.ends_with('Z'), "{created}");
        assert_eq!(created.len(), 20, "{created}");
    }
}
