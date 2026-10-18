//! Mide falsos positivos y consumo sobre un directorio real del sistema.
//!
//! Los falsos positivos son la métrica que decide si Rhino es usable: un
//! antivirus que marca archivos buenos es peor que no tener antivirus.
//!
//! Uso: `cargo run -p rhino-core --example scan_dir -- <directorio> [reglas] [salida.yarc]`
//!
//! `reglas` es un archivo `.yar` (se compila) o `.yarc` (ya compilado, que es la
//! ruta de producción). Sin él se escanea solo con las capas 1 y 3, que no
//! dependen de ninguna descarga. Con `salida.yarc` se escribe el conjunto
//! compilado.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use rhino_core::{Database, FileKind, HashList, RuleSet, Verdict, scan_dir};

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);

    let Some(root) = args.next().map(PathBuf::from) else {
        eprintln!("uso: scan_dir <directorio> [reglas.yar|reglas.yarc] [salida.yarc]");
        return ExitCode::FAILURE;
    };

    let rules = match args.next().map(PathBuf::from) {
        Some(path) => match load_rules(&path) {
            Ok(rules) => rules,
            Err(error) => {
                eprintln!("{error}");
                return ExitCode::FAILURE;
            }
        },
        None => RuleSet::empty(),
    };

    if let Some(output) = args.next().map(PathBuf::from) {
        match rules.to_compiled() {
            Ok(bytes) => match fs::write(&output, &bytes) {
                Ok(()) => println!(
                    "{} escrito: {:.1} MB",
                    output.display(),
                    bytes.len() as f32 / (1024.0 * 1024.0)
                ),
                Err(error) => eprintln!("no se pudo escribir {}: {error}", output.display()),
            },
            Err(error) => eprintln!("no se pudo compilar el conjunto: {error}"),
        }
    }

    // La capa 1 se alimenta del metadato `hash` de las propias reglas, más el
    // EICAR. Así se mide el escaneo completo sin depender de ningún feed aparte.
    let mut declared = rules.known_hashes();
    declared.push(rhino_core::corpus::eicar_sha256());
    let hashes = match HashList::from_hex(declared) {
        Ok(hashes) => hashes,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    println!("{} hashes declarados por las reglas", hashes.len());

    let database = Database::from_parts(rules, hashes);

    let (mut scanned, mut malicious, mut suspicious, mut executables) = (0usize, 0, 0, 0);
    let result = scan_dir(&root, &database, |report| {
        scanned += 1;
        if matches!(report.kind, FileKind::Pe(_)) {
            executables += 1;
        }
        match report.verdict {
            Verdict::Clean => {}
            Verdict::Malicious => {
                malicious += 1;
                println!("{}", report.summary());
            }
            Verdict::Suspicious => {
                suspicious += 1;
                println!("{}", report.summary());
            }
        }
    });

    if result.is_err() {
        eprintln!("no se pudo leer {}", root.display());
        return ExitCode::FAILURE;
    }

    println!(
        "\n{scanned} archivos analizados ({executables} ejecutables PE): {malicious} maliciosos, {suspicious} sospechosos, {} limpios",
        scanned - malicious - suspicious
    );
    ExitCode::SUCCESS
}

fn load_rules(path: &Path) -> Result<RuleSet, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("no se pudo leer {}: {error}", path.display()))?;
    let started = Instant::now();

    // El paquete de base de datos trae las reglas ya compiladas; la compilación
    // desde la fuente es solo para medir y para la canalización de CI.
    let precompiled = path
        .extension()
        .is_some_and(|extension| extension == "yarc");
    let rules = if precompiled {
        RuleSet::from_compiled(&bytes)?
    } else {
        let source = std::str::from_utf8(&bytes)
            .map_err(|_| format!("{} no es un archivo de texto", path.display()))?;
        RuleSet::compile(&[source])?
    };

    println!(
        "{} reglas {} en {:.1} s",
        rules.len(),
        if precompiled {
            "cargadas del paquete compilado"
        } else {
            "compiladas desde la fuente"
        },
        started.elapsed().as_secs_f32()
    );
    Ok(rules)
}
