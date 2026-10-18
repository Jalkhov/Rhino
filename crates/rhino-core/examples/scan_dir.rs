//! Mide falsos positivos sobre un directorio real del sistema.
//!
//! Es la métrica que decide si Rhino es usable: un antivirus que marca archivos
//! buenos es peor que no tener antivirus.
//!
//! Uso: `cargo run -p rhino-core --example scan_dir -- /usr/bin [reglas.yar]`
//!
//! El segundo argumento, opcional, es un archivo de reglas YARA. Sin él se
//! escanea solo con las capas 1 y 3, que no dependen de ninguna descarga.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use rhino_core::{FileKind, RuleSet, Verdict, scan_dir};

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);

    let Some(root) = args.next().map(PathBuf::from) else {
        eprintln!("uso: scan_dir <directorio> [reglas.yar]");
        return ExitCode::FAILURE;
    };

    let rules = match args.next().map(PathBuf::from) {
        Some(source) => {
            let Ok(text) = fs::read_to_string(&source) else {
                eprintln!("no se pudo leer {}", source.display());
                return ExitCode::FAILURE;
            };
            let started = Instant::now();
            let Ok(rules) = RuleSet::compile(&[text.as_str()]) else {
                eprintln!("las reglas de {} no compilan", source.display());
                return ExitCode::FAILURE;
            };
            println!(
                "{} reglas compiladas en {:.1} s (en la base de datos van precompiladas)",
                rules.len(),
                started.elapsed().as_secs_f32()
            );
            if let Ok(compiled) = rules.to_compiled() {
                println!(
                    "conjunto compilado: {:.1} MB",
                    compiled.len() as f32 / (1024.0 * 1024.0)
                );
            }
            rules
        }
        None => RuleSet::empty(),
    };

    let Ok(reports) = scan_dir(&root, &rules) else {
        eprintln!("no se pudo leer {}", root.display());
        return ExitCode::FAILURE;
    };

    let mut malicious = 0usize;
    let mut suspicious = 0usize;
    for report in reports
        .iter()
        .filter(|report| report.verdict != Verdict::Clean)
    {
        match report.verdict {
            Verdict::Malicious => malicious += 1,
            _ => suspicious += 1,
        }
        println!("{}", report.summary());
    }

    println!(
        "\n{} archivos analizados ({} ejecutables PE): {malicious} maliciosos, {suspicious} sospechosos, {} limpios",
        reports.len(),
        reports
            .iter()
            .filter(|report| matches!(report.kind, FileKind::Pe(_)))
            .count(),
        reports.len() - malicious - suspicious
    );
    ExitCode::SUCCESS
}
