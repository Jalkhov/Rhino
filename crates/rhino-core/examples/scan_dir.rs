//! Mide falsos positivos sobre un directorio real del sistema.
//!
//! Es la métrica que decide si Rhino es usable: un antivirus que marca archivos
//! buenos es peor que no tener antivirus.
//!
//! Uso: `cargo run -p rhino-core --example scan_dir -- /usr/bin`

use std::path::PathBuf;
use std::process::ExitCode;

use rhino_core::{FileKind, Verdict, scan_dir};

fn main() -> ExitCode {
    let Some(root) = std::env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("uso: scan_dir <directorio>");
        return ExitCode::FAILURE;
    };

    let Ok(reports) = scan_dir(&root) else {
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
