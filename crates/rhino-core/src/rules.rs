//! Capa 2: reglas YARA-X.
//!
//! YARA-X es la reimplementación de YARA hecha en Rust por VirusTotal
//! (licencia BSD-3-Clause). Rhino **no** escribe su propio motor de patrones:
//! escribe el orquestador que lo alimenta. Ver "Motor de detección y base de
//! datos" en el README.
//!
//! Las reglas llegan ya **compiladas** dentro del paquete de base de datos
//! (`rules.yarc`). Compilarlas en el equipo del usuario costaría segundos y
//! bastante memoria — justo lo que Rhino evita. `compile` y `to_compiled`
//! existen para la canalización de CI que construye ese paquete.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

use yara_x::{Compiler, MetaValue, Rules, Scanner};

/// Tope de tiempo por archivo. Una regla con expresiones regulares costosas no
/// debe poder colgar el escaneo completo.
const SCAN_TIMEOUT: Duration = Duration::from_secs(10);

/// Puntaje mínimo (0–100) para tratar una coincidencia como certeza.
///
/// El paquete `core` de YARA Forge puntúa cada regla; por debajo del umbral la
/// coincidencia se reporta como sospecha, no como detección confirmada.
pub const SCORE_MALICIOUS: i64 = 75;

/// Cuántos bytes mira como mucho la capa de reglas en un archivo.
///
/// YARA-X lee en un búfer lo que cabe por debajo de este tope y usa memoria
/// mapeada por encima, así que el consumo no crece con el tamaño del archivo.
/// El tope existe para que un archivo enorme (un ISO, un volcado de memoria) no
/// pueda agotar la RAM de un equipo modesto: pasado el límite se analiza solo el
/// principio, que es donde vive la cabecera. ClamAV usa un límite del mismo
/// orden de magnitud.
pub const MAX_SCAN_SIZE: usize = 64 * 1024 * 1024;

/// Conjunto de reglas compiladas, listo para escanear.
pub struct RuleSet {
    rules: Rules,
}

/// Una regla que coincidió con los datos analizados.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMatch {
    pub identifier: String,
    pub description: Option<String>,
    /// La licencia DRL 1.1 obliga a conservar al autor en el mensaje de
    /// coincidencia; la interfaz debe mostrarlo.
    pub author: Option<String>,
    pub source_url: Option<String>,
    pub score: Option<i64>,
}

impl RuleSet {
    /// Conjunto vacío. El escaneo sigue funcionando con las capas 1 y 3.
    pub fn empty() -> Self {
        Self {
            rules: Compiler::new().build(),
        }
    }

    /// Compila reglas desde su código fuente. Solo para construir la base de datos.
    pub fn compile(sources: &[&str]) -> Result<Self, String> {
        let mut compiler = Compiler::new();
        for source in sources {
            compiler
                .add_source(*source)
                .map_err(|error| error.to_string())?;
        }
        Ok(Self {
            rules: compiler.build(),
        })
    }

    /// Carga reglas ya compiladas (`rules.yarc` del paquete de base de datos).
    pub fn from_compiled(bytes: &[u8]) -> Result<Self, String> {
        Rules::deserialize(bytes)
            .map(|rules| Self { rules })
            .map_err(|error| error.to_string())
    }

    /// Devuelve el conjunto compilado en bytes, para publicarlo en la base de datos.
    pub fn to_compiled(&self) -> Result<Vec<u8>, String> {
        self.rules.serialize().map_err(|error| error.to_string())
    }

    /// Cuántas reglas contiene el conjunto.
    pub fn len(&self) -> usize {
        self.rules.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Escanea datos en memoria y describe cada regla que coincidió.
    pub fn scan(&self, data: &[u8]) -> Result<Vec<RuleMatch>, String> {
        let mut scanner = self.scanner();
        let results = scanner.scan(data).map_err(|error| error.to_string())?;

        Ok(results.matching_rules().map(describe).collect())
    }

    /// Escanea un archivo del disco sin cargarlo entero en memoria.
    ///
    /// Es la ruta que usa el escaneo real: el motor decide entre leer y mapear,
    /// y nunca mira más de [`MAX_SCAN_SIZE`] bytes.
    pub fn scan_path(&self, path: &Path) -> Result<Vec<RuleMatch>, String> {
        let mut scanner = self.scanner();

        match scanner.scan_file(path) {
            Ok(results) => Ok(results.matching_rules().map(describe).collect()),
            // Un proceso de 32 bits solo tiene ~2 GB de espacio de direcciones, y
            // el motor mapea el archivo entero antes de mirarlo, así que los
            // archivos de varios GB no se pueden mapear. Se lee entonces el
            // prefijo acotado, que es lo único que se iba a mirar de todos modos.
            Err(_) => self.scan_prefix(path),
        }
    }

    /// Escanea los primeros [`MAX_SCAN_SIZE`] bytes del archivo.
    fn scan_prefix(&self, path: &Path) -> Result<Vec<RuleMatch>, String> {
        let mut data = Vec::new();
        File::open(path)
            .map_err(|error| error.to_string())?
            .take(MAX_SCAN_SIZE as u64)
            .read_to_end(&mut data)
            .map_err(|error| error.to_string())?;

        self.scan(&data)
    }

    fn scanner(&self) -> Scanner<'_> {
        let mut scanner = Scanner::new(&self.rules);
        scanner.set_timeout(SCAN_TIMEOUT);
        scanner.max_scan_size(MAX_SCAN_SIZE);
        scanner
    }
}

fn describe(rule: yara_x::Rule) -> RuleMatch {
    let mut description = None;
    let mut author = None;
    let mut source_url = None;
    let mut score = None;

    for (name, value) in rule.metadata() {
        match name {
            "description" => description = text(&value),
            "author" => author = text(&value),
            "source_url" => source_url = text(&value),
            "score" => score = integer(&value),
            _ => {}
        }
    }

    RuleMatch {
        identifier: rule.identifier().to_string(),
        description,
        author,
        source_url,
        score,
    }
}

fn text(value: &MetaValue) -> Option<String> {
    match value {
        MetaValue::String(text) => Some(text.to_string()),
        _ => None,
    }
}

fn integer(value: &MetaValue) -> Option<i64> {
    match value {
        MetaValue::Integer(number) => Some(*number),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EICAR_RULE: &str = r#"
rule eicar_test_file {
    meta:
        description = "Detects the EICAR test file"
        author = "Rhino"
        source_url = "https://example.invalid/rules"
        score = 90
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}
"#;

    #[test]
    fn empty_set_matches_nothing() {
        let rules = RuleSet::empty();

        assert_eq!(rules.len(), 0);
        assert!(rules.is_empty());
        assert!(
            rules
                .scan(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn compiled_rule_matches_and_keeps_its_metadata() {
        let rules = RuleSet::compile(&[EICAR_RULE]).expect("la regla no compiló");
        assert_eq!(rules.len(), 1);

        let matches = rules.scan(crate::corpus::eicar().as_slice()).unwrap();

        assert_eq!(matches.len(), 1);
        let matched = &matches[0];
        assert_eq!(matched.identifier, "eicar_test_file");
        assert_eq!(matched.score, Some(90));
        assert_eq!(matched.author.as_deref(), Some("Rhino"));
        assert_eq!(
            matched.source_url.as_deref(),
            Some("https://example.invalid/rules")
        );
        assert!(matched.description.is_some());
    }

    #[test]
    fn unrelated_data_does_not_match() {
        let rules = RuleSet::compile(&[EICAR_RULE]).unwrap();

        assert!(
            rules
                .scan(crate::corpus::benign_text().as_slice())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn broken_source_is_an_error() {
        assert!(RuleSet::compile(&["rule { esto no es YARA"]).is_err());
    }

    #[test]
    fn compiled_rules_survive_the_round_trip() {
        let original = RuleSet::compile(&[EICAR_RULE]).unwrap();
        let bytes = original.to_compiled().expect("no se pudo serializar");

        let restored = RuleSet::from_compiled(&bytes).expect("no se pudo deserializar");

        assert_eq!(restored.len(), 1);
        assert_eq!(
            restored
                .scan(crate::corpus::eicar().as_slice())
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn scans_a_file_by_path_and_the_bounded_prefix() {
        let path = std::env::temp_dir().join(format!("rhino-reglas-{}.txt", std::process::id()));
        std::fs::write(&path, crate::corpus::eicar()).unwrap();
        let rules = RuleSet::compile(&[EICAR_RULE]).unwrap();

        assert_eq!(rules.scan_path(&path).unwrap().len(), 1);
        // La reserva acotada es la que entra cuando el archivo no se puede mapear.
        assert_eq!(rules.scan_prefix(&path).unwrap().len(), 1);

        let missing = path.with_extension("inexistente");
        assert!(rules.scan_path(&missing).is_err());

        std::fs::remove_file(&path).ok();
    }
}
