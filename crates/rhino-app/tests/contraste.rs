//! Contraste medido sobre los tokens reales de `ui/theme.slint`.
//!
//! La fase 4 de este proyecto se pagó tres veces porque el contraste se miraba a
//! ojo. Esta prueba lee la paleta del archivo que de verdad se compila y comprueba
//! los pares que la interfaz usa, con los mínimos de WCAG 2.2 AA: 4.5:1 para texto
//! y 3:1 para marcas y componentes. Si alguien cambia un color y rompe la lectura,
//! falla aquí y no en una captura.

use std::collections::BTreeMap;
use std::path::PathBuf;

/// Color de 8 bits por canal.
#[derive(Clone, Copy, Debug)]
struct Rgb {
    red: u8,
    green: u8,
    blue: u8,
}

impl Rgb {
    fn parse(text: &str) -> Option<Self> {
        let hex = text.trim().strip_prefix('#')?;
        if hex.len() != 6 {
            return None;
        }
        let channel = |start: usize| u8::from_str_radix(&hex[start..start + 2], 16).ok();
        Some(Self {
            red: channel(0)?,
            green: channel(2)?,
            blue: channel(4)?,
        })
    }

    /// Luminancia relativa según WCAG 2.2, fórmula de la definición.
    fn luminance(self) -> f64 {
        let linear = |channel: u8| {
            let value = f64::from(channel) / 255.0;
            if value <= 0.039_28 {
                value / 12.92
            } else {
                ((value + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * linear(self.red) + 0.7152 * linear(self.green) + 0.0722 * linear(self.blue)
    }
}

fn contrast(first: Rgb, second: Rgb) -> f64 {
    let one = first.luminance();
    let other = second.luminance();
    let (lighter, darker) = if one > other {
        (one, other)
    } else {
        (other, one)
    };
    (lighter + 0.05) / (darker + 0.05)
}

/// Lee las líneas `out property <color> nombre: #RRGGBB;` del tema.
fn tokens() -> BTreeMap<String, Rgb> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ui/theme.slint");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("no se pudo leer {}: {error}", path.display()));

    let mut found = BTreeMap::new();
    for line in source.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("out property <color>") else {
            continue;
        };
        let Some((name, value)) = rest.split_once(':') else {
            continue;
        };
        let value = value.split(';').next().unwrap_or("");
        let color = Rgb::parse(value)
            .unwrap_or_else(|| panic!("el token {} no es un color: {value:?}", name.trim()));
        found.insert(name.trim().to_owned(), color);
    }
    assert!(
        found.len() >= 20,
        "solo se leyeron {} colores de theme.slint: el parser dejó de entender el archivo",
        found.len()
    );
    found
}

/// Pares que la interfaz pinta de verdad, con el mínimo que exige WCAG.
const PAIRS: &[(&str, &str, f64, &str)] = &[
    // Texto sobre las superficies.
    ("ink", "card", 4.5, "texto principal sobre tarjeta"),
    ("ink", "ground", 4.5, "texto principal sobre el fondo"),
    ("ink-soft", "card", 4.5, "texto secundario sobre tarjeta"),
    ("ink-soft", "ground", 4.5, "texto secundario sobre el fondo"),
    ("ink-muted", "card", 4.5, "texto atenuado sobre tarjeta"),
    ("ink-muted", "ground", 4.5, "texto atenuado sobre el fondo"),
    ("ink-muted", "rail", 4.5, "riel sin elegir"),
    ("ink-muted", "sunken", 4.5, "texto atenuado en zona hundida"),
    ("ink-muted", "tile", 4.5, "pie del estado vacío"),
    ("ink-soft", "rail", 4.5, "etiqueta del riel"),
    ("ink-soft", "sunken", 4.5, "explicación desplegada"),
    // Botones.
    ("ink", "accent", 4.5, "texto del botón principal"),
    (
        "ink",
        "accent-deep",
        4.5,
        "texto del botón principal al pasar por encima",
    ),
    ("ink", "control", 4.5, "texto del botón secundario"),
    (
        "ink",
        "control-hover",
        4.5,
        "texto del botón secundario al pasar por encima",
    ),
    ("ink-off", "control", 4.5, "texto del botón deshabilitado"),
    // Distintivos.
    ("ink", "danger-fill", 4.5, "texto del distintivo de peligro"),
    ("rail", "warn", 4.5, "texto del distintivo de aviso"),
    ("warn", "card", 4.5, "aviso como texto"),
    ("ok-text", "card", 4.5, "verde como texto"),
    // Marcas finas y componentes (mínimo 3:1).
    ("accent-mark", "card", 3.0, "borde de la opción elegida"),
    ("accent-mark", "ground", 3.0, "barra de progreso"),
    (
        "accent-mark",
        "sunken",
        3.0,
        "barra de progreso sobre su canal",
    ),
    ("danger", "card", 3.0, "punto de peligro"),
    ("ok-text", "card", 3.0, "punto de lo que está bien"),
];

#[test]
fn every_pair_the_interface_uses_reads_at_aa() {
    let theme = tokens();
    let mut failures = Vec::new();

    for (foreground, background, minimum, what) in PAIRS {
        let Some(first) = theme.get(*foreground) else {
            failures.push(format!("falta el token {foreground} ({what})"));
            continue;
        };
        let Some(second) = theme.get(*background) else {
            failures.push(format!("falta el token {background} ({what})"));
            continue;
        };
        let ratio = contrast(*first, *second);
        if ratio < *minimum {
            failures.push(format!(
                "{what}: {foreground} sobre {background} da {ratio:.2}:1 y hacen falta {minimum}:1"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "contraste insuficiente:\n  {}",
        failures.join("\n  ")
    );
}

/// El rojo es de los hallazgos y nunca de un botón (regla 11 de AGENTS.md).
#[test]
fn no_button_uses_a_danger_colour() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ui/app.slint");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("no se pudo leer {}: {error}", path.display()));

    // Un `background` de botón que nombre un color de peligro. Solo dentro del
    // componente del botón: el distintivo del riel sí es rojo (regla 11).
    let mut inside_button = false;
    for (number, line) in source.lines().enumerate() {
        let line = line.trim();
        if line.starts_with("component ") {
            inside_button = line.starts_with("component AppButton");
        }
        let is_button_fill = inside_button
            && line.starts_with("background:")
            && (line.contains("danger") || line.contains("Theme.danger-fill"));
        assert!(
            !is_button_fill,
            "un botón se pinta de rojo en app.slint:{}: {line}",
            number + 1
        );
    }
}
