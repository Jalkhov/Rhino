//! Lector mínimo de cabeceras PE (Portable Executable).
//!
//! Solo lee cabeceras y con lecturas acotadas: nunca recorre los datos de las
//! secciones. Así el coste no depende del tamaño del archivo y el consumo de
//! memoria es fijo, que es la condición para funcionar bien en 32 bits.

use std::io::{self, Read, Seek, SeekFrom};

const DOS_MAGIC: &[u8; 2] = b"MZ";
const PE_SIGNATURE: &[u8; 4] = b"PE\0\0";

/// Tope de secciones que aceptamos leer. Un PE real rara vez pasa de ~10; el
/// tope evita que una cabecera manipulada nos haga reservar memoria de más.
const MAX_SECTIONS: u16 = 96;

const SECTION_MEM_EXECUTE: u32 = 0x2000_0000;
const SECTION_MEM_WRITE: u32 = 0x8000_0000;

/// Nombres de sección típicos de empaquetadores y compresores de ejecutables.
pub const PACKER_SECTION_NAMES: &[&str] = &[
    "UPX0", "UPX1", "UPX2", ".UPX0", ".UPX1", ".aspack", ".ASPack", ".adata", ".themida", ".vmp0",
    ".vmp1", ".mpress1", ".mpress2", ".petite", ".nsp0", ".nsp1", ".enigma1", ".enigma2", "FSG!",
];

/// Cabecera de un ejecutable PE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeFile {
    pub machine: u16,
    pub sections: Vec<PeSection>,
}

/// Entrada de la tabla de secciones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeSection {
    pub name: String,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

impl PeSection {
    pub fn is_executable(&self) -> bool {
        self.characteristics & SECTION_MEM_EXECUTE != 0
    }

    pub fn is_writable(&self) -> bool {
        self.characteristics & SECTION_MEM_WRITE != 0
    }
}

impl PeFile {
    /// Nombre legible de la arquitectura para la que se compiló el ejecutable.
    pub fn machine_name(&self) -> &'static str {
        match self.machine {
            0x014c => "i386",
            0x8664 => "x86-64",
            0x01c4 => "ARM",
            0xaa64 => "ARM64",
            0x0200 => "Itanium",
            _ => "arquitectura desconocida",
        }
    }

    /// Secciones cuyo nombre delata un empaquetador.
    pub fn packer_sections(&self) -> Vec<&PeSection> {
        self.sections
            .iter()
            .filter(|section| is_packer_section_name(&section.name))
            .collect()
    }

    /// Secciones ejecutables y escribibles a la vez (posible automodificación).
    pub fn writable_executable_sections(&self) -> Vec<&PeSection> {
        self.sections
            .iter()
            .filter(|section| section.is_executable() && section.is_writable())
            .collect()
    }
}

/// ¿El nombre corresponde a una sección de empaquetador conocida?
pub fn is_packer_section_name(name: &str) -> bool {
    PACKER_SECTION_NAMES
        .iter()
        .any(|known| known.eq_ignore_ascii_case(name))
}

/// Lee las cabeceras de un PE.
///
/// Devuelve `Ok(None)` cuando el archivo no es un PE (o está truncado), que es
/// un resultado normal, no un error.
pub fn parse<R: Read + Seek>(reader: &mut R) -> io::Result<Option<PeFile>> {
    let mut dos_header = [0u8; 64];
    if !read_exact_or_eof(reader, &mut dos_header)? {
        return Ok(None);
    }
    if &dos_header[0..2] != DOS_MAGIC {
        return Ok(None);
    }

    let pe_offset = u32::from_le_bytes(dos_header[0x3c..0x40].try_into().unwrap());
    reader.seek(SeekFrom::Start(u64::from(pe_offset)))?;

    let mut signature = [0u8; 4];
    if !read_exact_or_eof(reader, &mut signature)? || &signature != PE_SIGNATURE {
        return Ok(None);
    }

    let mut header = [0u8; 20];
    if !read_exact_or_eof(reader, &mut header)? {
        return Ok(None);
    }
    let machine = u16::from_le_bytes(header[0..2].try_into().unwrap());
    let section_count = u16::from_le_bytes(header[2..4].try_into().unwrap());
    let optional_size = u16::from_le_bytes(header[16..18].try_into().unwrap());

    // Solo nos interesa el tamaño de la cabecera opcional, para saltarla.
    reader.seek(SeekFrom::Current(i64::from(optional_size)))?;

    let mut sections = Vec::new();
    for _ in 0..section_count.min(MAX_SECTIONS) {
        let mut raw = [0u8; 40];
        if !read_exact_or_eof(reader, &mut raw)? {
            break;
        }
        sections.push(PeSection {
            name: section_name(&raw[0..8]),
            virtual_size: u32::from_le_bytes(raw[8..12].try_into().unwrap()),
            raw_size: u32::from_le_bytes(raw[16..20].try_into().unwrap()),
            characteristics: u32::from_le_bytes(raw[36..40].try_into().unwrap()),
        });
    }

    Ok(Some(PeFile { machine, sections }))
}

/// Nombre de sección: 8 bytes terminados en cero o rellenos de cero.
fn section_name(raw: &[u8]) -> String {
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

/// Como `read_exact`, pero distingue "archivo truncado" (`false`) de un fallo real.
fn read_exact_or_eof<R: Read>(reader: &mut R, buffer: &mut [u8]) -> io::Result<bool> {
    match reader.read_exact(buffer) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::{CHARACTERISTICS_CODE, CHARACTERISTICS_WRITABLE_CODE, pe_with_section};
    use proptest::prelude::*;
    use std::io::Cursor;

    /// Desplazamiento del contador de secciones dentro de la imagen sintética:
    /// cabecera DOS (0x3c guarda el offset del PE), firma "PE\0\0" y los dos
    /// primeros bytes de la cabecera COFF, que son `machine`.
    const SECTION_COUNT_OFFSET: usize = 0x80 + 4 + 2;

    #[test]
    fn parses_a_minimal_pe_image() {
        let image = pe_with_section(".text", CHARACTERISTICS_CODE);
        let parsed = parse(&mut Cursor::new(&image))
            .unwrap()
            .expect("debería ser un PE");

        assert_eq!(parsed.machine, 0x014c);
        assert_eq!(parsed.machine_name(), "i386");
        assert_eq!(parsed.sections.len(), 1);
        assert_eq!(parsed.sections[0].name, ".text");
        assert!(parsed.sections[0].is_executable());
        assert!(!parsed.sections[0].is_writable());
    }

    #[test]
    fn text_file_is_not_a_pe() {
        let parsed = parse(&mut Cursor::new(b"hola mundo")).unwrap();
        assert_eq!(parsed, None);
    }

    #[test]
    fn truncated_image_is_not_a_pe() {
        let parsed = parse(&mut Cursor::new(b"MZ")).unwrap();
        assert_eq!(parsed, None);
    }

    #[test]
    fn detects_packer_sections_by_name() {
        let image = pe_with_section("UPX0", CHARACTERISTICS_CODE);
        let parsed = parse(&mut Cursor::new(&image)).unwrap().unwrap();
        assert_eq!(parsed.packer_sections().len(), 1);
    }

    #[test]
    fn detects_writable_and_executable_sections() {
        let image = pe_with_section(".text", CHARACTERISTICS_WRITABLE_CODE);
        let parsed = parse(&mut Cursor::new(&image)).unwrap().unwrap();
        assert_eq!(parsed.writable_executable_sections().len(), 1);
        assert!(parsed.packer_sections().is_empty());
    }

    #[test]
    fn packer_names_are_case_insensitive() {
        assert!(is_packer_section_name("upx1"));
        assert!(is_packer_section_name(".Aspack"));
        assert!(!is_packer_section_name(".text"));
    }

    // El motor come archivos hostiles: ninguna entrada puede hacer entrar en
    // pánico al lector. La lección viene del historial de CVE de ClamAV, donde
    // los fallos graves están en los parsers, no en el motor de firmas.
    proptest! {
        #[test]
        fn parsing_arbitrary_bytes_never_panics(
            image in proptest::collection::vec(any::<u8>(), 0..4096),
        ) {
            let _ = parse(&mut Cursor::new(&image));
        }

        /// Empezando de una imagen válida, que es donde el atacante tiene el
        /// control real: el offset de la cabecera y las secciones.
        #[test]
        fn mutating_a_valid_image_never_panics(
            mutations in proptest::collection::vec((any::<usize>(), any::<u8>()), 0..64),
        ) {
            let mut image = pe_with_section(".text", CHARACTERISTICS_CODE);
            let length = image.len();
            for (position, byte) in mutations {
                image[position % length] = byte;
            }
            let _ = parse(&mut Cursor::new(&image));
        }

        /// Por muchas secciones que declare la cabecera, nunca reservamos
        /// memoria por encima del tope.
        #[test]
        fn never_reads_more_than_the_section_limit(
            declared in any::<u16>(),
            filler in proptest::collection::vec(any::<u8>(), 0..8192),
        ) {
            let mut image = pe_with_section(".text", CHARACTERISTICS_CODE);
            image[SECTION_COUNT_OFFSET..SECTION_COUNT_OFFSET + 2]
                .copy_from_slice(&declared.to_le_bytes());
            image.extend_from_slice(&filler);

            if let Some(pe) = parse(&mut Cursor::new(&image)).unwrap() {
                prop_assert!(pe.sections.len() <= MAX_SECTIONS as usize);
            }
        }
    }
}
