//! Generador de muestras sintéticas para pruebas.
//!
//! Rhino es un escáner estático: nunca ejecuta lo que analiza. Todas las muestras
//! de este módulo se construyen en memoria y son inofensivas, así que el proyecto
//! no necesita descargar ni almacenar malware real para probar el motor
//! (ver "Pruebas" en el README).

/// Contenido exacto del archivo de prueba estándar EICAR (inofensivo).
pub const EICAR_TEXT: &str =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/// Características de una sección `.text` corriente: ejecutable y legible.
pub const CHARACTERISTICS_CODE: u32 = 0x6000_0020;

/// Las mismas, más permiso de escritura (posible automodificación).
pub const CHARACTERISTICS_WRITABLE_CODE: u32 = 0xe000_0020;

/// Archivo de prueba estándar EICAR (inofensivo).
pub fn eicar() -> Vec<u8> {
    EICAR_TEXT.as_bytes().to_vec()
}

/// SHA-256 del archivo de prueba EICAR.
///
/// Es el hash que las pruebas usan para la capa 1, y el paquete de base de datos
/// también lo incluye.
pub fn eicar_sha256() -> String {
    crate::hash::sha256_hex(&eicar())
}

/// Texto corriente que ningún heurístico debería marcar.
pub fn benign_text() -> Vec<u8> {
    b"contenido inofensivo\n".to_vec()
}

/// Imagen PE mínima y válida con las secciones indicadas como
/// `(nombre, características)`.
pub fn pe_with_sections(sections: &[(&str, u32)]) -> Vec<u8> {
    const PE_OFFSET: usize = 0x80;
    const COFF_SIZE: usize = 20;
    const SECTION_SIZE: usize = 40;

    let headers_end = PE_OFFSET + 4 + COFF_SIZE + SECTION_SIZE * sections.len();
    let mut image = vec![0u8; headers_end];

    image[0..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&(PE_OFFSET as u32).to_le_bytes());
    image[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

    let coff = PE_OFFSET + 4;
    image[coff..coff + 2].copy_from_slice(&0x014cu16.to_le_bytes()); // i386
    image[coff + 2..coff + 4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
    image[coff + 16..coff + 18].copy_from_slice(&0u16.to_le_bytes()); // sin cabecera opcional

    for (index, (name, characteristics)) in sections.iter().enumerate() {
        assert!(
            name.len() <= 8,
            "el nombre de una sección PE admite 8 bytes como máximo"
        );
        let entry = coff + COFF_SIZE + index * SECTION_SIZE;
        image[entry..entry + name.len()].copy_from_slice(name.as_bytes());
        image[entry + 36..entry + 40].copy_from_slice(&characteristics.to_le_bytes());
    }

    image
}

/// Imagen PE mínima con una sola sección.
pub fn pe_with_section(name: &str, characteristics: u32) -> Vec<u8> {
    pe_with_sections(&[(name, characteristics)])
}

/// Ejecutable corriente: una sección de código, sin escritura.
pub fn benign_pe() -> Vec<u8> {
    pe_with_section(".text", CHARACTERISTICS_CODE)
}

/// Ejecutable con secciones características de un empaquetador.
pub fn packed_pe() -> Vec<u8> {
    pe_with_sections(&[
        ("UPX0", CHARACTERISTICS_CODE),
        ("UPX1", CHARACTERISTICS_CODE),
    ])
}

/// Ejecutable con una sección ejecutable y escribible a la vez.
pub fn writable_executable_pe() -> Vec<u8> {
    pe_with_section(".text", CHARACTERISTICS_WRITABLE_CODE)
}

/// Cabecera PE cortada: no debe tratarse como ejecutable.
pub fn truncated_pe() -> Vec<u8> {
    b"MZ".to_vec()
}
