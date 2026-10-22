# Pruebas

[← Volver al README](../README.md)
## Pruebas

**120 pruebas** con `cargo test --workspace`: 12 de la aplicación, 2 de contraste, 94 del
núcleo, 6 de propiedades, 5 de integración y 1 del manifiesto del paquete.

- **Unitarias:** obligatorias. Con `#[test]`, junto al código, vía `cargo test`.
- **De integración:** en `tests/`, para la lógica que cruza módulos.
- **End-to-end (e2e):** se entienden como pruebas de integración que ejecutan el motor
  completo sobre un corpus de archivos (benignos y maliciosos conocidos), no como
  automatización de la ventana gráfica. Automatizar la interfaz cuesta mucho y aporta
  poco; se omite por ahora.
- **Corpus sintético:** el módulo `rhino_core::corpus` genera en memoria las muestras que
  ejercitan cada capa (EICAR, PE empaquetado, sección ejecutable-escribible, PE truncado).
  Como Rhino es un escáner *estático* y nunca ejecuta lo que analiza, el proyecto **no
  necesita descargar ni almacenar malware real** para probar el motor.
- **Falsos positivos:** `cargo run -p rhino-core --example scan_dir -- <directorio> [reglas.yar|reglas.yarc]`
  mide la métrica que decide si un antivirus es usable. Con las capas 1 y 3: 0 detecciones
  sobre 2394 binarios de `/usr/bin`. Con el paquete real de YARA Forge (5137 reglas) sale
  **una**: la regla de *hacktool* «socat» marca a `socat1`, una herramienta legítima de
  doble uso. Un falso positivo de la clase esperable, no un fallo del motor.
- **Paquete firmado:** las pruebas cubren lo que de verdad importa de la base de datos:
  firma ausente, firma hecha con otra clave, manifiesto alterado después de firmar y archivo
  alterado con manifiesto válido. Los dos últimos fallan de forma distinta y deliberada
  (`Signature` para la firma, `Corrupt` para el contenido).
- **Interfaz:** `crates/rhino-app/tests/contraste.rs` lee `ui/theme.slint`, comprueba 25 pares
  de color contra AA (4,5:1 para texto, 3:1 para marcas finas) y falla si un botón usa el
  color de hallazgo. El layout no se prueba automáticamente: se mide sobre capturas, con la
  receta de `AGENTS.md`.
- **Accesibilidad:** `vm/uia.ps1` vuelca en el invitado el árbol de UI Automation de la
  ventana, una línea por control con su papel, su nombre y su estado. Es texto, así que se
  compara con `diff` contra los volcados aprobados de `vm/uia/`; el método, en
  `vm/README.md`. Lo que no prueba es el orden del teclado ni el aro de foco: eso se recorre
  con Tab y Enter de verdad.
