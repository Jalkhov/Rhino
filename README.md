# Rhino

Antivirus ligero, rápido y de bajo consumo para Windows, con interfaz intuitiva y gratuito.

## Principio rector

La eficiencia es la característica principal, no una optimización posterior. Rhino debe
ser prácticamente imperceptible en un equipo modesto: **la restricción dura es el consumo
de memoria y de CPU**, no el tamaño. Sin picos de CPU, sin consumo excesivo de RAM y sin
ralentizar el sistema. La funcionalidad se inspira en lo mejor de los antivirus
reconocidos, pero sin su peso.

**El tamaño de los binarios y del paquete de datos no es una restricción.** Un antivirus
potente y de bajo consumo no cabe en 3 MB, y recortar peso a costa de capacidad de
detección sería el error contrario. Lo que no se cruza es la memoria en uso y el tiempo de
CPU; el consumo medido se anota en "Motor de detección y base de datos".

## Plataforma objetivo

- **Mínimo:** Windows 10 de 32 bits (x86) con **4 GB de RAM**.
- **También soportado:** Windows 10/11 de 64 bits (x64).
- **Desarrollo:** Ubuntu, con compilación cruzada hacia Windows.

Los 4 GB son la base de desarrollo (provisional, octubre de 2026). Dejan margen para un
consumo de **100 a 200 MB** en reposo y durante el escaneo, que es el presupuesto que Rhino
se fija. Sin ese mínimo habría que apuntar cada decisión a equipos de 1 GB, y el antivirus
quedaría estrangulado por un objetivo que ya no corresponde a las máquinas reales.

En 32 bits conviene recordar que el sistema operativo solo ve unos 3,2 GB de esos 4 GB y
que **un proceso de 32 bits dispone de ~2 GB de espacio de direcciones**, del que también
sale el archivo mapeado.

### Política de arquitectura

Se diseña **32 bits primero**. Los límites de x86 (espacio de direcciones de 2-3 GB,
`usize` de 32 bits, archivos que no se pueden mapear completos en memoria) son la
línea base, y x64 es un superconjunto de esos límites.

Todo el código específico de arquitectura o de Windows vive en un único módulo
`platform`; el núcleo (motor de firmas, hashes, lógica de escaneo) es agnóstico. La
base de firmas es neutral respecto a la arquitectura y está versionada.

Así, abandonar x86 en una versión futura (planificado para una eventual 2.0, dejando
la última compilación de 32 bits funcionando sin actualizaciones) se reduce a: quitar
el target i686 de la CI, congelar el canal de actualización de 32 bits y borrar el
módulo `platform`. Sin tocar el núcleo.

## Alcance

**Solo modo usuario (user-mode).** Nada de kernel por ahora: ni minifiltros, ni
drivers. Es delicado, requiere firma de drivers y su propio ciclo de desarrollo, y
no aporta al objetivo de eficiencia en esta etapa. Es un tema que podría tocarse muy
a futuro, pero no condiciona ninguna decisión actual.

La protección en tiempo real (Fase 5) se plantea con las capacidades de modo usuario
disponibles, sin driver.

## Lenguaje: Rust

Elegido sobre Go por cuatro razones que atacan directo los objetivos del proyecto:

1. **Eficiencia real:** memoria segura sin recolector de basura. No hay pausas
   *stop-the-world*, lo que importa en un servicio que escanea archivos en tiempo real.
   Huella y latencia predecibles.
2. **Resistencia a ingeniería inversa:** un binario Rust con `strip` + LTO pierde casi
   toda su metadata. Go reconstruye nombres de funciones y tipos desde su propia
   metadata de runtime, lo que facilita revertir el binario. Rust eleva la barrera de
   los intentos más básicos.
3. **Ecosistema de seguridad nativo:** [YARA-X](https://github.com/VirusTotal/yara-x)
   (reescritura de YARA hecha en Rust por VirusTotal, madura y en producción) es el
   motor de firmas de facto y ya está en Rust. Con Go habría que usar CGo, que complica
   la compilación cruzada.
4. **Acceso a Windows:** [`windows-rs`](https://github.com/microsoft/windows-rs), de
   Microsoft, da bindings seguros a toda la API Win32. Y a diferencia de Go, Rust puede
   escribir drivers de kernel (minifiltros) si una fase futura lo requiere.

## Motor de detección y base de datos

**El motor de patrones no se escribe desde cero.** Es
[YARA-X](https://github.com/VirusTotal/yara-x) (licencia BSD-3-Clause), la reescritura
de YARA en Rust que VirusTotal tiene en producción escaneando miles de millones de
archivos. Lo propio de Rhino es el orquestador de escaneo, el formato del paquete de
base de datos, el actualizador, la heurística propia y la interfaz.

### Capas de detección

Las firmas son solo una de varias capas:

| Capa | Qué detecta | Coste | Depende de |
| --- | --- | --- | --- |
| 1. Hash exacto | Malware ya conocido (IOC) | Muy bajo | Listas de hashes |
| 2. Firmas YARA-X | Familias, herramientas de ataque, webshells, exploits | Bajo | YARA Forge |
| 3. Heurística propia | PE anómalo, packers, entropía alta, macros sospechosas | Medio | Solo Rhino |
| 4. Comportamiento (futuro) | Acciones en ejecución, en modo usuario | — | Solo Rhino |
| 5. ML / reputación (futuro) | — | — | — |

La capa 3 es la diferencia real: es la única donde Rhino aporta detección propia y no
depende de terceros.

### De dónde salen las firmas

De **YARA Forge** ([`YARAHQ/yara-forge`](https://github.com/YARAHQ/yara-forge)), un
proyecto que recolecta reglas de más de 45 repositorios de seguridad, las normaliza, las
prueba contra falsos positivos, las puntúa (0–100) y publica **paquetes semanales** en
tres niveles: `core` (alta calidad, bajo falso positivo), `extended` y `full`. Es lo que
usan productos comerciales como THOR.

Un trabajo automático en la CI haría el resto: descargar el release semanal, filtrar las
reglas con licencia copyleft, compilar con `yr compile`, armar el paquete, firmarlo y
publicarlo. Sin trabajo manual y sin laboratorio de malware propio.

### Licencias

Se consumen **solo fuentes permisivas**: YARA Forge `core` (mezcla de DRL 1.1, BSD y
Apache 2.0), y repositorios como Signature Base y SEKOIA.IO (DRL 1.1, que permite el uso
comercial con atribución). Quedan descartadas las reglas GPL (Yara-Rules/rules, CAPE
Sandbox) y la base de datos de ClamAV (GPL), que obligarían a que todo Rhino fuese GPL y
enredarían la compatibilidad con Slint (GPLv3 o comercial).

Esto mantiene a Rhino libre para ser abierto o cerrado cuando se decida.

**Consecuencia obligatoria:** la licencia DRL 1.1 exige que el mensaje de detección
nombre al autor de la regla. La interfaz debe poder mostrar *"Detectado por la regla X,
autor Y, fuente Z"*.

### Paquete de base de datos

```
rhino-db-AAAA.MM.DD/
  manifest.json   versión, fecha, canal, conteos y hash de cada archivo
  meta.json       por regla: autor, fuente, licencia, URL original
  rules.yarc      reglas YARA-X precompiladas
  hashes.bin      hashes conocido-malo (capa 1)
  manifest.sig    firma Ed25519 del manifest
```

Las reglas se compilan **una sola vez, en la CI**, nunca en el equipo del usuario:
compilar miles de reglas al arrancar cuesta segundos y mucha memoria en una máquina
modesta, mientras que cargar un archivo precompilado cuesta casi nada. El paquete va
firmado con Ed25519 (clave pública dentro de Rhino, privada solo en los secretos de la
CI): sin esa firma, quien intercepte una actualización podría apagar el antivirus.

El paquete es neutral respecto a la arquitectura; la actualización se sirve por canales
separados por arquitectura, según la política de arquitectura.

Medición real del paquete `core` (octubre de 2026): **5137 reglas**, que tardan unos 3 s
en compilar y ocupan **8,5 MB** ya compiladas.

### Consumo medido

Ruta de producción (`.yarc`, `RuleSet::from_compiled`), con el paquete `core` completo,
medido con `/usr/bin/time -v`:

| Escenario | RAM máxima |
| --- | --- |
| Capas 1 y 3, sin reglas | 11 MB |
| Con las 5137 reglas cargadas | 63 MB |
| Más un archivo de 512 MB | 115 MB |
| Compilando esas reglas en el equipo del usuario | 238 MB |

El conjunto cargado ocupa unos **52 MB**, y ahí está el argumento definitivo para
precompilar en la CI: hacerlo en el equipo del usuario no solo cuesta segundos, cuesta
unos 180 MB más de RAM. Los archivos grandes se leen con memoria mapeada (por encima de
32 MB), que es paginada del sistema de archivos y el sistema operativo puede reclamar: no
presiona la memoria como lo haría un `Vec`.

Escanear `/usr/bin` (2394 archivos) tarda 26 s con reglas y 9 s sin ellas.

El peor caso medido (115 MB) entra en el presupuesto de 100–200 MB que fijan los requisitos
mínimos, aunque cerca del límite.

## Interfaz gráfica: Slint

Elegida sobre `egui`, `iced` y las alternativas basadas en web:

- Se compila AOT a código nativo: sin intérprete, sin webview y sin recolector de basura.
- Tiene **renderizador por software** (CPU, sin GPU ni OpenGL), ideal para equipos
  modestos o con drivers gráficos malos. Se fuerza con `SLINT_BACKEND=winit-software`.
- Su huella es mínima (el framework está diseñado para embebidos).
- Es gratis para aplicaciones de escritorio (licencia *royalty-free*; también
  disponible bajo GPLv3 o comercial).

Descartadas: `egui` (modo inmediato, redibuja de más y requiere OpenGL), `iced`
(requiere GPU) y Tauri/Electron (meten un motor de navegador en RAM, contra el objetivo
de eficiencia).

La interfaz vive en su propio crate (`rhino-app`), desacoplada del núcleo
(`rhino-core`), para poder cambiarla sin tocar la lógica.

## Pruebas

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
- **Falsos positivos:** `cargo run -p rhino-core --example scan_dir -- <directorio> [reglas.yar]`
  mide la métrica que decide si un antivirus es usable. Con las capas 1 y 3: 0 detecciones
  sobre 2394 binarios de `/usr/bin`. Con el paquete real de YARA Forge (5137 reglas) sale
  **una**: la regla de *hacktool* «socat» marca a `socat1`, una herramienta legítima de
  doble uso. Un falso positivo de la clase esperable, no un fallo del motor.

## Estado

**Fase 1 (investigación) — completada.** Lenguaje: Rust. Interfaz: Slint.

**Fase 2 (entorno y esqueleto) — completada.** Workspace de Cargo con `rhino-core`
(núcleo agnóstico) y `rhino-app` (interfaz Slint), con pruebas unitarias. Compilación
cruzada a `i686-pc-windows-msvc` operativa y verificada (el binario resultante es un
PE32 de GUI para i386). Repositorio publicado en privado.

**Fase 3 (motor de escaneo) — en curso.** Arquitectura de detección y base de datos
definidas en la sección "Motor de detección y base de datos".

Primera rebanada, ya funcionando:

- `rhino-core`: hashing SHA-256 por *streaming* (búfer fijo de 64 KiB) y lector mínimo de
  cabeceras PE con lecturas acotadas. La capa de reglas recibe la **ruta**, no los bytes:
  el motor decide entre leer y mapear, con un tope de 64 MB por archivo. Ninguna capa carga
  el archivo completo en memoria.
- `scan()` devuelve un informe estructurado (`ScanReport`) con el veredicto y la lista de
  hallazgos, y **nombra la capa** que detectó cada uno: capa 1 (hash conocido), capa 2
  (reglas YARA-X) y capa 3 (heurística propia: secciones de empaquetador y secciones
  ejecutables-escribibles).
- Motor YARA-X integrado (`RuleSet::compile` / `RuleSet::from_compiled`, este último para
  las reglas precompiladas) con solo los módulos que el ruleset real usa. Cada hallazgo de
  regla lleva autor y URL de origen, que es lo que exige la licencia DRL 1.1.
- La ventana ya escanea de verdad: se escribe una ruta, el análisis corre en un hilo
  aparte (la ventana no se congela) y el resultado aparece en pantalla.
- `scan_dir()` recorre un directorio completo sin seguir enlaces simbólicos y omitiendo lo
  ilegible; el ejemplo `scan_dir` mide falsos positivos y consumo sobre binarios reales y
  acepta un `.yar`, un `.yarc` ya compilado o ninguno.
- Corpus sintético reutilizable en `rhino_core::corpus`, compartido por las pruebas
  unitarias y las de integración.
- Pruebas: 34 en total. Unitarias, más integración sobre archivos reales en disco,
  incluidos el archivo de prueba EICAR (inofensivo) y ejecutables sintéticos.

Pendiente de esta fase: más heurísticas (entropía, macros), el paquete de base de datos
firmado con su actualizador y el trabajo automático que lo construye. Al armar el paquete
conviene filtrar las reglas por etiqueta `FILE`: las etiquetadas `MEMORY` y `LOG` no
aplican a archivos en disco, y hay 627 reglas sin etiqueta ninguna cuya eliminación hay
que decidir con cuidado, porque perdería detecciones.

## Compilación cruzada

Desde Ubuntu, con `cargo-xwin` (target MSVC de Microsoft, que Rust mantiene en Tier 1
para 32 bits) más `clang-cl` y `lld-link`:

```sh
XWIN_ARCH=x86 cargo xwin build --release --target i686-pc-windows-msvc
```

`XWIN_ARCH=x86` es obligatorio: el default de `cargo-xwin` no descarga las librerías de
32 bits. Requiere `cargo install cargo-xwin` y un `lld-link` en el PATH (`rust-lld`
sirve, enlazado con ese nombre). La primera compilación descarga el SDK de Windows
(~1 GB) y queda en caché.

## Entorno de OpenCode

`opencode.jsonc` declara los MCP útiles para el proyecto: `context-mode`,
`ddg-search`, `rea` (ingeniería inversa) y `context7` (documentación de librerías).

## Fases (tentativo, sin apurar)

- [x] Fase 1 — Investigación y decisión de lenguaje (Rust, Slint).
- [x] Fase 2 — Entorno de compilación cruzada Ubuntu → Windows (i686 y x64) y esqueleto del proyecto.
- [ ] Fase 3 — Núcleo de escaneo (hashes, motor YARA-X, heurística propia y paquete de base de datos).
- [ ] Fase 4 — Interfaz de usuario intuitiva y liviana.
- [ ] Fase 5 — Protección en tiempo real en modo usuario (sin driver).
- [ ] Fase 6 — Endurecimiento anti-ingeniería-inversa y empaquetado.

## Riesgos conocidos

- **El conjunto de reglas cargado cuesta unos 52 MB de RAM**, y crece con el número de
  reglas que se empaqueten. Es hoy el mayor consumidor de memoria de Rhino y lo que decide
  qué tiers de YARA Forge caben en el presupuesto de 100–200 MB.
- **Windows 10 de 32 bits está al final de su vida (EOL desde octubre de 2025).** Es la
  plataforma mínima pedida, así que se soporta, pero conviene saberlo.
- **Rust está degradando los objetivos i686:** desde Rust 1.100 solo se distribuye la
  *std*, no las herramientas de compilación en 32 bits. Los binarios de 32 bits se
  siguen construyendo, pero hay que **compilar cruzado desde Linux/64 bits** (que es
  justo el plan de desarrollo definido).
- La mitigación de ingeniería inversa es una barrera, no una garantía: ningún lenguaje
  vuelve un binario irrevertible.
