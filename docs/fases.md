# Método de trabajo y fases

[← Volver al README](../README.md)
## Método de trabajo

Lo que ha hecho avanzar el proyecto, y conviene no perder:

- **Reglas estáticas antes que memoria.** Cada trampa de Slint que costó una ronda está en
  `AGENTS.md` con su caso y su número, para leerlas antes de dibujar.
- **Medir, no mirar.** Toda comprobación visual se hace midiendo píxeles sobre una captura
  (receta en `AGENTS.md`), y el contraste con una prueba que lee la paleta.
- **Encargos con alcance, firmas esperadas y criterio de aceptación.** Las rebanadas que
  salieron bien fueron las que se podían revisar y verificar por separado.
- **`docs/ESTADO.md`**: una página con qué funciona, qué es maqueta y qué está roto,
  actualizada en cada commit.
- **Fechas**: en disco siempre UTC en ISO 8601; en pantalla `DD-MM-YYYY HH:mm` en hora local.

Y lo que hay que vigilar, porque ya pasó: dar por bueno lo que no se ha probado, y tomar
decisiones de producto (ocultar controles, resumir un número, mover una tarjeta) sin
avisar. Lo que no se ha medido no se afirma.

## Fases

- [x] **Fase 1** — Investigación y decisión de lenguaje (Rust, Slint).
- [x] **Fase 2** — Entorno de compilación cruzada Ubuntu → Windows (i686 y x64) y esqueleto.
- [x] **Fase 3** — Núcleo de escaneo: hashes, YARA-X, heurística PE y paquete firmado.
- [x] **Fase 4** — Interfaz: seis pantallas ancladas en Avira, tipografía incrustada.
- [x] **Fase 5** — Interfaz honesta y completa: datos reales, poner a salvo, historial,
  ajustes, teclado y accesibilidad.
- [x] **Fase 6** — Rendimiento del análisis: cuatro hilos y salto de las reglas en imágenes,
  audio y vídeo. En Linux, 26 s → 11,75 s sobre `/usr/bin`; en Windows, **77,5 archivos por
  segundo** en `C:\Program Files`, con el pico de memoria en 225 MB. El precio es más CPU total.
- [ ] **Fase 7 (la siguiente)** — Protección en tiempo real, en modo usuario y sin driver.
- [~] **Fase 8** — Integridad y cadena de confianza. Hecho: no se instala un paquete más
  antiguo que el instalado (uno viejo, válidamente firmado, apagaría detecciones), y cada
  release publica su SHA-256. Falta: firmar el ejecutable cuando haya programa de firma para
  código abierto, y un plan para la clave privada (rotación y qué hacer si se filtra).

Tareas transversales, que se hacen una vez:

1. **Capturas doradas y galería de componentes.** Un `xtask` que arranque la app, recorra
   pantallas y estados y compare con `compare -metric AE`, más una pantalla `gallery.slint`
   (solo en depuración) con cada componente en cada estado. Todas las trampas de la fase 4
   —el área que colapsaba, la etiqueta descentrada, la tarjeta enorme— son justo lo que esa
   prueba detecta, y el botón terciario que salía azul se habría visto el primer día.
2. **Una pantalla es una matriz de estados**, no una imagen: vacía, cargando, con uno, con
   muchos, sin base y con error. Los tres defectos que sobrevivieron a la fase 4 eran estados
   que nadie había mirado.
3. **Anchos de botón por variante, no a mano.** Hoy hay ocho anchos escritos a mano y la
   aritmética se rehace cada vez que sube la escala tipográfica. Dos o tres variantes
   cerradas con su tabla de anchos revisada una vez.
