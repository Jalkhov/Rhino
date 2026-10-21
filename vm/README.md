# Banco de pruebas en Windows

Máquina virtual `MiniOS10`: Windows 10 de 64 bits en español, 4 GB de RAM, 4 vCPU, inicio de
sesión automático y pantalla 1858x940 al 125 %. La cuenta `root` tiene la contraseña `1234`;
eso es lo que desbloquea `guestcontrol` (se puso una vez con `net user root 1234` en una
consola elevada, porque con la contraseña en blanco Windows aplica `LimitBlankPasswordUse` y
`guestcontrol` rechaza cualquier credencial).

Canal con el invitado: la carpeta compartida del host `/home/jalkhov/Descargas/VBOX10/`
aparece dentro como **`Z:`**. Se deja ahí un binario y se lee lo que escriba, sin capturas.
El sitio del host se ve desde el invitado como `http://10.0.2.2:27182/db/stable`.
Lo sirve el servicio de usuario `rhino-web.service`, habilitado y con `Linger=yes`, así que
arranca al iniciar el equipo. Para reinstalarlo:

```sh
cp vm/rhino-web.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now rhino-web.service
```

Nota de `guestcontrol`: con `--exe` **no se repite** el nombre del ejecutable; los argumentos
empiezan en el primero. `--exe cmd.exe -- /c "..."` sí, `--exe cmd.exe -- cmd.exe /c "..."`
no.

## Volcado de accesibilidad

Lo que un lector de pantalla ve de verdad, sin instalar nada: UI Automation viene con .NET
Framework en Windows 10.

```sh
# lanzar la app
VBoxManage guestcontrol MiniOS10 start --username root --password 1234 \
  --exe 'Z:\rhino-app-x86.exe'
sleep 10

# volcar su arbol a Z:\uia.txt
VBoxManage guestcontrol MiniOS10 run --username root --password 1234 \
  --exe 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' --wait-stdout \
  -- -NoProfile -ExecutionPolicy Bypass -File 'Z:\uia.ps1'
```

Sale una línea por control: papel, nombre, habilitado y si está fuera de pantalla. Los
volcados aprobados viven en `vm/uia/` y se comparan con `diff` después de normalizar lo que
cambia con los datos (recuentos, rutas, versiones del paquete).

Antes de probar cambios de interfaz, recompila y copia el binario al canal compartido:

```sh
XWIN_ARCH=x86 cargo xwin build --release -p rhino-app --target i686-pc-windows-msvc
cp target/i686-pc-windows-msvc/release/rhino-app.exe /home/jalkhov/Descargas/VBOX10/rhino-app-x86.exe
```

Para hacerlo todo de una vez, desde la raíz del repositorio:

```sh
./vm/probar-uia.sh
```

El script arranca la VM si está apagada, espera al escritorio, lanza Rhino con la base de
pruebas, ejecuta `uia.ps1`, normaliza el proceso, la posición y la versión del paquete, y
compara contra `vm/uia/inicio.txt`. Si no hay diferencias, imprime `UIA OK`. Al terminar
cierra Rhino, pero deja la VM encendida.

El arranque automático está configurado; si alguien cierra la sesión a mano, la contraseña
sigue siendo `root` / `1234`.

Lo que este volcado **no** prueba: que el teclado recorra los controles en orden ni que el
foco se vea. Eso se comprueba con Tab y Enter de verdad (ver `AGENTS.md` para la receta en
Linux y la sección de arriba para el invitado).
