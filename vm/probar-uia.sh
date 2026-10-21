#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

VM=MiniOS10
SHARED=/home/jalkhov/Descargas/VBOX10
GOLDEN=vm/uia/inicio.txt
TEMPORAL=$(mktemp)
trap 'rm -f "$TEMPORAL"' EXIT

if ! VBoxManage showvminfo "$VM" --machinereadable | grep -q '^VMState="running"'; then
    VBoxManage startvm "$VM" --type headless >/dev/null
fi

for _ in $(seq 1 30); do
    if timeout 8 VBoxManage guestcontrol "$VM" run --username root --password 1234 \
        --wait-stdout -- cmd.exe /c "echo listo" >/dev/null 2>&1; then
        break
    fi
    sleep 3
done

# Espera al escritorio, no solo a que Guest Additions responda.
for _ in $(seq 1 40); do
    if timeout 8 VBoxManage guestcontrol "$VM" run --username root --password 1234 \
        --wait-stdout -- 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' \
        -NoProfile -Command "if (Get-Process explorer -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }" \
        >/dev/null 2>&1; then
        break
    fi
    sleep 3
done

cp vm/uia.ps1 "$SHARED/uia.ps1"

cat > "$SHARED/lanzar.bat" <<'BAT'
@echo off
set RHINO_DB_URL=http://10.0.2.2:27182/db/stable
start "" "Z:\rhino-app-x86.exe"
BAT

timeout 30 VBoxManage guestcontrol "$VM" run --username root --password 1234 \
    --wait-stdout -- cmd.exe /c "taskkill /IM rhino-app-x86.exe /F" >/dev/null 2>&1 || true

timeout 30 VBoxManage guestcontrol "$VM" start --username root --password 1234 \
    --exe 'Z:\lanzar.bat' >/dev/null
sleep 12

timeout 60 VBoxManage guestcontrol "$VM" run --username root --password 1234 \
    --wait-stdout -- 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' \
    -NoProfile -ExecutionPolicy Bypass -File 'Z:\uia.ps1' >/dev/null

python3 - "$SHARED/uia.txt" "$TEMPORAL" <<'PY'
import re
import sys

texto = open(sys.argv[1], encoding='utf-8-sig').read().replace('\r\n', '\n')
texto = re.sub(
    r"ventana: 'Rhino' proceso=\d+ caja=[-\d,]+ \d+x\d+",
    "ventana: 'Rhino'",
    texto,
)
texto = re.sub(r'Protección [0-9.]+ instalada', 'Protección <versión> instalada', texto)
open(sys.argv[2], 'w', encoding='utf-8').write(texto)
PY

diff -u "$GOLDEN" "$TEMPORAL"
echo "UIA OK: $GOLDEN"

timeout 30 VBoxManage guestcontrol "$VM" run --username root --password 1234 \
    --wait-stdout -- cmd.exe /c "taskkill /IM rhino-app-x86.exe /F" >/dev/null 2>&1 || true
