# Vuelca el arbol de UI Automation de la ventana de Rhino a texto.
#
# Comprueba lo que un lector de pantalla ve de verdad: papel, nombre y estado de cada
# control. Se ejecuta dentro del invitado y escribe en Z:, la carpeta compartida del host,
# para leerlo sin capturas. Sin instalaciones: UIAutomationClient viene con .NET Framework
# en Windows 10.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File Z:\uia.ps1
#
# Los volcados aprobados viven en vm/uia/ y se comparan con diff.

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

$salida = 'Z:\uia.txt'
$lineas = New-Object System.Collections.Generic.List[string]

# Los procesos de Rhino, en cualquiera de sus dos nombres.
$ids = @()
foreach ($nombre in @('rhino-app-x86', 'rhino-app', 'rhino_app')) {
    foreach ($p in @(Get-Process -Name $nombre -ErrorAction SilentlyContinue)) {
        $ids += $p.Id
    }
}

if ($ids.Count -eq 0) {
    [System.IO.File]::WriteAllText($salida, "NO HAY NINGUN PROCESO DE RHINO EN MARCHA`r`n",
        (New-Object System.Text.UTF8Encoding($false)))
    exit 1
}

$raiz = [System.Windows.Automation.AutomationElement]::RootElement
$hijos = $raiz.FindAll([System.Windows.Automation.TreeScope]::Children,
    [System.Windows.Automation.Condition]::TrueCondition)

$ventana = $null
foreach ($h in $hijos) {
    if ($ids -contains $h.Current.ProcessId) {
        $ventana = $h
        break
    }
}

if ($null -eq $ventana) {
    [System.IO.File]::WriteAllText($salida, "RHINO CORRE PERO NO TIENE VENTANA`r`n",
        (New-Object System.Text.UTF8Encoding($false)))
    exit 2
}

$r = $ventana.Current
$caja = $r.BoundingRectangle
$lineas.Add(("ventana: '{0}' proceso={1} caja={2},{3} {4}x{5}" -f
    $r.Name, $r.ProcessId, [int]$caja.X, [int]$caja.Y, [int]$caja.Width, [int]$caja.Height))
$lineas.Add(("papel= '{0}' clase= '{1}'" -f
    $r.ControlType.ProgrammaticName, $r.ClassName))
$lineas.Add('')

function Escribir($elemento, $nivel) {
    $d = $elemento.Current
    $nombre = $d.Name
    if ($null -eq $nombre) { $nombre = '' }
    $pad = '  ' * $nivel
    $lineas.Add(('{0}{1} "{2}" enabled={3} offscreen={4}' -f
        $pad, $d.ControlType.ProgrammaticName, $nombre, $d.IsEnabled, $d.IsOffscreen))

    $hijos = $elemento.FindAll([System.Windows.Automation.TreeScope]::Children,
        [System.Windows.Automation.Condition]::TrueCondition)
    foreach ($h in $hijos) { Escribir $h ($nivel + 1) }
}

Escribir $ventana 0

[System.IO.File]::WriteAllLines($salida, $lineas, (New-Object System.Text.UTF8Encoding($false)))
Write-Output ("controles: " + ($lineas.Count - 3))
