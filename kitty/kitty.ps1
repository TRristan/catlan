# Kitty para catlan: instalador. catlan lo sirve en /kitty.ps1 con su dirección y su id ya puestos.
# En el PC, PowerShell como administrador:   irm http://catlan:8080/kitty.ps1 | iex
# Instala Kitty (kitty.exe, un programa pequeño que sirve el propio catlan) en Archivos de programa y deja:
#  - una tarea programada (SYSTEM, cada 5 min y al arrancar) que envía el estado del PC: «kitty enviar»;
#  - el gato en la bandeja de cada usuario al iniciar sesión, para avisar a IT y ver cómo va el equipo.
# La clave del equipo va al registro, en HKLM\SOFTWARE\Kitty, solo para SYSTEM y administradores (la misma que el Kitty
# de antes: un PC ya instalado conserva su ficha). La ventana usa otra, que solo sirve para abrir incidencias de este PC.
$ErrorActionPreference = 'Stop' # al primer fallo, parar: nada de «instalado» a medias
$ProgressPreference = 'SilentlyContinue' # la barra de progreso de PowerShell 5 hace lentísima la descarga
$Url = '{{URL}}'
$Catlan = '{{ID}}'
$r = 'HKLM:\SOFTWARE\Kitty'
$dir = Join-Path $env:ProgramFiles 'Kitty'
$pub = Join-Path $env:ProgramData 'Kitty'
$exe = Join-Path $dir 'kitty.exe'
try {
    if (-not (Test-Path $r)) { New-Item $r | Out-Null }
} catch {
    Write-Host "Kitty: no puedo escribir en $r. Abre PowerShell como administrador y vuelve a pegar el comando." -ForegroundColor Red
    return
}
$key = (Get-ItemProperty $r).key
if (-not $key) { # la clave que identifica a este PC ante catlan (dos GUID: 244 bits aleatorios)
    $key = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
    Set-ItemProperty $r key $key
}
try { # quien tenga la clave se hace pasar por este PC: fuera los usuarios normales
    $acl = Get-Acl $r
    $acl.SetSecurityDescriptorSddlForm('O:BAG:SYD:PAI(A;CI;KA;;;SY)(A;CI;KA;;;BA)')
    Set-Acl $r $acl
} catch {
    Write-Host "Kitty: no he podido restringir $r; los usuarios locales podrán leer su clave." -ForegroundColor Yellow
}

# El programa, desde catlan (si ya estaba, se para y se sustituye: así también se actualiza)
New-Item -ItemType Directory -Force $dir, $pub | Out-Null
Get-Process kitty -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exe } | Stop-Process -Force
try {
    Invoke-WebRequest "$Url/kitty.exe" -OutFile "$exe.nuevo" -UseBasicParsing -TimeoutSec 120
    Move-Item -Force "$exe.nuevo" $exe
} catch {
    Remove-Item "$exe.nuevo" -ErrorAction SilentlyContinue
    Write-Host "Kitty: no he podido descargar $Url/kitty.exe ($($_.Exception.Message)). ¿Tiene catlan kitty.exe junto a su ejecutable?" -ForegroundColor Red
    return
}

# Lo que necesita la ventana (la leen los usuarios del PC): dónde está catlan y la clave de incidencias
$cfg = Join-Path $pub 'kitty.json'
$ukey = try { (Get-Content $cfg -Raw | ConvertFrom-Json).ukey } catch { '' }
if (-not $ukey) { $ukey = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N') }
[IO.File]::WriteAllText($cfg, (@{ url = $Url; catlan = $Catlan; ukey = $ukey } | ConvertTo-Json -Compress)) # UTF-8 sin BOM

# Cada 5 minutos y al arrancar, como SYSTEM: el estado del PC
$action = New-ScheduledTaskAction $exe 'enviar'
$triggers = @((New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)), (New-ScheduledTaskTrigger -AtStartup))
$who = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
$set = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
Register-ScheduledTask Kitty -Action $action -Trigger $triggers -Principal $who -Settings $set -Description "Kitty: envía a catlan ($Url) el estado de este PC cada 5 minutos" -Force | Out-Null
# El gato en la bandeja de cada usuario, al iniciar sesión
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' Kitty "`"$exe`" --oculto"
Remove-ItemProperty $r when -ErrorAction SilentlyContinue # para esperar al primer envío de esta instalación
Start-ScheduledTask Kitty
Start-Process explorer.exe "`"$exe`"" # la ventana, ya, como el usuario (no como administrador)

$code = try { $h = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($key)); ('{0:X2}{1:X2}-{2:X2}{3:X2}' -f $h[0], $h[1], $h[2], $h[3]) } catch { '(no disponible)' }
Write-Host "Kitty instalado en $env:COMPUTERNAME (código $code)." -ForegroundColor Green
for ($i = 0; $i -lt 30 -and -not (Get-ItemProperty $r -Name when -ErrorAction SilentlyContinue); $i++) { Start-Sleep 1 }
$st = Get-ItemProperty $r
if ($st.state -eq 'pendiente') { Write-Host "Acéptalo en catlan: Inventario → Kitty pide entrar (código $code)." }
elseif ($st.state -eq 'error') { Write-Host "Primer envío con error: $($st.error)" -ForegroundColor Yellow }
elseif ($st.state) { Write-Host "Primer envío: $($st.state)." }
