# Kitty para catlan: instalador. catlan lo sirve en /kitty.ps1 con su dirección y su id ya puestos.
# En el PC, PowerShell como administrador:   irm http://catlan:8080/kitty.ps1 | iex
# Deja una tarea programada (SYSTEM, cada 5 min y al arrancar) con el script en línea: ningún archivo en el equipo.
# Su clave y su último estado van al registro, en HKLM\SOFTWARE\Kitty, solo para SYSTEM y administradores.
$ErrorActionPreference = 'Stop' # al primer fallo, parar: nada de «instalado» a medias
$Url = '{{URL}}'
$Catlan = '{{ID}}'
$r = 'HKLM:\SOFTWARE\Kitty'
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

# Lo que corre cada 5 minutos: lo justo para ver fallos (nada de usuarios, programas, procesos ni archivos).
# Solo cmdlets y tipos básicos: funciona también con PowerShell en modo de lenguaje restringido.
$agent = @'
$ErrorActionPreference = 'Stop'
$r = 'HKLM:\SOFTWARE\Kitty'
function Note($state, $err) {
    Set-ItemProperty $r state $state
    Set-ItemProperty $r when (Get-Date -Format s)
    Set-ItemProperty $r error "$err"
}
try {
    $os = Get-CimInstance Win32_OperatingSystem
    $cpu = @(Get-CimInstance Win32_Processor)
    $cs = Get-CimInstance Win32_ComputerSystem
    $serial = "$((Get-CimInstance Win32_BIOS).SerialNumber)".Trim()
    if (@('0', 'none', 'default string', 'to be filled by o.e.m.', 'system serial number', 'not specified', 'not applicable') -contains $serial.ToLower()) { $serial = '' }
    $facts = @{
        osver = "$($os.Caption) $($os.Version)".Trim()
        model = "$($cs.Manufacturer) $($cs.Model)".Trim()
        cpu = "$($cpu[0].Name)".Trim()
        cores = [int]($cpu | Measure-Object NumberOfLogicalProcessors -Sum).Sum
        load = [double]($cpu | Measure-Object LoadPercentage -Average).Average
        mem_total = [int64]$os.TotalVisibleMemorySize * 1024
        mem_free = [int64]$os.FreePhysicalMemory * 1024
        uptime = [int64]((Get-Date) - $os.LastBootUpTime).TotalSeconds
        serial = $serial
        disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { @{ name = $_.DeviceID; total = [int64]$_.Size; free = [int64]$_.FreeSpace } })
        ips = @(Get-NetIPAddress -AddressState Preferred | Where-Object { $_.IPAddress -notmatch '^(127\.|::1$|fe80:)' } | ForEach-Object { $_.IPAddress })
    }
    # ip vacía: catlan pone la dirección desde la que llega
    $body = @{ key = (Get-ItemProperty $r).key; name = $env:COMPUTERNAME; ip = ''; serial = $serial; os = "windows/$($env:PROCESSOR_ARCHITECTURE.ToLower())"; kind = 'pc'; every = 5; facts = $facts } | ConvertTo-Json -Depth 4 -Compress
    $res = Invoke-RestMethod "$Url/api/agent" -Method Post -Body $body -ContentType 'application/json; charset=utf-8' -TimeoutSec 20 -UseBasicParsing
    if ($res.catlan -ne $Catlan) { throw "$Url no es el catlan que lo instaló" } # atado: no habla con ningún otro
    Note $res.state ''
} catch {
    Note 'error' $_.Exception.Message
}
'@
$agent = "`$Url = '$Url'`n`$Catlan = '$Catlan'`n" + $agent
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($agent))
$action = New-ScheduledTaskAction powershell.exe "-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand $enc"
$triggers = @((New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)), (New-ScheduledTaskTrigger -AtStartup))
$who = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
$set = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
Register-ScheduledTask Kitty -Action $action -Trigger $triggers -Principal $who -Settings $set -Description "Kitty: envía a catlan ($Url) el estado de este PC cada 5 minutos" -Force | Out-Null
Remove-ItemProperty $r when -ErrorAction SilentlyContinue # para esperar al primer envío de esta instalación
Start-ScheduledTask Kitty

$code = try { $h = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($key)); ('{0:X2}{1:X2}-{2:X2}{3:X2}' -f $h[0], $h[1], $h[2], $h[3]) } catch { '(no disponible)' }
Write-Host "Kitty instalado en $env:COMPUTERNAME (código $code)." -ForegroundColor Green
for ($i = 0; $i -lt 15 -and -not (Get-ItemProperty $r -Name when -ErrorAction SilentlyContinue); $i++) { Start-Sleep 1 }
$st = Get-ItemProperty $r
if ($st.state -eq 'pendiente') { Write-Host "Acéptalo en catlan: Inventario → Kitty pide entrar (código $code)." }
elseif ($st.state -eq 'error') { Write-Host "Primer envío con error: $($st.error)" -ForegroundColor Yellow }
elseif ($st.state) { Write-Host "Primer envío: $($st.state)." }
