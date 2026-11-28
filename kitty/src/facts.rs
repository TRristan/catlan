//! Lo que Kitty cuenta de su equipo: lo justo para ver fallos. Nada de usuarios, procesos ni archivos; los programas
//! instalados, solo si la política de catlan lo pide.
use serde_json::{Value, json};
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use sysinfo::{Disks, Networks, System};

/// Discos locales: «C:» en Windows (como el Kitty de PowerShell, así las gráficas de catlan siguen igual).
fn disks() -> Vec<Value> {
    let mut seen = std::collections::HashSet::new();
    Disks::new_with_refreshed_list()
        .iter()
        .filter(|d| !d.is_removable() && d.total_space() > 0)
        .filter_map(|d| {
            let m = d.mount_point().to_string_lossy().to_string();
            let name = if cfg!(windows) { m.trim_end_matches('\\').to_string() } else { m };
            seen.insert(name.clone()).then(|| json!({"name": name, "total": d.total_space(), "free": d.available_space()}))
        })
        .collect()
}

fn ips() -> Vec<String> {
    let mut out: Vec<String> = Networks::new_with_refreshed_list()
        .values()
        .flat_map(|n| n.ip_networks().iter().map(|i| i.addr))
        .filter(|a| !a.is_loopback() && !a.is_unspecified() && !matches!(a, std::net::IpAddr::V6(v) if (v.segments()[0] & 0xffc0) == 0xfe80))
        .map(|a| a.to_string())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// MAC de las tarjetas con IP, para encender el PC desde catlan (Wake-on-LAN).
fn macs() -> Vec<String> {
    let mut out: Vec<String> = Networks::new_with_refreshed_list()
        .values()
        .filter(|n| n.ip_networks().iter().any(|i| !i.addr.is_loopback()))
        .map(|n| n.mac_address().to_string())
        .filter(|m| m != "00:00:00:00:00:00")
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Actualizaciones de Windows pendientes (None: aún no se ha mirado). Las busca `pending_start` cada 6 horas.
static PENDING: std::sync::Mutex<Option<i64>> = std::sync::Mutex::new(None);

/// El hilo que pregunta a Windows Update cuántas faltan (tarda minutos: no puede frenar los envíos).
pub fn pending_start() {
    if !cfg!(windows) {
        return;
    }
    std::thread::spawn(|| {
        loop {
            const PS_PENDING: &str = "[Console]::OutputEncoding = [Text.Encoding]::UTF8
(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search(\"IsInstalled=0 and IsHidden=0 and Type='Software'\").Updates.Count";
            if let Some(n) = powershell(PS_PENDING, Duration::from_secs(900)).ok().and_then(|o| o.trim().parse::<i64>().ok()) {
                *PENDING.lock().unwrap_or_else(|e| e.into_inner()) = Some(n);
            }
            std::thread::sleep(Duration::from_secs(6 * 3600));
        }
    });
}

pub fn name() -> String {
    std::env::var("COMPUTERNAME").ok().filter(|n| !n.is_empty()).or_else(System::host_name).unwrap_or_else(|| "equipo".into())
}

/// Para la ventana: carga, memoria y discos de ahora mismo (sin PowerShell: cada 2 s).
pub fn stats(sys: &mut System) -> Value {
    sys.refresh_cpu_usage();
    sys.refresh_memory();
    json!({"name": name(), "os": System::long_os_version().unwrap_or_default(), "uptime": System::uptime(),
           "cpu": sys.global_cpu_usage().round(), "mem_total": sys.total_memory(), "mem_used": sys.total_memory().saturating_sub(sys.available_memory()),
           "disks": disks(), "ips": ips()})
}

/// Programas instalados, como en «Aplicaciones instaladas»: el registro de desinstalación de la máquina (64 y 32 bits)
/// y el de cada usuario con sesión cargada (los que se instalan sin administrador). Sin componentes del sistema ni parches.
/// shortcut: los portables (AnyDesk sin instalar) y las apps de la Tienda no salen; leer Prefetch o Appx si hace falta.
#[cfg(windows)]
pub fn software() -> Vec<Value> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_LOCAL_MACHINE, HKEY_USERS};
    const U: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";
    let mut roots: Vec<(RegKey, String)> =
        vec![(RegKey::predef(HKEY_LOCAL_MACHINE), U.into()), (RegKey::predef(HKEY_LOCAL_MACHINE), r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall".into())];
    let users: Vec<String> = RegKey::predef(HKEY_USERS).enum_keys().flatten().filter(|s| !s.ends_with("_Classes")).collect();
    roots.extend(users.into_iter().map(|s| (RegKey::predef(HKEY_USERS), format!(r"{s}\{U}"))));
    let mut out: Vec<(String, String, String)> = Vec::new();
    for (root, path) in roots {
        let Ok(k) = root.open_subkey(&path) else { continue };
        for sub in k.enum_keys().flatten() {
            let Ok(e) = k.open_subkey(&sub) else { continue };
            let s = |n: &str| e.get_value::<String, _>(n).unwrap_or_default().trim().to_string();
            if e.get_value::<u32, _>("SystemComponent").unwrap_or(0) == 1 || !s("ParentKeyName").is_empty() || s("DisplayName").is_empty() {
                continue;
            }
            out.push((s("DisplayName"), s("DisplayVersion"), s("Publisher")));
        }
    }
    out.sort();
    out.dedup();
    out.into_iter().map(|(n, v, p)| json!({"name": n, "version": v, "publisher": p})).collect()
}

#[cfg(not(windows))]
pub fn software() -> Vec<Value> {
    Vec::new()
}

/// Ejecuta PowerShell con un tiempo máximo y devuelve lo que escribe.
fn powershell(script: &str, max: Duration) -> Result<String, String> {
    let utf16: Vec<u8> = script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let mut cmd = Command::new("powershell.exe");
    cmd.args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &b64(&utf16)]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // sin ventana de consola
    }
    let mut child = cmd.spawn().map_err(|e| format!("no se pudo abrir PowerShell: {e}"))?;
    let mut out = child.stdout.take().ok_or("sin salida de PowerShell")?;
    let reader = std::thread::spawn(move || {
        let mut s = Vec::new();
        let _ = out.read_to_end(&mut s); // en otro hilo: una salida grande no bloquea la espera
        s
    });
    let t0 = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if t0.elapsed() < max => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("PowerShell tardó demasiado".into());
            }
        }
    }
    Ok(String::from_utf8_lossy(&reader.join().unwrap_or_default()).into_owned())
}

pub fn b64(b: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            s.push(if i <= c.len() { A[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    s
}

/// shortcut: sistema, modelo, nº de serie y Visor de eventos salen de PowerShell (Get-CimInstance, Get-WinEvent), como en el
/// Kitty de antes; pasar a la API de Windows (WMI, EvtQuery) si hace falta prescindir de PowerShell.
const PS: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$now = Get-Date -Format s
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$serial = "$((Get-CimInstance Win32_BIOS).SerialNumber)".Trim()
if (@('0', 'none', 'default string', 'to be filled by o.e.m.', 'system serial number', 'not specified', 'not applicable') -contains $serial.ToLower()) { $serial = '' }
$from = if ($since) { [datetime]$since } else { (Get-Date).AddDays(-1) }
$events = @()
try {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System', 'Application'; Level = 1, 2; StartTime = $from } -MaxEvents 20 -ErrorAction SilentlyContinue | ForEach-Object {
        $m = ("$($_.Message)" -replace '(?i)\\Users\\[^\\\s]+', '\Users\(usuario)' -replace '\s+', ' ').Trim()
        @{ rec = [int64]$_.RecordId; log = $_.LogName; time = $_.TimeCreated.ToUniversalTime().ToString('s') + 'Z'; level = [int]$_.Level; source = "$($_.ProviderName)"; code = [int]$_.Id; msg = $m.Substring(0, [Math]::Min(400, $m.Length)) }
    })
} catch {}
# parches: el último instalado y si Windows espera un reinicio (los pendientes, aparte: buscarlos tarda minutos)
$patch = @{ reboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') }
try { $hf = Get-HotFix -ErrorAction SilentlyContinue | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1; if ($hf) { $patch.last = $hf.InstalledOn.ToString('yyyy-MM-dd'); $patch.kb = "$($hf.HotFixID)" } } catch {}
# seguridad: antivirus, BitLocker en el disco del sistema, firewall y la cuenta Administrador de serie
$sec = @{}
try { $mp = Get-MpComputerStatus -ErrorAction Stop; $sec.defender = [bool]($mp.AntivirusEnabled -and $mp.RealTimeProtectionEnabled); $sec.sigdays = [int]$mp.AntivirusSignatureAge } catch {}
try { $sec.av = @(Get-CimInstance -Namespace root/SecurityCenter2 AntiVirusProduct -ErrorAction Stop | Where-Object { ($_.productState -band 0x1000) -and $_.displayName -notmatch 'Defender' } | ForEach-Object { "$($_.displayName)" }) } catch {}
try { $sec.bitlocker = [int](Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop).ProtectionStatus } catch {}
try { $sec.fwoff = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { -not $_.Enabled } | ForEach-Object { "$($_.Name)" }) } catch {}
try { $sec.admin = [bool](Get-LocalUser -ErrorAction Stop | Where-Object { "$($_.SID)" -like '*-500' }).Enabled } catch {}
@{ now = $now; osver = "$($os.Caption) $($os.Version)".Trim(); model = "$($cs.Manufacturer) $($cs.Model)".Trim(); serial = $serial; events = $events; patch = $patch; sec = $sec } | ConvertTo-Json -Depth 4 -Compress
"#;

/// Lo lento (PowerShell, un par de segundos): sistema, modelo, nº de serie y eventos desde `since`. {} si falla.
pub fn slow(since: Option<&str>) -> Value {
    if cfg!(windows) {
        let since = since.filter(|s| s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-:T. ".contains(&b))).unwrap_or("");
        powershell(&format!("$since = '{since}'\n{PS}"), Duration::from_secs(60)).ok().and_then(|o| serde_json::from_str::<Value>(o.trim()).ok())
    } else {
        None
    }
    .unwrap_or(json!({}))
}

/// Todo lo que va a catlan: (facts, nº de serie, eventos, la hora local de `ps` para el próximo `since`).
/// `ps` es lo de `slow`; si no es `fresh` (reaprovechado de un envío anterior), sin eventos ni hora.
pub fn collect(ps: &Value, fresh: bool) -> (Value, String, Value, Option<String>) {
    let mut sys = System::new();
    sys.refresh_cpu_usage();
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL.max(Duration::from_millis(500)));
    sys.refresh_cpu_usage();
    sys.refresh_memory();
    let s = |k: &str| ps.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let osver = Some(s("osver")).filter(|o| !o.is_empty()).or_else(System::long_os_version).unwrap_or_default();
    let cpus = sys.cpus();
    let facts = json!({
        "osver": osver, "model": s("model"), "cpu": cpus.first().map(|c| c.brand().trim().to_string()).unwrap_or_default(), "cores": cpus.len(),
        "load": (sys.global_cpu_usage() as f64 * 10.0).round() / 10.0, "mem_total": sys.total_memory(), "mem_free": sys.available_memory(),
        "uptime": System::uptime(), "serial": s("serial"), "disks": disks(), "ips": ips(), "macs": macs(),
        "patch": ps.get("patch").cloned().map(|mut p| { p["pending"] = json!(*PENDING.lock().unwrap_or_else(|e| e.into_inner())); p }), "sec": ps.get("sec"),
    });
    if !fresh {
        return (facts, s("serial"), json!([]), None); // catlan guarda los eventos que ya tenía
    }
    let events = match ps.get("events") {
        Some(Value::Array(a)) => Value::Array(a.clone()),
        Some(Value::Object(o)) => json!([o]), // ConvertTo-Json deja un solo evento sin lista
        _ => json!([]),
    };
    (facts, s("serial"), events, Some(s("now")).filter(|n| !n.is_empty()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64_como_powershell() {
        assert_eq!(super::b64(b"Ma"), "TWE=");
        assert_eq!(super::b64(b"Man"), "TWFu");
        assert_eq!(super::b64(b"M"), "TQ==");
    }

    #[test]
    fn programas_instalados() {
        let l = super::software();
        assert!(l.iter().all(|p| !p["name"].as_str().unwrap().is_empty()) && l.windows(2).all(|w| w[0] != w[1]));
        if cfg!(windows) {
            assert!(!l.is_empty(), "un Windows sin ningún programa en el registro de desinstalación");
        }
    }
}
