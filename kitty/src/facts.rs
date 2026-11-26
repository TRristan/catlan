//! Lo que Kitty cuenta de su equipo: lo justo para ver fallos. Nada de usuarios, programas, procesos ni archivos.
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
        .iter()
        .flat_map(|(_, n)| n.ip_networks().iter().map(|i| i.addr))
        .filter(|a| !a.is_loopback() && !a.is_unspecified() && !matches!(a, std::net::IpAddr::V6(v) if (v.segments()[0] & 0xffc0) == 0xfe80))
        .map(|a| a.to_string())
        .collect();
    out.sort();
    out.dedup();
    out
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

fn b64(b: &[u8]) -> String {
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
@{ now = $now; osver = "$($os.Caption) $($os.Version)".Trim(); model = "$($cs.Manufacturer) $($cs.Model)".Trim(); serial = $serial; events = $events } | ConvertTo-Json -Depth 4 -Compress
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
        "uptime": System::uptime(), "serial": s("serial"), "disks": disks(), "ips": ips(),
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
}
