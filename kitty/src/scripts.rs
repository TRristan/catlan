//! Scripts de PowerShell que lanza IT desde catlan. Llegan en la respuesta de un envío, se ejecutan como SYSTEM en otro
//! hilo (uno detrás de otro, hasta 10 minutos cada uno) y su salida vuelve a catlan en el envío siguiente.
use serde_json::{Value, json};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

static QUEUE: Mutex<Vec<(i64, String)>> = Mutex::new(Vec::new());
static DONE: Mutex<Vec<Value>> = Mutex::new(Vec::new());
const MAX: Duration = Duration::from_secs(600);

/// Los que manda catlan: [{id, body}].
pub fn take(v: Option<&Value>) {
    let Some(a) = v.and_then(Value::as_array) else { return };
    let new: Vec<(i64, String)> = a.iter().filter_map(|r| Some((r.get("id")?.as_i64()?, r.get("body")?.as_str()?.to_string()))).collect();
    if new.is_empty() {
        return;
    }
    QUEUE.lock().unwrap_or_else(|e| e.into_inner()).extend(new);
    std::thread::spawn(drain);
}

/// Los resultados por enviar ([{id, code, out}]); se vacían al leerlos y vuelven con `keep` si el envío falla.
pub fn results() -> Vec<Value> {
    std::mem::take(&mut *DONE.lock().unwrap_or_else(|e| e.into_inner()))
}

pub fn keep(r: Vec<Value>) {
    DONE.lock().unwrap_or_else(|e| e.into_inner()).extend(r);
}

/// Ejecuta la cola. Un solo hilo a la vez: el que encuentra la cola vacía sale.
fn drain() {
    static RUNNING: Mutex<()> = Mutex::new(());
    let Ok(_one) = RUNNING.try_lock() else { return };
    loop {
        let next = {
            let mut q = QUEUE.lock().unwrap_or_else(|e| e.into_inner());
            if q.is_empty() { None } else { Some(q.remove(0)) }
        };
        let Some((id, body)) = next else { return };
        let (code, out) = run(&body);
        DONE.lock().unwrap_or_else(|e| e.into_inner()).push(json!({"id": id, "code": code, "out": out}));
    }
}

/// PowerShell con el script, salida y errores juntos. (código, salida); -1 si no arranca o tarda demasiado.
fn run(body: &str) -> (i64, String) {
    // tal cual, detrás de dos líneas: así «exit N» del script es el código que se guarda
    let script = format!("[Console]::OutputEncoding = [Text.Encoding]::UTF8\n$ProgressPreference = 'SilentlyContinue'\n{body}");
    let utf16: Vec<u8> = script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let mut cmd = Command::new(if cfg!(windows) { "powershell.exe" } else { "pwsh" });
    cmd.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &crate::facts::b64(&utf16)]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // sin ventana de consola
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return (-1, format!("no se pudo abrir PowerShell: {e}")),
    };
    let read = |p: Option<Box<dyn std::io::Read + Send>>| {
        std::thread::spawn(move || {
            let mut s = Vec::new();
            if let Some(mut p) = p {
                let _ = p.read_to_end(&mut s);
            }
            s
        })
    };
    let (o, e) = (read(child.stdout.take().map(|p| Box::new(p) as _)), read(child.stderr.take().map(|p| Box::new(p) as _)));
    let t0 = Instant::now();
    let code = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st.code().unwrap_or(-1) as i64,
            Ok(None) if t0.elapsed() < MAX => std::thread::sleep(Duration::from_millis(200)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break -1;
            }
        }
    };
    let mut out = String::from_utf8_lossy(&o.join().unwrap_or_default()).into_owned();
    out.push_str(&String::from_utf8_lossy(&e.join().unwrap_or_default()));
    if t0.elapsed() >= MAX {
        out.push_str("\n(Kitty lo cortó: pasaba de 10 minutos)");
    }
    (code, out)
}

#[cfg(all(test, windows))]
#[test]
fn ejecuta_y_devuelve_la_salida() {
    let (code, out) = run("Write-Output 'hola gato'; Write-Error 'falla'; exit 3");
    assert_eq!(code, 3, "{out}");
    assert!(out.contains("hola gato") && out.contains("falla"), "{out}");
    assert_eq!(run("Get-Date | Out-Null").0, 0);
}
