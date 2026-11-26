//! Programas que IT quiere en los PCs. catlan manda la lista de ids de winget en cada respuesta, y el servicio (SYSTEM)
//! instala los que faltan y actualiza los demás. Lo hace en otro hilo, porque winget tarda minutos, y el resultado vuelve
//! a catlan en el siguiente envío. Si un programa se quita de la lista, no se desinstala.
use serde_json::{Map, Value, json};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

static WANT: Mutex<Vec<String>> = Mutex::new(Vec::new());
static DONE: Mutex<Option<Map<String, Value>>> = Mutex::new(None);
/// Cada cuánto se buscan actualizaciones (y al momento si cambia la lista).
const EVERY: Duration = Duration::from_secs(3600);

/// Sin guion inicial: no se cuela como opción de winget (catlan ya lo valida; aquí, por si acaso).
fn id_ok(s: &str) -> bool {
    let mut c = s.chars();
    c.next().is_some_and(|f| f.is_ascii_alphanumeric()) && s.len() <= 128 && c.all(|x| x.is_ascii_alphanumeric() || ".+_-".contains(x))
}

/// La lista que manda catlan.
pub fn want(v: Option<&Value>) {
    if let Some(a) = v.and_then(Value::as_array) {
        *WANT.lock().unwrap_or_else(|e| e.into_inner()) = a.iter().filter_map(Value::as_str).filter(|s| id_ok(s)).map(String::from).collect();
    }
}

/// Cómo fue cada programa, para enviarlo a catlan: {id: {ok, msg}}.
pub fn report() -> Value {
    Value::Object(DONE.lock().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_default())
}

/// El hilo que instala y actualiza (solo en el servicio).
pub fn start() {
    std::thread::spawn(|| {
        let mut last: Option<(Vec<String>, Instant)> = None;
        loop {
            std::thread::sleep(Duration::from_secs(20));
            let w = WANT.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if last.as_ref().is_some_and(|(l, at)| *l == w && at.elapsed() < EVERY) {
                continue;
            }
            last = Some((w.clone(), Instant::now()));
            let wg = winget();
            let mut done = Map::new();
            for id in &w {
                let (ok, msg) = match &wg {
                    Some(wg) => one(wg, id),
                    None => (false, "este PC no tiene winget (Instalador de aplicaciones de Microsoft)".into()),
                };
                done.insert(id.clone(), json!({"ok": ok, "msg": msg}));
                *DONE.lock().unwrap_or_else(|e| e.into_inner()) = Some(done.clone()); // se va viendo según avanza
            }
            *DONE.lock().unwrap_or_else(|e| e.into_inner()) = Some(done);
        }
    });
}

/// winget.exe. Como SYSTEM no está en el PATH: hay que buscarlo dentro de WindowsApps (la versión más nueva).
fn winget() -> Option<PathBuf> {
    let base = PathBuf::from(std::env::var("ProgramFiles").ok()?).join("WindowsApps");
    let mut found: Vec<PathBuf> = std::fs::read_dir(&base)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("Microsoft.DesktopAppInstaller_") && n.ends_with("__8wekyb3d8bbwe")))
        .map(|p| p.join("winget.exe"))
        .filter(|p| p.is_file())
        .collect();
    found.sort(); // shortcut: orden por nombre, no por versión real; vale mientras las versiones tengan los mismos dígitos
    found.pop()
}

/// Instalar si falta; si ya está, actualizar.
fn one(wg: &PathBuf, id: &str) -> (bool, String) {
    const COMMON: [&str; 4] = ["--exact", "--accept-source-agreements", "--disable-interactivity", "--silent"];
    let installed = run(wg, &["list", "--id", id, "--exact", "--accept-source-agreements", "--disable-interactivity"], 120) == Ok(0);
    let (verb, done): (&[&str], &str) = if installed { (&["upgrade", "--accept-package-agreements"], "al día") } else { (&["install", "--accept-package-agreements", "--scope", "machine"], "instalado") };
    let args: Vec<&str> = [verb[0], "--id", id].into_iter().chain(verb[1..].iter().copied()).chain(COMMON).collect();
    match run(wg, &args, 1800) {
        Ok(0) => (true, done.into()),
        Ok(c) if installed && c as u32 == 0x8A15_002B => (true, "al día".into()), // no hay versión nueva
        Ok(c) => (false, format!("winget no ha podido {} (código 0x{:08X})", if installed { "actualizarlo" } else { "instalarlo" }, c as u32)),
        Err(e) => (false, e),
    }
}

fn run(wg: &PathBuf, args: &[&str], max_secs: u64) -> Result<i32, String> {
    let mut cmd = Command::new(wg);
    cmd.args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // sin ventana de consola
    }
    let mut child = cmd.spawn().map_err(|e| format!("no se pudo abrir winget: {e}"))?;
    let t0 = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return Ok(st.code().unwrap_or(-1)),
            Ok(None) if t0.elapsed() < Duration::from_secs(max_secs) => std::thread::sleep(Duration::from_millis(500)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("winget tardó demasiado".into());
            }
        }
    }
}

#[test]
fn ids() {
    assert!(id_ok("Google.Chrome") && id_ok("7zip.7zip") && id_ok("Notepad++.Notepad++"));
    assert!(!id_ok("-h") && !id_ok("") && !id_ok("a b") && !id_ok("x;calc"));
}
