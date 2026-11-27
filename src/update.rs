//! catlan se actualiza con las versiones publicadas en GitHub (Releases), que compila y sube GitHub Actions al crear una
//! etiqueta vX.Y.Z. Solo se conecta a GitHub cuando un administrador lo pide o activa «Actualizar solo»: si no, nada
//! sale de tu red. Descarga el ejecutable de este sistema (y kitty.exe, si catlan reparte uno), comprueba su sha256 con el
//! SHA256SUMS de la versión, se reemplaza y se reinicia. Los PCs con Kitty se actualizan después, solos.
use crate::config::{DATA, HERE};
use crate::db::{q, val};
use crate::p;
use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};
use std::io::Read;
use std::sync::Mutex;
use std::time::Duration;

const REPO: &str = "TRristan/catlan";
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");
/// Lo último que se supo de GitHub, para enseñarlo sin volver a preguntar.
static LAST: Mutex<Option<Value>> = Mutex::new(None);

fn docker() -> bool {
    std::path::Path::new("/.dockerenv").exists()
}

/// El ejecutable publicado para este sistema. None: aquí no se puede (otra arquitectura, o Docker, que se actualiza con su imagen).
fn asset() -> Option<&'static str> {
    if docker() {
        return None;
    }
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("catlan-linux-x86_64"),
        ("windows", "x86_64") => Some("catlan-windows-x86_64.exe"),
        _ => None,
    }
}

/// "1.2.10" > "1.2.9"; con o sin «v» delante.
pub fn newer(a: &str, b: &str) -> bool {
    let n = |s: &str| s.trim_start_matches('v').split('.').map(|x| x.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    n(a) > n(b)
}

fn get(url: &str) -> Result<ureq::Response> {
    // sin datos de esta instalación: GitHub solo pide un User-Agent
    Ok(ureq::get(url).timeout(Duration::from_secs(120)).set("User-Agent", "catlan-updater").call()?)
}

fn bytes(url: &str) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    get(url)?.into_reader().take(200 << 20).read_to_end(&mut b)?;
    Ok(b)
}

pub fn auto() -> bool {
    val("SELECT v FROM meta WHERE k='autoupdate'", p![]).ok().and_then(|v| v.as_str().map(|s| s == "1")).unwrap_or(false)
}

pub fn set_auto(on: bool) -> Result<()> {
    q("INSERT OR REPLACE INTO meta(k, v) VALUES('autoupdate', ?)", p![if on { "1" } else { "0" }])?;
    Ok(())
}

/// Lo que ve la página «Salud de catlan».
pub fn status() -> Value {
    json!({"current": CURRENT, "can": asset().is_some(), "docker": docker(), "auto": auto(), "last": crate::util::lock(&LAST).clone()})
}

/// Pregunta a GitHub por la última versión.
pub fn check() -> Result<Value> {
    let r = match ureq::get(&format!("https://api.github.com/repos/{REPO}/releases/latest")).timeout(Duration::from_secs(30)).set("User-Agent", "catlan-updater").call() {
        Err(ureq::Error::Status(404, _)) => bail!("todavía no hay ninguna versión publicada en GitHub"),
        r => r?,
    };
    let r: Value = serde_json::from_str(&r.into_string()?)?;
    let tag = r["tag_name"].as_str().ok_or_else(|| anyhow!("GitHub no ha devuelto ninguna versión"))?;
    let notes: String = r["body"].as_str().unwrap_or("").chars().take(4000).collect();
    let v = json!({"latest": tag.trim_start_matches('v'), "newer": newer(tag, CURRENT), "notes": notes, "url": r["html_url"],
                   "at": crate::util::local("%Y-%m-%d %H:%M")});
    *crate::util::lock(&LAST) = Some(v.clone());
    Ok(json!({"assets": r["assets"], "info": v}))
}

/// Descarga un archivo de la versión y comprueba su sha256 con SHA256SUMS. None: la versión no lo trae.
fn fetch(assets: &Value, sums: &str, name: &str) -> Result<Option<Vec<u8>>> {
    let Some(url) = assets.as_array().and_then(|a| a.iter().find(|x| x["name"] == name)).and_then(|x| x["browser_download_url"].as_str()) else {
        return Ok(None);
    };
    let want = sums.lines().find_map(|l| {
        let (h, n) = l.split_once(char::is_whitespace)?;
        (n.trim().trim_start_matches('*') == name).then(|| h.to_lowercase())
    });
    let Some(want) = want else { bail!("{name} no está en SHA256SUMS") };
    let b = bytes(url)?;
    if crate::crypto::hex(&<sha2::Sha256 as sha2::Digest>::digest(&b)) != want {
        bail!("{name} descargado no coincide con su sha256: no se instala");
    }
    Ok(Some(b))
}

/// Instala la última versión y devuelve cuál; después hay que reiniciar (`restart`).
pub fn apply() -> Result<String> {
    let Some(mine) = asset() else { bail!("aquí catlan no se puede actualizar solo (en Docker, actualiza la imagen)") };
    let rel = check()?;
    let (assets, info) = (&rel["assets"], &rel["info"]);
    if !info["newer"].as_bool().unwrap_or(false) {
        bail!("ya tienes la última versión ({CURRENT})");
    }
    let sums = fetch_sums(assets)?;
    let bin = fetch(assets, &sums, mine)?.ok_or_else(|| anyhow!("la versión no trae {mine}"))?;
    // kitty.exe: si catlan reparte uno, también el nuevo (y los PCs se actualizan solos al verlo)
    if let Some(k) = [HERE.join("kitty.exe"), DATA.join("kitty.exe")].into_iter().find(|p| p.is_file()) {
        if let Some(b) = fetch(assets, &sums, "kitty.exe")? {
            let tmp = k.with_extension("exe.nuevo");
            std::fs::write(&tmp, b)?;
            std::fs::rename(&tmp, &k)?;
        }
    }
    let me = std::env::current_exe()?;
    let new = me.with_extension("nuevo");
    std::fs::write(&new, bin)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755))?;
    }
    // Windows deja renombrar el .exe en marcha pero no sobrescribirlo: el de ahora pasa a «.viejo»
    let old = me.with_extension("viejo");
    let _ = std::fs::remove_file(&old);
    std::fs::rename(&me, &old)?;
    if let Err(e) = std::fs::rename(&new, &me) {
        let _ = std::fs::rename(&old, &me);
        return Err(e.into());
    }
    Ok(info["latest"].as_str().unwrap_or("").to_string())
}

fn fetch_sums(assets: &Value) -> Result<String> {
    let url = assets.as_array().and_then(|a| a.iter().find(|x| x["name"] == "SHA256SUMS")).and_then(|x| x["browser_download_url"].as_str());
    Ok(String::from_utf8(bytes(url.ok_or_else(|| anyhow!("la versión no trae SHA256SUMS"))?)?)?)
}

/// Arranca el catlan nuevo y sale este. Con systemd, sale con error y el servicio (Restart=on-failure) lo relanza.
pub fn restart() -> ! {
    {
        let c = crate::util::lock(crate::db::writer());
        let _ = c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
    }
    let systemd = std::env::var_os("INVOCATION_ID").is_some();
    if !systemd {
        if let Ok(me) = std::env::current_exe() {
            let _ = std::process::Command::new(me).args(std::env::args_os().skip(1)).env("CATLAN_RESTART", "1").spawn();
        }
    }
    println!("catlan actualizado: reiniciando");
    std::process::exit(if systemd { 75 } else { 0 });
}

/// Al arrancar: borra el ejecutable anterior y, si viene de actualizarse, espera a que el viejo suelte el puerto.
pub fn on_start() {
    if let Ok(me) = std::env::current_exe() {
        let _ = std::fs::remove_file(me.with_extension("viejo"));
    }
    if std::env::var_os("CATLAN_RESTART").is_some() {
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// «Actualizar solo»: una vez al día (la primera, a los 10 minutos de arrancar).
pub fn auto_loop() {
    std::thread::sleep(Duration::from_secs(600));
    loop {
        if auto() && asset().is_some() {
            match apply() {
                Ok(v) => {
                    println!("catlan: actualizado a {v}");
                    restart();
                }
                Err(e) => println!("catlan: sin actualizar ({e})"),
            }
        }
        std::thread::sleep(Duration::from_secs(86400));
    }
}

#[test]
fn versions() {
    assert!(newer("v1.2.10", "1.2.9") && newer("1.1.0", "1.0.0") && newer("2", "1.9.9"));
    assert!(!newer("1.0.0", "1.0.0") && !newer("v1.0.0", "1.0.1"));
}
