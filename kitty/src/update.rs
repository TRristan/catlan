//! Kitty se actualiza solo: catlan anuncia en /kitty.json el sha256 del kitty.exe que reparte. El servicio (SYSTEM) lo
//! compara con el suyo y, si cambia, lo descarga, comprueba que llega entero y lo pone en su sitio. Windows deja renombrar
//! un .exe en marcha: el viejo pasa a «kitty.exe.viejo» y el nuevo ocupa su nombre. La ventana de cada usuario ve que su
//! archivo ha cambiado y se reabre con el nuevo.
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn sha256(p: &Path) -> Option<String> {
    use sha2::Digest;
    let b = std::fs::read(p).ok()?;
    Some(sha2::Sha256::digest(&b).iter().map(|x| format!("{x:02x}")).collect())
}

/// El kitty.exe instalado (Archivos de programa\Kitty), si es este. Una copia de pruebas o descargada no se toca.
pub fn installed() -> Option<PathBuf> {
    let me = std::env::current_exe().ok()?;
    let dir = PathBuf::from(std::env::var("ProgramFiles").ok()?).join("Kitty");
    let same = me.parent().is_some_and(|p| p.to_string_lossy().eq_ignore_ascii_case(&dir.to_string_lossy()));
    same.then_some(me)
}

/// ¿Hay un Kitty nuevo en catlan? Lo instala y devuelve true: el servicio sale y la tarea programada lo vuelve a lanzar.
pub fn check(url: &str) -> Result<bool, String> {
    if !url.starts_with("https://") {
        return Ok(false); // en claro, cualquiera en la red podría colar otro kitty.exe: se reinstala desde catlan
    }
    let Some(me) = installed() else {
        return Ok(false);
    };
    let _ = std::fs::remove_file(me.with_extension("exe.viejo")); // el de la actualización anterior, ya sin usar
    let v: Value = crate::net::agent()
        .get(&format!("{url}/kitty.json"))
        .timeout(Duration::from_secs(10))
        .call()
        .map_err(|e| e.to_string())?
        .into_string()
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let want = v.get("kitty").and_then(Value::as_str).unwrap_or("");
    if want.len() != 64 || sha256(&me).as_deref() == Some(want) {
        return Ok(false); // catlan sin kitty.exe (o uno anterior a esto), o ya es el mismo
    }
    let mut b = Vec::new();
    use std::io::Read;
    crate::net::agent()
        .get(&format!("{url}/kitty.exe"))
        .timeout(Duration::from_secs(120))
        .call()
        .map_err(|e| e.to_string())?
        .into_reader()
        .take(64 << 20)
        .read_to_end(&mut b)
        .map_err(|e| e.to_string())?;
    let new = me.with_extension("exe.nuevo");
    std::fs::write(&new, &b).map_err(|e| e.to_string())?;
    if sha256(&new).as_deref() != Some(want) {
        let _ = std::fs::remove_file(&new);
        return Err("el kitty.exe descargado no coincide con el que anuncia catlan".into());
    }
    let old = me.with_extension("exe.viejo");
    std::fs::rename(&me, &old).map_err(|e| e.to_string())?;
    if let Err(e) = std::fs::rename(&new, &me) {
        let _ = std::fs::rename(&old, &me); // sin Kitty no: vuelve el de antes
        return Err(e.to_string());
    }
    Ok(true)
}
