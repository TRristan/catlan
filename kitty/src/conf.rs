//! Dónde guarda Kitty lo suyo. La clave del equipo, en el registro (HKLM\SOFTWARE\Kitty, solo SYSTEM y administradores),
//! como el Kitty de PowerShell: los equipos ya instalados conservan su identidad. Lo que necesita la ventana (dirección de
//! catlan y clave de incidencias), en %ProgramData%\Kitty\kitty.json, que pueden leer los usuarios del PC.
//! KITTY_DIR: todo en archivos de esa carpeta, para probarlo sin ser administrador.
use serde_json::{Value, json};
use std::path::PathBuf;

pub struct Conf {
    pub url: String,
    pub catlan: String,
    pub ukey: String,
}

fn test_dir() -> Option<PathBuf> {
    std::env::var_os("KITTY_DIR").filter(|d| !d.is_empty()).map(PathBuf::from)
}

pub fn dir() -> PathBuf {
    test_dir().unwrap_or_else(|| PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into())).join("Kitty"))
}

impl Conf {
    pub fn load() -> Result<Conf, String> {
        let p = dir().join("kitty.json");
        let v: Value = std::fs::read(&p)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or_else(|| format!("Kitty no está instalado en este equipo (falta {})", p.display()))?;
        let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").trim_end_matches('/').to_string();
        let c = Conf { url: s("url"), catlan: s("catlan"), ukey: s("ukey") };
        if c.url.is_empty() || c.ukey.len() < 32 {
            return Err(format!("{} está incompleto: vuelve a instalar Kitty desde catlan", p.display()));
        }
        Ok(c)
    }

    /// El servidor, para enseñarlo: «catlan:8080».
    pub fn host(&self) -> String {
        self.url.split_once("://").map_or(self.url.as_str(), |(_, r)| r).to_string()
    }
}

/// La clave que identifica a este equipo ante catlan. Solo la lee SYSTEM (la tarea programada).
pub fn secret_key() -> Result<String, String> {
    let k = get("key").ok_or("sin la clave del equipo: vuelve a instalar Kitty desde catlan")?;
    if k.len() < 32 { Err("clave del equipo no válida".into()) } else { Ok(k) }
}

/// Valores del estado del agente: key, since, state, when, error.
pub fn get(name: &str) -> Option<String> {
    if let Some(d) = test_dir() {
        let v: Value = std::fs::read(d.join("state.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(json!({}));
        if name == "key" {
            return std::fs::read_to_string(d.join("key")).ok().map(|s| s.trim().to_string());
        }
        return v.get(name).and_then(Value::as_str).map(String::from);
    }
    reg_get(name)
}

pub fn set(name: &str, value: &str) {
    if let Some(d) = test_dir() {
        let p = d.join("state.json");
        let mut v: Value = std::fs::read(&p).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(json!({}));
        v[name] = value.into();
        let _ = std::fs::write(p, v.to_string());
        return;
    }
    reg_set(name, value);
}

#[cfg(windows)]
fn reg_get(name: &str) -> Option<String> {
    winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE).open_subkey(r"SOFTWARE\Kitty").ok()?.get_value(name).ok()
}

#[cfg(windows)]
fn reg_set(name: &str, value: &str) {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_SET_VALUE};
    if let Ok(k) = winreg::RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(r"SOFTWARE\Kitty", KEY_SET_VALUE) {
        let _ = k.set_value(name, &value.to_string());
    }
}

#[cfg(not(windows))]
fn reg_get(_: &str) -> Option<String> {
    None
}

#[cfg(not(windows))]
fn reg_set(_: &str, _: &str) {}
