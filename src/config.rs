//! Configuración por variables de entorno, la misma que en la versión de Python.
use std::path::PathBuf;
use std::sync::LazyLock;

pub const VERSION: &str = "1.0";
pub const MAX_BODY: usize = 20 * 1024 * 1024;

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_default()
}

fn env_num<T: std::str::FromStr>(k: &str, def: T) -> T {
    match std::env::var(k) {
        Ok(v) => v.trim().parse().unwrap_or_else(|_| {
            eprintln!("{k} no es un número válido: {v}");
            std::process::exit(2)
        }),
        Err(_) => def,
    }
}

/// Carpeta del ejecutable: los datos van a su lado, como iban al lado de catlan.py.
pub static HERE: LazyLock<PathBuf> = LazyLock::new(|| {
    std::env::current_exe().ok().and_then(|p| p.parent().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("."))
});
pub static DATA: LazyLock<PathBuf> = LazyLock::new(|| match std::env::var("CATLAN_DATA") {
    Ok(d) if !d.is_empty() => PathBuf::from(d),
    _ => HERE.join("data"),
});
pub static PORT: LazyLock<u16> = LazyLock::new(|| env_num("CATLAN_PORT", 8080));
/// HTTPS propio: rutas del certificado y su clave (PEM); sin clave, va dentro del certificado.
pub static CERT: LazyLock<String> = LazyLock::new(|| env("CATLAN_CERT"));
pub static KEY: LazyLock<String> = LazyLock::new(|| env("CATLAN_KEY"));
/// 0 = sin receptor de syslog
pub static SYSLOG_PORT: LazyLock<u16> = LazyLock::new(|| env_num("CATLAN_SYSLOG_PORT", 514));
/// Contraseña del usuario admin inicial; vacía = «admin», a cambiar al entrar.
pub static PASSWORD: LazyLock<String> = LazyLock::new(|| env("CATLAN_PASSWORD"));

pub fn scheme() -> &'static str {
    if CERT.is_empty() { "http" } else { "https" }
}

pub fn db_path() -> PathBuf {
    DATA.join("catlan.db")
}

/// La ruta absoluta de los datos, escrita como la escribe Python (sin el prefijo \\?\ de Windows).
pub fn data_resolved() -> String {
    let p = std::fs::canonicalize(&*DATA).unwrap_or_else(|_| DATA.clone());
    let s = p.to_string_lossy().to_string();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else {
        s.strip_prefix(r"\\?\").map(String::from).unwrap_or(s)
    }
}

/// Una cookie por instalación: el navegador no separa cookies por puerto, y dos catlan en la misma máquina se cerraban la sesión.
pub static COOKIE: LazyLock<String> = LazyLock::new(|| format!("catlan_{}", &crate::crypto::sha256_hex(&data_resolved())[..10]));
