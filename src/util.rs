//! Lo pequeño que usa todo catlan: errores para la API, JSON, fechas, %g de Python y trabajo en paralelo.
use serde_json::{Map, Value};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Una expresión regular compilada una sola vez.
#[macro_export]
macro_rules! re {
    ($s:expr) => {{
        static R: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new($s).unwrap());
        &*R
    }};
}

/// Error con un mensaje para quien usa la web: la API responde 400 con él.
#[derive(Debug)]
pub struct Bad(pub String);
impl std::fmt::Display for Bad {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Bad {}

pub fn bad<T>(m: impl Into<String>) -> anyhow::Result<T> {
    Err(Bad(m.into()).into())
}

/// Datos con otra forma (una lista donde va un objeto…): 400 sin más detalle.
#[derive(Debug)]
pub struct Shape;
impl std::fmt::Display for Shape {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("los datos no tienen la forma esperada")
    }
}
impl std::error::Error for Shape {}

pub fn obj(v: &Value) -> anyhow::Result<&Map<String, Value>> {
    v.as_object().ok_or_else(|| Shape.into())
}

pub type Row = Map<String, Value>;

/// Lectura cómoda de filas y objetos JSON, con los mismos «vacíos» que Python.
pub trait J {
    fn val(&self, k: &str) -> &Value;
    fn s(&self, k: &str) -> &str {
        self.val(k).as_str().unwrap_or("")
    }
    fn i(&self, k: &str) -> Option<i64> {
        self.val(k).as_i64()
    }
    fn f(&self, k: &str) -> Option<f64> {
        self.val(k).as_f64()
    }
    fn t(&self, k: &str) -> bool {
        truthy(self.val(k))
    }
}
static NULL: Value = Value::Null;
impl J for Map<String, Value> {
    fn val(&self, k: &str) -> &Value {
        self.get(k).unwrap_or(&NULL)
    }
}
impl J for Value {
    fn val(&self, k: &str) -> &Value {
        self.get(k).unwrap_or(&NULL)
    }
}

/// Lo que Python toma por falso: None, 0, "", [], {}.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `type(v) is int` de Python: un número entero (un booleano no cuenta).
pub fn is_int(v: &Value) -> bool {
    v.is_i64() || v.is_u64()
}

/// `str(v)` de Python, para los campos de texto que llegan de la red.
pub fn py_str(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::Bool(b) => if *b { "True" } else { "False" }.into(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Los primeros n caracteres (no bytes): como `s[:n]` en Python.
pub fn trunc(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

pub fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

pub fn utc(fmt: &str) -> String {
    chrono::Utc::now().format(fmt).to_string()
}

pub fn local(fmt: &str) -> String {
    chrono::Local::now().format(fmt).to_string()
}

/// `f"{v:g}"` de Python: 6 cifras significativas, sin ceros al final.
pub fn fmt_g(v: f64) -> String {
    if v == 0.0 || !v.is_finite() {
        return if v == 0.0 { "0".into() } else { format!("{v}") };
    }
    let exp = v.abs().log10().floor() as i32;
    if !(-4..6).contains(&exp) {
        let s = format!("{v:.5e}");
        let (m, e) = s.split_once('e').unwrap_or((&s, "0"));
        let m = if m.contains('.') { m.trim_end_matches('0').trim_end_matches('.') } else { m };
        let e: i32 = e.parse().unwrap_or(0);
        return format!("{m}e{}{:02}", if e < 0 { '-' } else { '+' }, e.abs());
    }
    let s = format!("{:.*}", (5 - exp).max(0) as usize, v);
    if s.contains('.') { s.trim_end_matches('0').trim_end_matches('.').to_string() } else { s }
}

/// `round(v, n)` de Python (redondeo al par en el empate exacto).
pub fn round(v: f64, n: i32) -> f64 {
    let p = 10f64.powi(n);
    (v * p).round_ties_even() / p
}

/// Aplica f a cada elemento con hasta n hilos; el resultado sale en el mismo orden.
pub fn par_map<T: Sync, R: Send>(items: &[T], n: usize, f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let next = AtomicUsize::new(0);
    let out: Vec<Mutex<Option<R>>> = items.iter().map(|_| Mutex::new(None)).collect();
    std::thread::scope(|s| {
        for _ in 0..n.min(items.len()) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= items.len() {
                        break;
                    }
                    *out[i].lock().unwrap() = Some(f(&items[i]));
                }
            });
        }
    });
    out.into_iter().map(|m| m.into_inner().unwrap().unwrap()).collect()
}

/// `parse_qs` de Python: sin los valores vacíos.
pub fn parse_qs(q: &str) -> std::collections::HashMap<String, Vec<String>> {
    let mut out: std::collections::HashMap<String, Vec<String>> = Default::default();
    for (k, v) in form_urlencoded::parse(q.as_bytes()) {
        if !v.is_empty() {
            out.entry(k.into_owned()).or_default().push(v.into_owned());
        }
    }
    out
}

/// `urllib.parse.quote`: todo menos letras, números, `_.-~` y `/`, en %XX.
pub fn quote(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' | b'/' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Mutex que sigue sirviendo aunque un hilo muriera con él cogido.
pub fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn g_como_python() {
        for (v, s) in [(71.0, "71"), (65.0, "65"), (22.5, "22.5"), (0.016, "0.016"), (1234567.0, "1.23457e+06"), (0.00001, "1e-05"), (-3.25, "-3.25")] {
            assert_eq!(fmt_g(v), s);
        }
    }
    #[test]
    fn en_paralelo_y_en_orden() {
        assert_eq!(par_map(&[1, 2, 3, 4, 5], 3, |x| x * 10), vec![10, 20, 30, 40, 50]);
        assert!(par_map(&[] as &[i32], 4, |x| *x).is_empty());
    }
}
