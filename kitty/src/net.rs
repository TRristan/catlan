//! Hablar con catlan y enviar el estado del equipo (lo que hace la tarea programada cada 5 minutos).
use crate::{conf, facts};
use serde_json::{Value, json};
use std::time::Duration;

/// POST con JSON: (código HTTP, respuesta). Código 0: no se pudo hablar con catlan.
pub fn post(url: &str, body: &Value) -> (u16, Value) {
    let r = ureq::post(url).timeout(Duration::from_secs(20)).set("Content-Type", "application/json; charset=utf-8").send_string(&body.to_string());
    match r {
        Ok(r) => (r.status(), r.into_string().ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null)),
        Err(ureq::Error::Status(c, r)) => (c, r.into_string().ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(json!({"error": format!("catlan respondió {c}")}))),
        Err(e) => (0, json!({"error": format!("no hay conexión con catlan ({})", e.kind())})),
    }
}

/// `kitty enviar`: el estado de este equipo a catlan, y el resultado anotado para el instalador.
pub fn send() -> Result<String, String> {
    let c = conf::Conf::load()?;
    let key = conf::secret_key()?;
    let since = conf::get("since");
    let (facts, serial, events, now) = facts::collect(since.as_deref());
    let arch = std::env::var("PROCESSOR_ARCHITECTURE").map(|a| a.to_lowercase()).unwrap_or_else(|_| std::env::consts::ARCH.into());
    // ip vacía: catlan pone la dirección desde la que llega
    let body = json!({"key": key, "ukey": c.ukey, "name": facts::name(), "ip": "", "serial": serial, "os": format!("{}/{arch}", std::env::consts::OS),
                      "kind": "pc", "every": 5, "facts": facts, "events": events});
    let (code, res) = post(&format!("{}/api/agent", c.url), &body);
    if code != 200 {
        return Err(res.get("error").and_then(Value::as_str).map(String::from).unwrap_or_else(|| format!("catlan respondió {code}")));
    }
    if res.get("catlan").and_then(Value::as_str) != Some(c.catlan.as_str()) {
        return Err(format!("{} no es el catlan que lo instaló", c.url)); // atado: no habla con ningún otro
    }
    let state = res.get("state").and_then(Value::as_str).unwrap_or("").to_string();
    if state == "adoptado" {
        if let Some(n) = now {
            conf::set("since", &n); // pendiente: los eventos esperan a que lo acepten
        }
    }
    Ok(state)
}
