//! Hablar con catlan y enviar el estado del equipo (lo que hace `kitty servicio` cada minuto).
use crate::{conf, facts};
use serde_json::{Value, json};
use std::time::Duration;

/// Cada cuánto envía el servicio el estado del PC (casi en directo en catlan) (CPU, memoria, discos), y cada cuánto lo lento (eventos, modelo, serie).
pub const EVERY: Duration = Duration::from_secs(15);
pub const SLOW_EVERY: Duration = Duration::from_secs(300);

/// POST con JSON: (código HTTP, respuesta). Código 0: no se pudo hablar con catlan.
pub fn post(url: &str, body: &Value) -> (u16, Value) {
    let r = ureq::post(url).timeout(Duration::from_secs(20)).set("Content-Type", "application/json; charset=utf-8").send_string(&body.to_string());
    match r {
        Ok(r) => (r.status(), r.into_string().ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null)),
        Err(ureq::Error::Status(c, r)) => (c, r.into_string().ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(json!({"error": format!("catlan respondió {c}")}))),
        Err(e) => (0, json!({"error": format!("no hay conexión con catlan ({})", e.kind())})),
    }
}

/// «192.168.1.5» → «http://192.168.1.5:8080». None si no parece una dirección (va a una línea de PowerShell).
pub fn normalize(s: &str) -> Option<String> {
    let s = s.trim().trim_end_matches('/');
    let ok = !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || ".:/-[]".contains(c));
    let u = if s.contains("://") { s.to_string() } else if s.contains(':') { format!("http://{s}") } else { format!("http://{s}:8080") };
    (ok && (u.starts_with("http://") || u.starts_with("https://"))).then_some(u)
}

/// ¿Hay un catlan en esta dirección? Devuelve su id.
pub fn probe(url: &str) -> Option<String> {
    let body = ureq::get(&format!("{url}/kitty.json")).timeout(Duration::from_millis(2500)).call().ok()?.into_string().ok()?;
    let v: Value = serde_json::from_str(&body).ok()?;
    v.get("catlan").and_then(Value::as_str).filter(|s| !s.is_empty()).map(String::from)
}

/// Kitty sin instalar busca catlan: primero «catlan:8080», luego cada equipo de su red local (/24) en el puerto 8080.
pub fn find() -> Option<String> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
    if probe("http://catlan:8080").is_some() {
        return Some("http://catlan:8080".into());
    }
    let mut nets: Vec<[u8; 3]> = sysinfo::Networks::new_with_refreshed_list()
        .iter()
        .flat_map(|(_, n)| n.ip_networks().iter().map(|i| i.addr))
        .filter_map(|a| match a {
            IpAddr::V4(v) if v.is_private() => Some([v.octets()[0], v.octets()[1], v.octets()[2]]),
            _ => None,
        })
        .collect();
    nets.sort();
    nets.dedup();
    // shortcut: solo el /24 de cada interfaz y el puerto 8080; si catlan está en otra subred, se escribe a mano
    let open: Vec<Ipv4Addr> = std::thread::scope(|s| {
        let hs: Vec<_> = nets.iter().flat_map(|n| (1..255u8).map(move |h| Ipv4Addr::new(n[0], n[1], n[2], h)))
            .map(|ip| s.spawn(move || TcpStream::connect_timeout(&SocketAddr::new(ip.into(), 8080), Duration::from_millis(400)).ok().map(|_| ip)))
            .collect();
        hs.into_iter().filter_map(|h| h.join().ok().flatten()).collect()
    });
    open.into_iter().map(|ip| format!("http://{ip}:8080")).find(|u| probe(u).is_some())
}

/// `kitty enviar`: el estado de este equipo a catlan, y el resultado anotado para el instalador.
/// `ps`: lo lento de `facts::slow`; `fresh` si se acaba de sacar (lleva los eventos nuevos).
pub fn send(ps: &Value, fresh: bool) -> Result<String, String> {
    let c = conf::Conf::load()?;
    let key = conf::secret_key()?;
    let (facts, serial, events, now) = facts::collect(ps, fresh);
    let arch = std::env::var("PROCESSOR_ARCHITECTURE").map(|a| a.to_lowercase()).unwrap_or_else(|_| std::env::consts::ARCH.into());
    // ip vacía: catlan pone la dirección desde la que llega
    let body = json!({"key": key, "ukey": c.ukey, "name": facts::name(), "ip": "", "serial": serial, "os": format!("{}/{arch}", std::env::consts::OS),
                      "kind": "pc", "every": EVERY.as_secs().div_ceil(60), "secs": EVERY.as_secs(), "facts": facts, "events": events, "apps": crate::apps::report()});
    let (code, res) = post(&format!("{}/api/agent", c.url), &body);
    if code != 200 {
        return Err(res.get("error").and_then(Value::as_str).map(String::from).unwrap_or_else(|| format!("catlan respondió {code}")));
    }
    if res.get("catlan").and_then(Value::as_str) != Some(c.catlan.as_str()) {
        return Err(format!("{} no es el catlan que lo instaló", c.url)); // atado: no habla con ningún otro
    }
    let state = res.get("state").and_then(Value::as_str).unwrap_or("").to_string();
    crate::apps::want(res.get("apps"));
    if state == "adoptado" {
        if let Some(n) = now {
            conf::set("since", &n); // pendiente: los eventos esperan a que lo acepten
        }
    }
    Ok(state)
}

#[test]
fn normalize_addresses() {
    assert_eq!(normalize("192.168.1.5").as_deref(), Some("http://192.168.1.5:8080"));
    assert_eq!(normalize(" catlan:9000/ ").as_deref(), Some("http://catlan:9000"));
    assert_eq!(normalize("https://it.local").as_deref(), Some("https://it.local"));
    assert_eq!(normalize("x'; calc; '"), None); // va dentro de una línea de PowerShell
    assert_eq!(normalize("ftp://x"), None);
    assert_eq!(normalize(""), None);
}
