//! Hablar con catlan y enviar el estado del equipo (lo que hace `kitty servicio` cada minuto).
use crate::{conf, facts};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// Cada cuánto envía el servicio el estado del PC (casi en directo en catlan) (CPU, memoria, discos), y cada cuánto lo lento (eventos, modelo, serie).
pub const EVERY: Duration = Duration::from_secs(15);
pub const SLOW_EVERY: Duration = Duration::from_secs(300);

/// Acepta solo el certificado con esta huella (sha256 en hex); con `want` vacío, cualquiera, y apunta cuál era (para
/// descubrir catlan en la red antes de instalar). Los nombres no cuentan: el autofirmado no sabe con qué IP lo llamarán.
#[derive(Debug)]
struct Pinned {
    want: String,
    seen: Arc<Mutex<String>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for Pinned {
    fn verify_server_cert(&self, cert: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let h = hex_sha256(cert);
        let ok = self.want.is_empty() || self.want.eq_ignore_ascii_case(&h);
        *self.seen.lock().unwrap_or_else(|e| e.into_inner()) = h;
        if ok { Ok(rustls::client::danger::ServerCertVerified::assertion()) } else { Err(rustls::Error::General("no es el certificado de catlan".into())) }
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

fn hex_sha256(b: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(b).iter().map(|x| format!("{x:02X}")).collect()
}

fn pinned(want: &str, seen: Arc<Mutex<String>>) -> ureq::Agent {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let v = Pinned { want: want.to_string(), seen, provider: provider.clone() };
    match rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions() {
        Ok(b) => ureq::AgentBuilder::new().tls_config(Arc::new(b.dangerous().with_custom_certificate_verifier(Arc::new(v)).with_no_client_auth())).build(),
        Err(_) => ureq::agent(),
    }
}

/// Para hablar con el catlan que instaló Kitty: anclado a su certificado si es el autofirmado; si no, los del sistema.
pub fn agent() -> &'static ureq::Agent {
    static A: OnceLock<ureq::Agent> = OnceLock::new();
    A.get_or_init(|| match conf::Conf::load().map(|c| c.pin).unwrap_or_default() {
        p if p.is_empty() => ureq::agent(),
        p => pinned(&p, Default::default()),
    })
}

/// POST con JSON: (código HTTP, respuesta). Código 0: no se pudo hablar con catlan.
pub fn post(url: &str, body: &Value) -> (u16, Value) {
    let r = agent().post(url).timeout(Duration::from_secs(20)).set("Content-Type", "application/json; charset=utf-8").send_string(&body.to_string());
    match r {
        Ok(r) => (r.status(), r.into_string().ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null)),
        Err(ureq::Error::Status(c, r)) => (c, r.into_string().ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(json!({"error": format!("catlan respondió {c}")}))),
        Err(e) => (0, json!({"error": format!("no hay conexión con catlan ({})", e.kind())})),
    }
}

/// «192.168.1.5» → «https://192.168.1.5:8080». None si no parece una dirección (va a una línea de PowerShell).
pub fn normalize(s: &str) -> Option<String> {
    let s = s.trim().trim_end_matches('/');
    let ok = !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || ".:/-[]".contains(c));
    let u = if s.contains("://") {
        s.to_string()
    } else if s.contains(':') {
        format!("https://{s}")
    } else {
        format!("https://{s}:8080")
    };
    (ok && u.starts_with("https://")).then_some(u)
}

/// ¿Hay un catlan en esta dirección? Devuelve su id y la huella de su certificado para anclarlo ("" si es de una CA:
/// entonces PowerShell lo comprueba como cualquier web). La primera vez se cree al que conteste (como con SSH); para
/// no fiarse ni de eso, el comando de catlan lleva la huella dentro.
pub fn probe(url: &str) -> Option<(String, String)> {
    let seen = Arc::new(Mutex::new(String::new()));
    let body = pinned("", seen.clone()).get(&format!("{url}/kitty.json")).timeout(Duration::from_millis(2500)).call().ok()?.into_string().ok()?;
    let v: Value = serde_json::from_str(&body).ok()?;
    let id = v.get("catlan").and_then(Value::as_str).filter(|s| !s.is_empty())?.to_string();
    let pin = v.get("pin").and_then(Value::as_str).unwrap_or("").to_string();
    let seen = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
    // dice ser autofirmado con otra huella que la que ha enseñado: alguien en medio
    (pin.is_empty() || pin.eq_ignore_ascii_case(&seen)).then_some((id, pin))
}

/// Kitty sin instalar busca catlan: primero «catlan:8080», luego cada equipo de su red local (/24) en el puerto 8080.
pub fn find() -> Option<String> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
    if probe("https://catlan:8080").is_some() {
        return Some("https://catlan:8080".into());
    }
    let mut nets: Vec<[u8; 3]> = sysinfo::Networks::new_with_refreshed_list()
        .values()
        .flat_map(|n| n.ip_networks().iter().map(|i| i.addr))
        .filter_map(|a| match a {
            IpAddr::V4(v) if v.is_private() => Some([v.octets()[0], v.octets()[1], v.octets()[2]]),
            _ => None,
        })
        .collect();
    nets.sort();
    nets.dedup();
    // shortcut: solo el /24 de cada interfaz y el puerto 8080; si catlan está en otra subred, se escribe a mano
    let open: Vec<Ipv4Addr> = std::thread::scope(|s| {
        let hs: Vec<_> = nets
            .iter()
            .flat_map(|n| (1..255u8).map(move |h| Ipv4Addr::new(n[0], n[1], n[2], h)))
            .map(|ip| s.spawn(move || TcpStream::connect_timeout(&SocketAddr::new(ip.into(), 8080), Duration::from_millis(400)).ok().map(|_| ip)))
            .collect();
        hs.into_iter().filter_map(|h| h.join().ok().flatten()).collect()
    });
    open.into_iter().map(|ip| format!("https://{ip}:8080")).find(|u| probe(u).is_some())
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
    if state == "adoptado"
        && let Some(n) = now
    {
        conf::set("since", &n); // pendiente: los eventos esperan a que lo acepten
    }
    Ok(state)
}

#[test]
fn normalize_addresses() {
    assert_eq!(normalize("192.168.1.5").as_deref(), Some("https://192.168.1.5:8080"));
    assert_eq!(normalize(" catlan:9000/ ").as_deref(), Some("https://catlan:9000"));
    assert_eq!(normalize("https://it.local").as_deref(), Some("https://it.local"));
    assert_eq!(normalize("x'; calc; '"), None); // va dentro de una línea de PowerShell
    assert_eq!(normalize("http://catlan:8080"), None); // en claro ya no se instala
    assert_eq!(normalize("ftp://x"), None);
    assert_eq!(normalize(""), None);
}
