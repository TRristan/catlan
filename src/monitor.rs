//! Monitor: comprobaciones (ping, puerto, web, certificado, DNS), avisos, dependencias, resúmenes por hora, SLA,
//! copias diarias, syslog e IPAM.
use crate::config::{DATA, SYSLOG_PORT, db_path};
use crate::db::{q, val, writer};
use crate::health::{KITTY_LOST, M, collect};
use crate::util::{J, Row, bad, lock, now, round, trunc, truthy, utc};
use crate::{p, re};
use anyhow::Result;
use indexmap::IndexMap;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Read;
use std::net::{Ipv4Addr, TcpStream, ToSocketAddrs, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::{Arc, LazyLock, Mutex, RwLock, mpsc};
use std::time::{Duration, Instant};

/// Un ping con el ping del sistema. Devuelve (responde, ms).
pub fn ping(host: &str) -> (bool, Option<f64>) {
    let mut cmd = Command::new("ping");
    if cfg!(windows) {
        cmd.args(["-n", "1", "-w", "1000", host]);
    } else {
        cmd.args(["-c", "1", "-W", "1", host]);
    }
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // sin ventana de consola
    }
    let Ok(mut child) = cmd.spawn() else { return tcp_ping(host) }; // sin comando ping (contenedor mínimo)
    let t0 = Instant::now();
    let ok = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st.success(),
            Ok(None) if t0.elapsed() < Duration::from_secs(5) => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return (false, None);
            }
        }
    };
    let mut raw = vec![];
    if let Some(mut s) = child.stdout.take() {
        let _ = s.read_to_end(&mut raw);
    }
    let mut err = vec![];
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_end(&mut err);
    }
    if !ok && re!(r"(?i)permi|socket|not found|no se encuentra").is_match(&String::from_utf8_lossy(&err)) {
        return tcp_ping(host); // ping sin permiso para ICMP: mejor TCP que dar el equipo por caído
    }
    let out = String::from_utf8_lossy(&raw);
    let m = re!(r"(?i)(?:time|tiempo)\s*[=<]\s*([\d.,]+)").captures(&out); // Windows en español: «tiempo=3ms»
    // Windows da código 0 también con «host inaccesible»: hace falta TTL o un tiempo (IPv6 no muestra TTL)
    let up = ok && (m.is_some() || out.to_lowercase().contains("ttl="));
    (up, if up { m.and_then(|m| m[1].replace(',', ".").parse().ok()) } else { None })
}

/// Sin ICMP: responde si algún puerto habitual acepta o rechaza la conexión (rechazar también es estar encendido).
fn tcp_ping(host: &str) -> (bool, Option<f64>) {
    let t0 = Instant::now();
    let Some(ip) = (host, 0).to_socket_addrs().ok().and_then(|mut a| a.next()).map(|a| a.ip()) else { return (false, None) };
    let up = std::thread::scope(|s| {
        let hs: Vec<_> = [80u16, 443, 22, 445, 3389, 53]
            .iter()
            .map(|&p| {
                s.spawn(move || match TcpStream::connect_timeout(&(ip, p).into(), Duration::from_secs(1)) {
                    Ok(_) => true,
                    Err(e) => e.kind() == std::io::ErrorKind::ConnectionRefused,
                })
            })
            .collect();
        hs.into_iter().any(|h| h.join().unwrap_or(false))
    });
    (up, up.then(|| ms(t0)))
}

pub const CHECK_KINDS: &[&str] = &["ping", "tcp", "http", "ssl", "dns"];

fn ms(t0: Instant) -> f64 {
    round(t0.elapsed().as_secs_f64() * 1000.0, 1)
}

fn why_io(e: &std::io::Error) -> String {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionRefused => "rechaza la conexión".into(),
        TimedOut | WouldBlock => "no contesta (tiempo agotado)".into(),
        _ => e.to_string(),
    }
}

/// Motivo corto de un fallo de red, para el aviso.
fn why(e: &(dyn std::error::Error + 'static)) -> String {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(x) = cur {
        if let Some(io) = x.downcast_ref::<std::io::Error>() {
            if let Some(inner) = io.get_ref()
                && let Some(r) = inner.downcast_ref::<rustls::Error>()
            {
                return tls_why(r);
            }
            if matches!(io.kind(), std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) {
                return why_io(io);
            }
        }
        if let Some(r) = x.downcast_ref::<rustls::Error>() {
            return tls_why(r);
        }
        if let Some(t) = x.downcast_ref::<ureq::Transport>()
            && t.kind() == ureq::ErrorKind::Dns
        {
            return "el nombre no resuelve".into();
        }
        cur = x.source();
    }
    e.to_string()
}

fn tls_why(r: &rustls::Error) -> String {
    match r {
        rustls::Error::InvalidCertificate(c) => format!("certificado no válido: {c:?}"),
        other => other.to_string(),
    }
}

/// Conecta por TCP a la primera dirección del nombre que conteste.
fn connect(host: &str, port: u16, t: Duration) -> Result<TcpStream, String> {
    let addrs = (host, port).to_socket_addrs().map_err(|_| "el nombre no resuelve".to_string())?;
    let mut last = "el nombre no resuelve".to_string();
    for a in addrs {
        match TcpStream::connect_timeout(&a, t) {
            Ok(s) => return Ok(s),
            Err(e) => last = why_io(&e),
        }
    }
    Err(last)
}

fn probe_tcp(host: &str, port: u16) -> (bool, Option<f64>, String) {
    let t0 = Instant::now();
    match connect(host, port, Duration::from_secs(3)) {
        Ok(_) => (true, Some(ms(t0)), format!("puerto {port} abierto")),
        Err(w) => (false, None, format!("puerto {port}: {w}")),
    }
}

/// Cliente HTTP: verifica certificados con los del sistema (una web con HTTPS roto es una web caída).
pub static HTTP: LazyLock<ureq::Agent> = LazyLock::new(|| ureq::AgentBuilder::new().timeout(Duration::from_secs(8)).user_agent("catlan").build());

fn read_limited(r: ureq::Response, n: u64) -> Vec<u8> {
    let mut v = vec![];
    let _ = r.into_reader().take(n).read_to_end(&mut v);
    v
}

fn probe_http(url: &str, expect: &str) -> (bool, Option<f64>, String) {
    let t0 = Instant::now();
    let (code, body) = match HTTP.get(url).call() {
        Ok(r) => (r.status(), read_limited(r, 2_000_000)),
        Err(ureq::Error::Status(c, _)) => (c, vec![]),
        Err(ureq::Error::Transport(t)) => return (false, None, why(&t)),
    };
    let ms = ms(t0);
    if code >= 400 {
        return (false, Some(ms), format!("HTTP {code}"));
    }
    if !expect.is_empty() && !body.windows(expect.len()).any(|w| w == expect.as_bytes()) {
        return (false, Some(ms), format!("HTTP {code}, pero sin «{expect}»"));
    }
    (true, Some(ms), format!("HTTP {code}"))
}

pub enum HttpErr {
    Status(u16),
    Other(String),
}

/// GET con usuario y contraseña, por Digest (lo que piden los grabadores) o Basic, según lo que pida el equipo.
pub fn get_with_auth(url: &str, user: &str, pass: &str) -> Result<Vec<u8>, HttpErr> {
    let resp = match HTTP.get(url).call() {
        Ok(r) => return Ok(read_limited(r, 10_000_000)),
        Err(ureq::Error::Status(401, r)) => r,
        Err(ureq::Error::Status(c, _)) => return Err(HttpErr::Status(c)),
        Err(ureq::Error::Transport(t)) => return Err(HttpErr::Other(why(&t))),
    };
    let digest = resp.all("WWW-Authenticate").into_iter().find(|h| h.to_lowercase().starts_with("digest")).map(String::from);
    let auth = match digest {
        Some(h) => {
            let f: HashMap<String, String> =
                re!(r#"(\w+)\s*=\s*(?:"([^"]*)"|([^,\s]+))"#).captures_iter(&h).map(|c| (c[1].to_lowercase(), c.get(2).or(c.get(3)).map_or("", |m| m.as_str()).to_string())).collect();
            let gs = |k: &str| f.get(k).cloned().unwrap_or_default();
            let alg = if gs("algorithm").to_uppercase().starts_with("SHA-256") { "sha256" } else { "md5" };
            let hx = |s: String| crate::crypto::hex(&crate::crypto::hash(alg, s.as_bytes()));
            let uri = url.splitn(4, '/').nth(3).map(|p| format!("/{p}")).unwrap_or("/".into());
            let ha1 = hx(format!("{user}:{}:{pass}", gs("realm")));
            let ha2 = hx(format!("GET:{uri}"));
            let cnonce = crate::crypto::token_hex(8);
            let qop = gs("qop").split(',').any(|q| q.trim() == "auth");
            let response = if qop { hx(format!("{ha1}:{}:00000001:{cnonce}:auth:{ha2}", gs("nonce"))) } else { hx(format!("{ha1}:{}:{ha2}", gs("nonce"))) };
            let mut a = format!(
                r#"Digest username="{user}", realm="{}", nonce="{}", uri="{uri}", response="{response}", algorithm={}"#,
                gs("realm"),
                gs("nonce"),
                if alg == "md5" { "MD5" } else { "SHA-256" }
            );
            if qop {
                a += &format!(r#", qop=auth, nc=00000001, cnonce="{cnonce}""#);
            }
            if f.contains_key("opaque") {
                a += &format!(r#", opaque="{}""#, gs("opaque"));
            }
            a
        }
        None => format!("Basic {}", data_encoding::BASE64.encode(format!("{user}:{pass}").as_bytes())),
    };
    match HTTP.get(url).set("Authorization", &auth).call() {
        Ok(r) => Ok(read_limited(r, 10_000_000)),
        Err(ureq::Error::Status(c, _)) => Err(HttpErr::Status(c)),
        Err(ureq::Error::Transport(t)) => Err(HttpErr::Other(why(&t))),
    }
}

/// Fin de validez (notAfter) de un certificado X.509, con el mismo lector BER que SNMP.
pub fn cert_expiry(der: &[u8]) -> Result<i64> {
    use crate::snmp::ber_read;
    let (_, cert, _) = ber_read(der, 0)?;
    let (_, tbs, _) = ber_read(cert, 0)?;
    let (tag, _, i) = ber_read(tbs, 0)?;
    let mut i = if tag == 0xA0 { i } else { 0 }; // [0] versión: falta en certificados v1
    for _ in 0..3 {
        i = ber_read(tbs, i)?.2; // número de serie, algoritmo, emisor
    }
    let (_, validity, _) = ber_read(tbs, i)?;
    let (_, _, j) = ber_read(validity, 0)?;
    let (tag, t, _) = ber_read(validity, j)?;
    let s = std::str::from_utf8(t)?;
    let t = if tag == 0x17 {
        // UTCTime: de 1950 a 2049 (RFC 5280)
        let yy: i32 = s.get(..2).unwrap_or("").parse()?;
        chrono::NaiveDateTime::parse_from_str(&format!("{}{}", if yy >= 50 { 19 } else { 20 }, s), "%Y%m%d%H%M%SZ")?
    } else {
        chrono::NaiveDateTime::parse_from_str(s, "%Y%m%d%H%M%SZ")?
    };
    Ok(t.and_utc().timestamp())
}

/// Acepta cualquier certificado: aquí solo importa la caducidad, también la de los autofirmados.
#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);
impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer,
        _: &[rustls::pki_types::CertificateDer],
        _: &rustls::pki_types::ServerName,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

static TLS_ANY: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
    let prov = Arc::new(rustls::crypto::ring::default_provider());
    Arc::new(
        rustls::ClientConfig::builder_with_provider(prov.clone())
            .with_safe_default_protocol_versions()
            .expect("TLS")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCert(prov)))
            .with_no_client_auth(),
    )
});

fn probe_ssl(host: &str, port: u16, days: f64) -> (bool, Option<f64>, String) {
    let t0 = Instant::now();
    let der = (|| -> Result<Vec<u8>, String> {
        let mut sock = connect(host, port, Duration::from_secs(5))?;
        let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = sock.set_write_timeout(Some(Duration::from_secs(5)));
        let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
        let mut conn = rustls::ClientConnection::new(TLS_ANY.clone(), name).map_err(|e| e.to_string())?;
        while conn.is_handshaking() {
            conn.complete_io(&mut sock).map_err(|e| why(&e))?;
        }
        conn.peer_certificates().and_then(|c| c.first()).map(|c| c.to_vec()).ok_or_else(|| "el servidor no envió certificado".into())
    })();
    let der = match der {
        Ok(d) => d,
        Err(w) => return (false, None, w),
    };
    let ms = ms(t0);
    let left = match cert_expiry(&der) {
        Ok(t) => (t as f64 - now()) / 86400.0,
        Err(e) => return (false, Some(ms), trunc(&e.to_string(), 200)),
    };
    if left < 0.0 {
        return (false, Some(ms), format!("certificado caducado hace {} días", (-left) as i64 + 1));
    }
    (left > days, Some(ms), format!("certificado caduca en {} días", left as i64))
}

fn probe_dns(name: &str, expect: &str) -> (bool, Option<f64>, String) {
    let t0 = Instant::now();
    let ips: BTreeSet<String> = match (name, 0).to_socket_addrs() {
        Ok(a) => a.map(|s| s.ip().to_string()).collect(),
        Err(_) => return (false, None, "el nombre no resuelve".into()),
    };
    let first: Vec<&str> = ips.iter().take(3).map(String::as_str).collect();
    if !expect.is_empty() && !ips.contains(expect) {
        return (false, Some(ms(t0)), format!("resuelve a {}, no a {expect}", first.join(", ")));
    }
    (true, Some(ms(t0)), format!("resuelve a {}", first.join(", ")))
}

/// Una comprobación de cualquier tipo. Devuelve (va bien, ms, detalle).
pub fn run_check(c: &Row) -> (bool, Option<f64>, String) {
    let port = |d: i64| c.i("port").filter(|p| *p != 0).unwrap_or(d) as u16;
    match c.s("kind") {
        "tcp" => probe_tcp(c.s("host"), port(0)),
        "http" => probe_http(c.s("url"), c.s("expect")),
        "ssl" => probe_ssl(c.s("host"), port(443), c.f("warn_days").filter(|d| *d != 0.0).unwrap_or(30.0)),
        "dns" => probe_dns(c.s("host"), c.s("expect")),
        _ => {
            let (up, rtt) = ping(c.s("host"));
            (up, rtt, if up { String::new() } else { "no responde al ping".into() })
        }
    }
}

// ── Avisos: correo, Telegram y webhook. Lo guardado en catlan manda; lo que no, sale de las variables de entorno ──
pub const ALERT_KEYS: [&str; 9] = ["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "MAIL_FROM", "MAIL_TO", "TELEGRAM_TOKEN", "TELEGRAM_CHAT", "WEBHOOK_URL"];
/// Nunca salen por la API (la URL de un webhook es una llave).
pub const ALERT_SECRET: [&str; 3] = ["SMTP_PASS", "TELEGRAM_TOKEN", "WEBHOOK_URL"];
/// Lo que vino de variables de entorno al arrancar.
static ENV_ALERTS: LazyLock<HashMap<&'static str, String>> = LazyLock::new(|| ALERT_KEYS.iter().map(|k| (*k, std::env::var(format!("CATLAN_{k}")).unwrap_or_default())).collect());
static CFG: LazyLock<RwLock<HashMap<&'static str, String>>> = LazyLock::new(|| RwLock::new(ENV_ALERTS.clone()));

pub fn cfg(k: &str) -> String {
    CFG.read().unwrap_or_else(|e| e.into_inner()).get(k).cloned().unwrap_or_default()
}

pub fn saved_alerts() -> Result<Map<String, Value>> {
    let v = val("SELECT v FROM meta WHERE k='alerts'", p![])?;
    Ok(serde_json::from_str(v.as_str().unwrap_or("{}")).unwrap_or_default())
}

pub fn apply_alerts() -> Result<()> {
    let saved = saved_alerts()?;
    let mut c = CFG.write().unwrap_or_else(|e| e.into_inner());
    for k in ALERT_KEYS {
        let v = saved.get(k).and_then(Value::as_str).filter(|s| !s.is_empty()).map(String::from).unwrap_or_else(|| ENV_ALERTS[k].clone());
        c.insert(k, v);
    }
    Ok(())
}

pub fn alerts_view() -> Result<Value> {
    let saved = saved_alerts()?;
    let mut out = Map::new();
    for k in ALERT_KEYS.iter().filter(|k| !ALERT_SECRET.contains(k)) {
        out.insert(k.to_string(), cfg(k).into());
    }
    out.insert("set".into(), ALERT_SECRET.iter().map(|k| (k.to_string(), Value::from(!cfg(k).is_empty()))).collect::<Map<_, _>>().into());
    let hook = cfg("WEBHOOK_URL");
    out.insert("webhook_host".into(), hook.split_once("://").map(|(_, r)| r.split(['/', '?', '#']).next().unwrap_or("")).unwrap_or("").into());
    out.insert("env".into(), ALERT_KEYS.iter().filter(|k| !ENV_ALERTS[*k].is_empty() && !saved.get(**k).is_some_and(truthy)).copied().collect::<Vec<_>>().into());
    out.insert("channels".into(), channels().into());
    Ok(out.into())
}

pub fn check_alert(k: &str, v: &str) -> Result<()> {
    let (ok, msg) = match k {
        "SMTP_HOST" => (crate::validate::host_ok(v), "servidor de correo no válido"),
        "SMTP_PORT" => (v.parse::<u32>().is_ok_and(|p| (1..=65535).contains(&p)) && v.bytes().all(|b| b.is_ascii_digit()), "puerto del correo no válido"),
        "MAIL_FROM" => (re!(r"^[^@\s,]+@[^@\s,]+$").is_match(v), "remitente no válido"),
        "MAIL_TO" => (re!(r"^[^@\s,]+@[^@\s,]+(\s*,\s*[^@\s,]+@[^@\s,]+)*$").is_match(v), "destinatarios no válidos (separa varios con comas)"),
        "TELEGRAM_CHAT" => (re!(r"^(-?\d{1,20}|@\w{4,64})$").is_match(v), "chat de Telegram: un número o @canal"),
        "WEBHOOK_URL" => (re!(r"^https?://[^\s/]+\S{0,500}$").is_match(v), "el webhook empieza por http:// o https://"),
        "TELEGRAM_TOKEN" => (re!(r"^\d{3,20}:[\w-]{20,100}$").is_match(v), "token de Telegram no válido (123456:ABC…)"),
        _ => (true, ""),
    };
    if ok { Ok(()) } else { bad(msg) }
}

pub fn channels() -> Vec<&'static str> {
    let mut out = vec![];
    if !cfg("SMTP_HOST").is_empty() && !cfg("MAIL_TO").is_empty() {
        out.push("correo");
    }
    if !cfg("TELEGRAM_TOKEN").is_empty() && !cfg("TELEGRAM_CHAT").is_empty() {
        out.push("Telegram");
    }
    if !cfg("WEBHOOK_URL").is_empty() {
        out.push("webhook");
    }
    out
}

/// Envía un aviso a los destinatarios (separados por comas).
fn mail(subject: &str, text: &str) -> Result<()> {
    use lettre::Transport;
    use lettre::transport::smtp::{authentication::Credentials, client::Tls, client::TlsParameters};
    let host = cfg("SMTP_HOST");
    let from = [cfg("MAIL_FROM"), cfg("SMTP_USER"), "catlan@localhost".into()].into_iter().find(|s| !s.is_empty()).unwrap_or_default();
    let mut b = lettre::Message::builder().from(from.parse()?).subject(subject);
    for to in cfg("MAIL_TO").split(',') {
        b = b.to(to.trim().parse()?);
    }
    let msg = b.header(lettre::message::header::ContentType::TEXT_PLAIN).body(text.to_string())?;
    let port: u16 = cfg("SMTP_PORT").parse().unwrap_or(587);
    // Como hacía smtplib: STARTTLS si el servidor lo ofrece (465: TLS desde el principio), sin exigir un certificado
    // de una CA pública: los servidores de correo internos suelen llevar uno propio.
    let tls = TlsParameters::builder(host.clone()).dangerous_accept_invalid_certs(true).dangerous_accept_invalid_hostnames(true).build_rustls()?;
    let mut t = lettre::SmtpTransport::builder_dangerous(&host).port(port).timeout(Some(Duration::from_secs(15))).tls(if port == 465 { Tls::Wrapper(tls) } else { Tls::Opportunistic(tls) });
    let user = cfg("SMTP_USER");
    if !user.is_empty() {
        t = t.credentials(Credentials::new(user, cfg("SMTP_PASS")));
    }
    t.build().send(&msg)?;
    Ok(())
}

fn post_json(url: &str, data: &Value) -> Result<()> {
    match HTTP.post(url).timeout(Duration::from_secs(10)).set("Content-Type", "application/json").send_string(&data.to_string()) {
        Ok(_) => Ok(()),
        Err(ureq::Error::Status(c, r)) => bad(format!("HTTP Error {c}: {}", r.status_text())),
        Err(ureq::Error::Transport(t)) => bad(why(&t)),
    }
}

/// Avisa por todos los canales configurados; si uno falla, los demás salen igual. Devuelve {canal: error o null}.
pub fn notify(subject: &str, text: &str) -> Map<String, Value> {
    let mut out = Map::new();
    for ch in channels() {
        let r = match ch {
            "correo" => mail(subject, text),
            "Telegram" => post_json(&format!("https://api.telegram.org/bot{}/sendMessage", cfg("TELEGRAM_TOKEN")), &json!({"chat_id": cfg("TELEGRAM_CHAT"), "text": format!("{subject}\n\n{text}")})),
            // «text» lo leen Slack, Teams, Mattermost y Google Chat; «content», Discord
            _ => post_json(&cfg("WEBHOOK_URL"), &json!({"text": format!("{subject}\n{text}"), "content": format!("{subject}\n{text}"), "subject": subject, "body": text})),
        };
        match r {
            Ok(()) => out.insert(ch.into(), Value::Null),
            Err(e) => {
                let msg = trunc(&e.to_string(), 200);
                println!("aviso por {ch} fallido: {msg}");
                out.insert(ch.into(), msg.into())
            }
        };
    }
    out
}

/// En silencio o en un mantenimiento programado (desde mute_from, si lo hay, hasta mute_until; en UTC).
pub fn muted(row: &Row) -> bool {
    let now = utc("%Y-%m-%d %H:%M:%S");
    !row.s("mute_until").is_empty() && row.s("mute_until") > now.as_str() && row.s("mute_from") <= now.as_str()
}

/// Avisa si el estado no es el último avisado. Silenciado no avisa: al acabar el silencio, si sigue mal, avisa entonces.
fn alert(table: &str, row: &Row, state: Option<&str>, good: &str, subject: &str, text: &str) -> Result<()> {
    let alerted = row.get("alerted").and_then(Value::as_str);
    let Some(state) = state else { return Ok(()) };
    if Some(state) == alerted || muted(row) {
        return Ok(());
    }
    q(&format!("UPDATE {table} SET alerted=? WHERE id=?"), p![state, &row["id"]])?;
    if !(alerted.is_none() && state == good) {
        // el primer «va bien» no es noticia
        notify(subject, &format!("{text}\n\n-- catlan"));
    }
    Ok(())
}

pub const CHECKS: &str = "SELECT c.*, i.name AS item_name FROM checks c LEFT JOIN items i ON i.id = c.item";
pub const SOURCES: &str = "SELECT s.*, i.name AS item_name FROM sources s LEFT JOIN items i ON i.id = s.item";

fn probe(c: Row) -> Result<()> {
    let (up, rtt, detail) = run_check(&c);
    let fails = if up { 0 } else { c.i("fails").unwrap_or(0) + 1 };
    let old = c.get("state").and_then(Value::as_str);
    // 2 fallos seguidos: sin falsas alarmas por un paquete perdido
    let state = if up {
        Some("up")
    } else if fails >= 2 {
        Some("down")
    } else {
        old
    };
    q("INSERT INTO pings(check_id, up, rtt) VALUES(?,?,?)", p![&c["id"], up, rtt.map_or(crate::db::SqlV::Null, crate::db::SqlV::Real)])?;
    let since = if state != old { ", since=CURRENT_TIMESTAMP" } else { "" };
    q(&format!("UPDATE checks SET state=?, fails=?, rtt=?, detail=?{since} WHERE id=?"), p![state, fails, rtt.map_or(crate::db::SqlV::Null, crate::db::SqlV::Real), &detail, &c["id"]])?;
    if state == Some("down")
        && let Some(item) = c.i("item").filter(|i| *i != 0)
        && dependents()?.get(&item).is_some_and(|v| !v.is_empty())
    {
        return Ok(()); // cae porque cae otro del que cuelga: se avisa del culpable; si sigue caído cuando este vuelva, avisará entonces
    }
    let name = [c.s("label"), c.s("item_name"), c.s("host")].into_iter().find(|s| !s.is_empty()).unwrap_or("");
    let target = if c.s("kind") == "http" { c.s("url") } else { c.s("host") };
    let (subject, text) = if state == Some("down") {
        (format!("catlan: {name}: {detail}"), format!("{name} ({target}): {detail}"))
    } else {
        (format!("catlan: {name} vuelve a funcionar"), format!("{name} ({target}) vuelve a funcionar: {detail}"))
    };
    alert("checks", &c, state, "up", &subject, &text)
}

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Key {
    Item(i64),
    Free(String),
}

/// Equipos caídos solo porque cae otro del que cuelgan en un esquema: {item: [nombres de los culpables]}.
/// Los esquemas no tienen dirección, así que la da quien sigue funcionando: en cada grupo de caídos conectados,
/// el culpable es el que toca algo que funciona (o algo sin monitor, que cuenta como que funciona: en la duda, avisar).
pub fn dependents() -> Result<HashMap<i64, Vec<String>>> {
    let mut by_item: HashMap<i64, Vec<Row>> = HashMap::new();
    for c in q("SELECT item, state, fails FROM checks WHERE item IS NOT NULL", p![])? {
        if let Some(i) = c.i("item") {
            by_item.entry(i).or_default().push(c);
        }
    }
    // un equipo está caído si todas sus comprobaciones fallan; fallando sin llegar a «caído» ya cuenta (llegan a destiempo)
    let down: HashSet<Key> = by_item.iter().filter(|(_, cs)| cs.iter().all(|c| c.s("state") == "down" || c.t("fails"))).map(|(i, _)| Key::Item(*i)).collect();
    let names: HashMap<i64, String> = q("SELECT id, name FROM items", p![])?.into_iter().map(|r| (r.i("id").unwrap_or(0), r.s("name").to_string())).collect();
    let mut verdict: HashMap<Key, Option<BTreeSet<String>>> = HashMap::new(); // None: en algún esquema es él el culpable
    for r in q("SELECT id, data FROM maps", p![])? {
        let d: Value = serde_json::from_str(r.s("data")).unwrap_or_default();
        if d.s("type") == "rack" {
            continue;
        }
        let mut key: HashMap<String, Key> = HashMap::new();
        let mut adj: IndexMap<Key, HashSet<Key>> = IndexMap::new();
        for n in d["nodes"].as_array().into_iter().flatten().filter_map(Value::as_object) {
            let Some(id) = n.get("id") else { continue };
            let id = id.as_str().map(String::from).unwrap_or_else(|| id.to_string());
            let k = match n.get("item").filter(|v| truthy(v)) {
                Some(v) if v.is_i64() => Key::Item(v.as_i64().unwrap()),
                Some(v) => Key::Free(format!("item:{v}")),
                None => Key::Free(id.clone()),
            };
            adj.entry(k.clone()).or_default();
            key.insert(id, k);
        }
        for link in d["links"].as_array().into_iter().flatten().filter_map(Value::as_array) {
            if link.len() < 2 {
                continue;
            }
            let id = |v: &Value| v.as_str().map(String::from).unwrap_or_else(|| v.to_string());
            if let (Some(a), Some(b)) = (key.get(&id(&link[0])).cloned(), key.get(&id(&link[1])).cloned()) {
                adj.entry(a.clone()).or_default().insert(b.clone());
                adj.entry(b).or_default().insert(a);
            }
        }
        let mut seen: HashSet<Key> = HashSet::new();
        for start in adj.keys().filter(|k| down.contains(k)).cloned().collect::<Vec<_>>() {
            if seen.contains(&start) {
                continue;
            }
            let (mut group, mut todo) = (BTreeSet::new(), vec![start]);
            while let Some(k) = todo.pop() {
                // grupo de caídos conectados entre sí
                if group.insert(k.clone()) {
                    todo.extend(adj[&k].iter().filter(|n| down.contains(n)).cloned());
                }
            }
            seen.extend(group.iter().cloned());
            let mut causes: BTreeSet<Key> = group.iter().filter(|k| adj[*k].iter().any(|n| !down.contains(n))).cloned().collect();
            if causes.is_empty() {
                causes = group.clone(); // nadie toca nada que funcione: avisan todos
            }
            for k in &group {
                if causes.contains(k) {
                    verdict.insert(k.clone(), None);
                } else if let Some(set) = verdict.entry(k.clone()).or_insert_with(|| Some(BTreeSet::new())) {
                    set.extend(causes.iter().map(|c| match c {
                        Key::Item(i) => names.get(i).cloned().unwrap_or("?".into()),
                        Key::Free(_) => "?".into(),
                    }));
                }
            }
        }
    }
    Ok(verdict
        .into_iter()
        .filter_map(|(k, v)| match (k, v) {
            (Key::Item(i), Some(v)) if !v.is_empty() => Some((i, v.into_iter().collect())),
            _ => None,
        })
        .collect())
}

// ── El hilo del monitor: irrompible; un fallo queda en la consola y en la salud de catlan ──
struct Mon {
    beat: f64,
    error: String,
    error_at: Option<f64>,
    thread: Option<std::thread::JoinHandle<()>>,
}
static MON: LazyLock<Mutex<Mon>> = LazyLock::new(|| Mutex::new(Mon { beat: now(), error: String::new(), error_at: None, thread: None }));

pub fn mon_error(msg: String) {
    let msg = trunc(&msg, 300);
    println!("monitor: {msg}");
    let mut m = lock(&MON);
    m.error = msg;
    m.error_at = Some(now());
}

fn panic_msg(p: &(dyn std::any::Any + Send)) -> String {
    p.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| p.downcast_ref::<String>().cloned()).unwrap_or_else(|| "pánico".into())
}

/// Lo que corre en el pool: un fallo (o un pánico) queda anotado, no se pierde en silencio.
pub fn guarded(name: &str, f: impl FnOnce() -> Result<()>) {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => mon_error(format!("{name}: {e}")),
        Err(p) => mon_error(format!("{name}: {}", panic_msg(&*p))),
    }
}

/// Latido del monitor: si el hilo murió, se vuelve a arrancar; si va atrasado, la web lo dice.
pub fn monitor_health() -> Value {
    let dead = lock(&MON).thread.as_ref().is_some_and(|t| t.is_finished());
    if dead {
        start_monitor();
    }
    let m = lock(&MON);
    json!({"age": (now() - m.beat) as i64, "error": m.error, "error_ago": m.error_at.map(|t| (now() - t) as i64)})
}

/// El monitor, vigilado: si su hilo muere (un pánico fuera de `guarded`), se anota y vuelve a arrancar solo.
pub fn start_monitor() {
    let t = std::thread::spawn(|| {
        loop {
            if let Err(p) = std::thread::spawn(monitor).join() {
                mon_error(format!("el monitor se paró ({}); vuelve a arrancar", panic_msg(&*p)));
            }
            std::thread::sleep(Duration::from_secs(5));
        }
    });
    lock(&MON).thread = Some(t);
}

type Job = Box<dyn FnOnce() + Send>;

/// Hasta 64 comprobaciones a la vez: con muchas lentas (8 s de espera) no se forma cola.
struct Pool(mpsc::Sender<Job>);
impl Pool {
    fn new(n: usize) -> Pool {
        let (tx, rx) = mpsc::channel::<Job>();
        let rx = Arc::new(Mutex::new(rx));
        for _ in 0..n {
            let rx = rx.clone();
            std::thread::spawn(move || {
                loop {
                    let job = lock(&rx).recv();
                    match job {
                        Ok(j) => j(),
                        Err(_) => break,
                    }
                }
            });
        }
        Pool(tx)
    }
    fn submit(&self, f: impl FnOnce() + Send + 'static) {
        let _ = self.0.send(Box::new(f));
    }
}

fn monitor() {
    let pool = Pool::new(64);
    let mut n: u64 = 0;
    loop {
        n += 1; // fuera del try: si una vuelta falla, lo de «cada 10 min» no se reintenta cada 2 s
        // una BD ocupada o un disco lleno no paran la vigilancia: se reintenta en la vuelta siguiente
        guarded("vuelta", || monitor_round(&pool, n));
        lock(&MON).beat = now();
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// Una vuelta: lanza lo que toca y, cada tanto, resúmenes, avisos de caducidad, copia diaria y limpieza.
fn monitor_round(pool: &Pool, n: u64) -> Result<()> {
    for c in q(&format!("{CHECKS} WHERE c.last IS NULL OR c.last <= datetime('now', '-' || c.every || ' seconds')"), p![])? {
        q("UPDATE checks SET last=CURRENT_TIMESTAMP WHERE id=?", p![&c["id"]])?; // marcado antes: no se lanza dos veces
        pool.submit(move || guarded("probe", || probe(c)));
    }
    for src in q(&format!("{SOURCES} WHERE s.kind != 'kitty' AND (s.last IS NULL OR s.last <= datetime('now', '-' || s.every || ' seconds'))"), p![])? {
        q("UPDATE sources SET last=CURRENT_TIMESTAMP WHERE id=?", p![&src["id"]])?;
        pool.submit(move || guarded("gather", || gather(&src)));
    }
    // los Kitty envían ellos; tres envíos sin noticias = apagado o sin red
    for src in q(&format!("{SOURCES} WHERE s.kind = 'kitty' AND COALESCE(s.error, '') != ? AND s.last <= datetime('now', '-' || (3 * s.every) || ' seconds')"), p![KITTY_LOST])? {
        save_health(&src, &[], &[], None, Some(KITTY_LOST))?;
    }
    if n % 300 == 1 {
        // al arrancar y cada 10 min
        rollup()?;
        warranties()?;
        daily_backup()?;
    }
    if n.is_multiple_of(1800) {
        // en bruto, unos días; lo de antes ya está resumido por horas (días: Opciones → Salud de catlan)
        let r = retention();
        let d = |k: &str| r[k].as_i64().unwrap_or(1);
        q("DELETE FROM pings WHERE ts < datetime('now', ?)", p![format!("-{} days", d("raw"))])?;
        q("DELETE FROM metrics WHERE ts < datetime('now', ?)", p![format!("-{} days", d("raw"))])?;
        q("DELETE FROM syslog WHERE ts < datetime('now', ?)", p![format!("-{} days", d("syslog"))])?;
        q("DELETE FROM pings_h WHERE hour < datetime('now', ?)", p![format!("-{} days", d("hours"))])?;
        q("DELETE FROM metrics_h WHERE hour < datetime('now', ?)", p![format!("-{} days", d("hours"))])?;
        lock(writer()).execute_batch("PRAGMA optimize")?; // tras borrar mucho, que SQLite revise sus estadísticas
    }
    Ok(())
}

/// Días que se guarda cada cosa: (clave, por defecto, mínimo, máximo). Por horas, más de un año por defecto, para
/// comparar con el mismo mes del año anterior.
const RETENTION: [(&str, i64, i64, i64); 3] = [("raw", 7, 1, 90), ("syslog", 30, 1, 365), ("hours", KEEP_DAYS, 30, 1000)];
pub const KEEP_DAYS: i64 = 400;
pub const MAX_HOURS: i64 = 24 * 1000;

pub fn retention() -> Value {
    let saved = val("SELECT v FROM meta WHERE k='retention'", p![]).ok().and_then(|v| v.as_str().and_then(|s| serde_json::from_str::<Value>(s).ok())).unwrap_or_default();
    RETENTION.iter().map(|&(k, def, lo, hi)| (k.to_string(), json!(saved[k].as_i64().unwrap_or(def).clamp(lo, hi)))).collect::<Map<_, _>>().into()
}

pub fn set_retention(b: &Value) -> Result<Value> {
    let mut v = retention();
    for &(k, _, lo, hi) in &RETENTION {
        match b.get(k) {
            None => {}
            Some(x) if x.as_i64().is_some_and(|n| (lo..=hi).contains(&n)) => v[k] = x.clone(),
            Some(_) => return bad(format!("{k}: entre {lo} y {hi} días")),
        }
    }
    q("INSERT OR REPLACE INTO meta(k, v) VALUES('retention', ?)", p![v.to_string()])?;
    Ok(v)
}

/// Resume por horas (media, mínimo y máximo) las horas ya cerradas. Empieza en la última hora resumida
/// y la rehace, así que no importa haber estado apagado ni que una hora se resumiera a medias.
pub fn rollup() -> Result<()> {
    let (h, this) = ("strftime('%Y-%m-%d %H:00:00', ts)", "strftime('%Y-%m-%d %H:00:00', 'now')");
    let start = val("SELECT COALESCE(max(hour), '') FROM pings_h", p![])?;
    q(
        &format!(
            "INSERT OR REPLACE INTO pings_h SELECT check_id, {h} AS h, count(*), sum(up), avg(rtt), min(rtt), max(rtt) \
             FROM pings WHERE ts >= ? AND ts < {this} GROUP BY check_id, h"
        ),
        p![start],
    )?;
    let start = val("SELECT COALESCE(max(hour), '') FROM metrics_h", p![])?;
    q(
        &format!(
            "INSERT OR REPLACE INTO metrics_h SELECT source_id, key, {h} AS h, max(label), max(unit), avg(value), min(value), max(value) \
             FROM metrics WHERE ts >= ? AND ts < {this} GROUP BY source_id, key, h"
        ),
        p![start],
    )?;
    Ok(())
}

/// Disponibilidad de cada comprobación en un mes (hora local del servidor), sacada de los resúmenes por hora.
/// shortcut: la hora en curso aún no está resumida, así que el mes actual va hasta 1 h por detrás.
pub fn sla(month: &str) -> Result<Value> {
    if !re!(r"^\d{4}-(0[1-9]|1[0-2])$").is_match(month) {
        return bad("mes no válido: AAAA-MM");
    }
    let first = format!("{month}-01");
    let r = q(
        "SELECT datetime(?, 'utc') AS s, datetime(?, '+1 month', 'utc') AS e, (min(strftime('%s', datetime(?, '+1 month', 'utc')), \
         strftime('%s', 'now')) - strftime('%s', datetime(?, 'utc'))) / 3600 AS h",
        p![&first, &first, &first, &first],
    )?
    .one()
    .unwrap_or_default();
    let hours = r.i("h").unwrap_or(0);
    let mut rows = vec![];
    for mut c in q(
        "SELECT c.id, COALESCE(NULLIF(c.label, ''), i.name, c.host) AS name, c.kind, c.host, c.every, c.item, \
         sum(h.n) AS n, sum(h.up) AS up, count(h.hour) AS hours, sum(h.rtt * h.n) / sum(CASE WHEN h.rtt IS NULL THEN 0 ELSE h.n END) AS rtt \
         FROM checks c LEFT JOIN items i ON i.id = c.item LEFT JOIN pings_h h ON h.check_id = c.id AND h.hour >= ? AND h.hour < ? \
         GROUP BY c.id ORDER BY name COLLATE NOCASE",
        p![&r["s"], &r["e"]],
    )? {
        let (n, up, every) = (c.i("n").unwrap_or(0), c.i("up").unwrap_or(0), c.f("every").unwrap_or(0.0));
        let ch = c.f("hours").unwrap_or(0.0);
        c.insert("uptime".into(), if n != 0 { json!(up as f64 / n as f64) } else { Value::Null });
        // cada fallo cuenta como un intervalo entero
        c.insert("down_min".into(), if n != 0 { json!(((n - up) as f64 * every / 60.0).round_ties_even() as i64) } else { Value::Null });
        c.insert("coverage".into(), json!(if hours > 0 { (ch / hours as f64).min(1.0) } else { 0.0 }));
        let rtt = c.f("rtt").map(|v| round(v, 1));
        c.insert("rtt".into(), json!(rtt));
        rows.push(c);
    }
    let known: Vec<f64> = rows.iter().filter_map(|r| r.f("uptime")).collect();
    let avg = if known.is_empty() { Value::Null } else { json!(known.iter().sum::<f64>() / known.len() as f64) };
    Ok(json!({"month": month, "hours": hours.max(0), "avg": avg, "checks": rows, "first": val("SELECT min(hour) FROM pings_h", p![])?}))
}

pub fn monitor_state() -> Result<Value> {
    let deps = dependents()?;
    let mut out = vec![];
    for mut c in q(&format!("{CHECKS} ORDER BY COALESCE(NULLIF(c.label, ''), i.name, c.host) COLLATE NOCASE"), p![])? {
        let id = c["id"].clone();
        c.insert("uptime".into(), val("SELECT avg(up) FROM pings WHERE check_id=? AND ts > datetime('now', '-1 day')", p![&id])?);
        let mut recent: Vec<Value> = q("SELECT up FROM pings WHERE check_id=? ORDER BY rowid DESC LIMIT 40", p![&id])?.into_iter().map(|r| r["up"].clone()).collect();
        recent.reverse();
        c.insert("recent".into(), recent.into());
        let dep = if c.s("state") == "down" { c.i("item").and_then(|i| deps.get(&i)).map(|v| json!(v)).unwrap_or(Value::Null) } else { Value::Null };
        c.insert("dep".into(), dep);
        out.push(c);
    }
    let srcs: Vec<Value> = q(SOURCES, p![])?
        .into_iter()
        .map(|r| {
            let name = [r.s("label"), r.s("item_name"), r.s("host")].into_iter().find(|s| !s.is_empty()).unwrap_or("").to_string();
            let problems: Value = serde_json::from_str(r.s("problems")).unwrap_or(json!([]));
            json!({"id": r["id"], "name": name, "state": r["state"], "problems": problems, "error": r["error"],
                   "mute_until": r["mute_until"], "mute_from": r["mute_from"]})
        })
        .collect();
    Ok(json!({"channels": channels(), "checks": out, "sources": srcs, "monitor": monitor_health()}))
}

/// Las garantías, licencias, dominios… que caducan hoy o dentro de 30 días, una vez al día: el texto del aviso.
pub fn warranties_due() -> Result<Option<String>> {
    let today = crate::util::local("%Y-%m-%d");
    if val("SELECT v FROM meta WHERE k='warranty_day'", p![])?.as_str() == Some(today.as_str()) {
        return Ok(None);
    }
    q("INSERT OR REPLACE INTO meta(k, v) VALUES('warranty_day', ?)", p![&today])?;
    let days = "(date('now', 'localtime'), date('now', 'localtime', '+30 days'))";
    let rows = q(
        &format!(
            "SELECT name, warranty AS day, 'garantía' AS kind FROM items WHERE warranty IN {days} UNION ALL \
             SELECT name, date, kind FROM expiries WHERE date IN {days} ORDER BY day, name COLLATE NOCASE"
        ),
        p![],
    )?;
    if rows.is_empty() {
        return Ok(None);
    }
    let lines: Vec<String> = rows.iter().map(|r| format!("- {}: {} ({})", r.s("name"), if r.s("day") == today { "hoy".into() } else { format!("el {}", r.s("day")) }, r.s("kind"))).collect();
    Ok(Some(lines.join("\n") + "\n\n-- catlan"))
}

/// Una vez al día: avisa de las garantías, licencias, dominios… que caducan dentro de 30 días y de los que caducan hoy.
pub fn warranties() -> Result<()> {
    if let Some(text) = warranties_due()?
        && !channels().is_empty()
    {
        notify("catlan: caducidades", &text);
    }
    Ok(())
}

/// Una copia al día en data/backups/; se quedan las 7 últimas.
fn daily_backup() -> Result<()> {
    let (d, day) = (DATA.join("backups"), crate::util::local("%Y%m%d"));
    if d.join(format!("catlan-{day}.db")).exists() {
        return Ok(());
    }
    std::fs::create_dir_all(&d)?;
    let tmp = d.join(format!(".catlan-{day}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    crate::db::backup_to(&tmp)?;
    std::fs::rename(&tmp, d.join(format!("catlan-{day}.db")))?; // a medias nunca cuenta como copia
    let old = backups()?;
    for f in old.iter().take(old.len().saturating_sub(7)) {
        let _ = std::fs::remove_file(f);
    }
    Ok(())
}

fn backups() -> Result<Vec<std::path::PathBuf>> {
    let d = DATA.join("backups");
    if !d.exists() {
        return Ok(vec![]);
    }
    let mut v: Vec<_> =
        std::fs::read_dir(d)?.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("catlan-") && n.ends_with(".db"))).collect();
    v.sort();
    Ok(v)
}

pub static STARTED: LazyLock<String> = LazyLock::new(|| utc("%Y-%m-%d %H:%M:%S"));

/// La salud del propio catlan.
pub fn system_health() -> Result<Value> {
    let size = |f: std::path::PathBuf| std::fs::metadata(f).map(|m| m.len()).unwrap_or(0);
    let late = val("SELECT COUNT(*) FROM checks WHERE last IS NOT NULL AND last < datetime('now', '-' || (every * 3 + 60) || ' seconds')", p![])?.as_i64().unwrap_or(0)
        + val("SELECT COUNT(*) FROM sources WHERE kind != 'kitty' AND last IS NOT NULL AND last < datetime('now', '-' || (every * 3 + 60) || ' seconds')", p![])?.as_i64().unwrap_or(0);
    let mut bk = vec![];
    for f in backups()?.iter().rev() {
        let md = std::fs::metadata(f)?;
        let at: chrono::DateTime<chrono::Utc> = md.modified()?.into();
        bk.push(json!({"name": f.file_name().map(|n| n.to_string_lossy().to_string()), "bytes": md.len(), "at": at.format("%Y-%m-%d %H:%M:%S").to_string()}));
    }
    let mut counts = Map::new();
    for t in ["items", "pages", "checks", "sources", "incidents", "log", "metrics", "syslog"] {
        counts.insert(t.into(), val(&format!("SELECT COUNT(*) FROM {t}"), p![])?);
    }
    Ok(json!({"version": crate::config::VERSION, "schema": crate::db::user_version()?, "db_bytes": size(db_path()),
        "wal_bytes": size(DATA.join("catlan.db-wal")), "integrity": crate::db::INTEGRITY.get(), "started": *STARTED, "backups": bk,
        "monitor": monitor_health(), "late": late, "syslog": *SYSLOG_PORT, "https": crate::server::TLS.get().map_or("", |t| t.pin.as_str()), "rejected": crate::server::REJECTED.load(std::sync::atomic::Ordering::Relaxed), "counts": counts}))
}

/// Nunca salen por la API ni al historial.
pub const SECRET: [&str; 3] = ["community", "pass", "priv_pass"];

pub fn health() -> Result<Value> {
    let agents: HashMap<i64, Value> = q("SELECT source, id FROM agents WHERE source IS NOT NULL", p![])?.into_iter().filter_map(|r| Some((r.i("source")?, r["id"].clone()))).collect();
    let mut out = vec![];
    for mut s in q(&format!("{SOURCES} ORDER BY COALESCE(NULLIF(s.label, ''), i.name, s.host) COLLATE NOCASE"), p![])? {
        for k in SECRET {
            s.shift_remove(k);
        }
        let id = s.i("id").unwrap_or(0);
        let problems: Value = serde_json::from_str(s.s("problems")).unwrap_or(json!([]));
        let info: Value = serde_json::from_str(s.s("info")).unwrap_or(json!({}));
        s.insert("problems".into(), problems);
        s.insert("info".into(), info);
        s.insert("agent".into(), agents.get(&id).cloned().unwrap_or(Value::Null));
        let latest = q("SELECT key, label, value, unit FROM metrics WHERE source_id=? AND ts = (SELECT max(ts) FROM metrics WHERE source_id=?) ORDER BY key", p![id, id])?;
        s.insert("latest".into(), latest.rows.into_iter().map(Value::Object).collect::<Vec<_>>().into());
        out.push(Value::Object(s));
    }
    Ok(out.into())
}

/// Histórico agrupado en ~300 puntos por serie, sea cual sea el rango. Más allá de 7 días solo quedan los resúmenes por hora.
pub fn series(source: i64, hours: i64) -> Result<Value> {
    let step = 60.max(hours * 3600 / 300);
    let (t, ts, v) = if hours <= 168 { ("metrics", "ts", "value") } else { ("metrics_h", "hour", "v") };
    let mut out = Map::new();
    for r in q(
        &format!(
            "SELECT key, label, unit, min({ts}) AS ts, avg({v}) AS v FROM {t} WHERE source_id=? AND {ts} > datetime('now', ?) \
             GROUP BY key, CAST(strftime('%s', {ts}) / ? AS INTEGER) ORDER BY ts"
        ),
        p![source, format!("-{hours} hours"), step],
    )? {
        let s = out.entry(r.s("key")).or_insert_with(|| json!({"label": r["label"], "unit": r["unit"], "points": []}));
        if let Some(p) = s["points"].as_array_mut() {
            p.push(json!([r["ts"], r.f("v").map(|x| round(x, 2))]));
        }
    }
    Ok(out.into())
}

/// Latencia media de cada dispositivo del monitor, agrupada en ~120 puntos.
pub fn latency(hours: i64) -> Result<Value> {
    let step = 60.max(hours * 3600 / 120);
    let (t, ts) = if hours <= 168 { ("pings", "ts") } else { ("pings_h", "hour") };
    let mut out = Map::new();
    for r in q(
        &format!(
            "SELECT check_id, min({ts}) AS ts, avg(rtt) AS v FROM {t} WHERE {ts} > datetime('now', ?) AND rtt IS NOT NULL \
             GROUP BY check_id, CAST(strftime('%s', {ts}) / ? AS INTEGER) ORDER BY ts"
        ),
        p![format!("-{hours} hours"), step],
    )? {
        let e = out.entry(r["check_id"].to_string()).or_insert_with(|| json!([]));
        if let Some(a) = e.as_array_mut() {
            a.push(json!([r["ts"], r.f("v").map(|x| round(x, 2))]));
        }
    }
    Ok(out.into())
}

/// Cambia con cada lectura guardada en Salud: la web, abierta en Salud, se entera por su WebSocket.
pub static HEALTH: LazyLock<tokio::sync::watch::Sender<u64>> = LazyLock::new(|| tokio::sync::watch::channel(0).0);

/// Guarda una lectura (de SNMP o de un Kitty), el estado del equipo, y avisa si cambia.
pub fn save_health(src: &Row, out: &[M], probs: &[String], info: Option<&Map<String, Value>>, err: Option<&str>) -> Result<()> {
    HEALTH.send_modify(|v| *v = v.wrapping_add(1));
    let state = if err.is_some() {
        "error"
    } else if !probs.is_empty() {
        "warn"
    } else {
        "ok"
    };
    if !out.is_empty() {
        let mut c = lock(writer());
        let tx = c.transaction()?;
        {
            let mut st = tx.prepare_cached("INSERT INTO metrics(source_id, key, label, value, unit) VALUES(?,?,?,?,?)")?;
            for (k, l, v, u) in out {
                st.execute(rusqlite::params![src.i("id"), k, l, v, u])?;
            }
        }
        tx.commit()?;
    }
    let since = if Some(state) != src.get("state").and_then(Value::as_str) { ", since=CURRENT_TIMESTAMP" } else { "" };
    q(
        &format!("UPDATE sources SET state=?, problems=?, error=?, info=COALESCE(?, info){since} WHERE id=?"),
        p![state, json!(probs).to_string(), err, info.filter(|i| !i.is_empty()).map(|i| Value::Object(i.clone()).to_string()), &src["id"]],
    )?;
    let name = [src.s("label"), src.s("item_name"), src.s("host")].into_iter().find(|s| !s.is_empty()).unwrap_or("");
    let host = src.s("host");
    let list: Vec<String> = if probs.is_empty() { err.map(String::from).into_iter().collect() } else { probs.to_vec() };
    let (subject, text) = if state == "ok" {
        (format!("catlan: {name} vuelve a estar bien"), format!("{name} ({host}) ya no tiene avisos."))
    } else {
        (format!("catlan: {name}: {}", list.first().cloned().unwrap_or_default()), format!("{name} ({host}):\n\n{}", list.iter().map(|p| format!("- {p}")).collect::<Vec<_>>().join("\n")))
    };
    alert("sources", src, Some(state), "ok", &subject, &text)
}

fn gather(src: &Row) -> Result<()> {
    match collect(src) {
        Ok((out, probs, info)) => save_health(src, &out, &probs, Some(&info), None),
        Err(e) => save_health(src, &[], &[], None, Some(&trunc(&e.to_string(), 300))),
    }
}

/// Syslog por UDP (RFC 3164 y 5424): cada mensaje va a la ficha del equipo del inventario con esa IP.
/// Lo que llega de IPs que no están en el inventario se descarta.
pub fn syslog_server() {
    let s = match UdpSocket::bind(("0.0.0.0", *SYSLOG_PORT)) {
        Ok(s) => s,
        Err(e) => {
            println!("syslog: no puedo escuchar en UDP {} ({e}); prueba con otro CATLAN_SYSLOG_PORT (0 = sin syslog)", *SYSLOG_PORT);
            return;
        }
    };
    let mut buf = vec![0u8; 8192];
    loop {
        // shortcut: sin límite de mensajes por segundo; si un equipo inunda, fíltralo en el equipo o en el cortafuegos
        let r = (|| -> Result<()> {
            let (n, from) = s.recv_from(&mut buf)?;
            let ip = from.ip().to_string();
            let Some(item) = q("SELECT id FROM items WHERE ip=? ORDER BY id LIMIT 1", p![&ip])?.one() else { return Ok(()) };
            let data = &buf[..n];
            let pri = re!(r"^<(\d{1,3})>").captures(std::str::from_utf8(&data[..data.len().min(5)]).unwrap_or(""));
            let (start, sev) = match &pri {
                Some(c) => (c[0].len(), c[1].parse::<i64>().unwrap_or(6) & 7),
                None => (0, 6),
            };
            let msg = trunc(String::from_utf8_lossy(&data[start..]).trim(), 1000);
            q("INSERT INTO syslog(item, ip, sev, msg) VALUES(?,?,?,?)", p![&item["id"], &ip, sev, msg])?;
            Ok(())
        })();
        if let Err(e) = r {
            println!("syslog: {e}"); // un paquete raro no tumba el receptor
        }
    }
}

// ── Redes IPv4: subredes, IPs libres y en uso ──
#[derive(Clone, Copy)]
pub struct Net4 {
    pub net: u32,
    pub prefix: u32,
}

pub enum NetErr {
    Bad,
    V6,
}

/// Como `ip_network(s, strict=False)`: "10.0.0.7/24" -> 10.0.0.0/24; sin prefijo, /32.
pub fn parse_net(s: &str) -> Result<Net4, NetErr> {
    let (a, pfx) = s.split_once('/').map(|(a, p)| (a, Some(p))).unwrap_or((s, None));
    if let Ok(ip) = a.parse::<Ipv4Addr>() {
        let prefix = match pfx {
            None => 32,
            Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => p.parse().map_err(|_| NetErr::Bad)?,
            Some(p) => {
                let m = u32::from(p.parse::<Ipv4Addr>().map_err(|_| NetErr::Bad)?);
                if m.leading_ones() + m.trailing_zeros() != 32 {
                    return Err(NetErr::Bad);
                }
                m.leading_ones()
            }
        };
        if prefix > 32 {
            return Err(NetErr::Bad);
        }
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        return Ok(Net4 { net: u32::from(ip) & mask, prefix });
    }
    let v6_prefix_ok = pfx.is_none_or(|p| p.parse::<u32>().is_ok_and(|n| n <= 128));
    if a.parse::<std::net::Ipv6Addr>().is_ok() && v6_prefix_ok { Err(NetErr::V6) } else { Err(NetErr::Bad) }
}

impl Net4 {
    pub fn num_addresses(&self) -> u64 {
        1u64 << (32 - self.prefix)
    }
    pub fn contains(&self, a: u32) -> bool {
        (a as u64) >= self.net as u64 && (a as u64) < self.net as u64 + self.num_addresses()
    }
    /// Las direcciones de equipos: sin la de red ni la de difusión (salvo en /31 y /32).
    pub fn hosts(&self) -> impl Iterator<Item = u32> {
        let (first, last) = match self.prefix {
            32 => (self.net as u64, self.net as u64),
            31 => (self.net as u64, self.net as u64 + 1),
            _ => (self.net as u64 + 1, self.net as u64 + self.num_addresses() - 2),
        };
        (first..=last).map(|x| x as u32)
    }
}

impl std::fmt::Display for Net4 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}/{}", Ipv4Addr::from(self.net), self.prefix)
    }
}

/// Una subred: cada IP en uso (inventario y último escaneo) y los conflictos: una IP en dos equipos del inventario,
/// o que responde en la red sin estar en el inventario.
pub fn ipam(row: &Row) -> Result<Value> {
    let Ok(net) = parse_net(row.s("cidr")) else { return bad("red no válida") };
    let mut used: BTreeMap<u32, Vec<Value>> = BTreeMap::new();
    for r in q("SELECT id, name, ip FROM items WHERE ip != ''", p![])? {
        if let Ok(a) = r.s("ip").trim().parse::<Ipv4Addr>()
            && net.contains(u32::from(a))
        {
            used.entry(u32::from(a)).or_default().push(json!({"id": r["id"], "name": r["name"]}));
        }
    }
    let scan: BTreeMap<u32, Value> = serde_json::from_str::<Vec<Value>>(row.s("scan"))
        .unwrap_or_default()
        .into_iter()
        .filter_map(|f| Some((u32::from(f.s("ip").parse::<Ipv4Addr>().ok()?), f.get("name").cloned().unwrap_or("".into()))))
        .collect();
    let all: BTreeSet<u32> = used.keys().chain(scan.keys()).copied().collect();
    let ips: Vec<Value> = all
        .iter()
        .map(|a| {
            let its = used.get(a).cloned().unwrap_or_default();
            let conflict = if its.len() > 1 {
                "duplicada"
            } else if its.is_empty() {
                "sin registrar"
            } else {
                ""
            };
            json!({"ip": Ipv4Addr::from(*a).to_string(), "items": its, "seen": scan.get(a), "up": if row.t("scanned") { json!(scan.contains_key(a)) } else { Value::Null }, "conflict": conflict})
        })
        .collect();
    let size = if net.prefix < 31 { net.num_addresses() - 2 } else { net.num_addresses() };
    let next_free: Vec<String> = net.hosts().filter(|h| !used.contains_key(h) && !scan.contains_key(h)).take(8).map(|h| Ipv4Addr::from(h).to_string()).collect();
    let mut out = row.clone();
    out.insert("scan".into(), Value::Null);
    out.insert("size".into(), size.into());
    out.insert("used".into(), ips.len().into());
    out.insert("free".into(), size.saturating_sub(ips.len() as u64).into());
    out.insert("next_free".into(), next_free.into());
    out.insert("ips".into(), ips.into());
    Ok(out.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_init;

    #[test]
    fn redes() {
        let n = parse_net("127.0.0.5/29").ok().unwrap();
        assert_eq!(n.to_string(), "127.0.0.0/29");
        assert_eq!(n.hosts().count(), 6);
        assert_eq!(parse_net("10.0.0.1").ok().unwrap().hosts().count(), 1);
        assert!(matches!(parse_net("::1/128"), Err(NetErr::V6)) && matches!(parse_net("nada"), Err(NetErr::Bad)));
        assert_eq!(parse_net("10.1.2.3/255.255.255.0").ok().unwrap().to_string(), "10.1.2.0/24");
    }

    #[test]
    fn caducidad_de_certificados() {
        use crate::snmp::tlv;
        // certificado mínimo: versión, serie, algoritmo, emisor y validez (UTCTime y GeneralizedTime)
        let cert = |not_after: Vec<u8>| {
            let validity = tlv(0x30, &[tlv(0x17, b"250101000000Z"), not_after].concat());
            let tbs = tlv(0x30, &[tlv(0xA0, &tlv(2, &[2])), tlv(2, &[1]), tlv(0x30, &[]), tlv(0x30, &[]), validity].concat());
            tlv(0x30, &tbs)
        };
        assert_eq!(cert_expiry(&cert(tlv(0x17, b"300601123000Z"))).unwrap(), 1906547400);
        assert_eq!(cert_expiry(&cert(tlv(0x18, b"20500601123000Z"))).unwrap(), 2537699400);
        assert!(cert_expiry(b"basura").is_err());
    }

    #[test]
    fn resumen_por_horas_y_disponibilidad() {
        test_init();
        let cid = q("INSERT INTO checks(host, every) VALUES('sla', 60)", p![]).unwrap().lastrowid;
        for (ts, up, rtt) in [("10:01", 1, Some(10.0)), ("10:20", 1, Some(20.0)), ("10:40", 1, Some(30.0)), ("10:59", 1, Some(40.0)), ("11:05", 0, None), ("11:06", 0, None)] {
            q("INSERT INTO pings(check_id, ts, up, rtt) VALUES(?, ?, ?, ?)", p![cid, format!("2026-01-15 {ts}:00"), up, rtt.map_or(crate::db::SqlV::Null, crate::db::SqlV::Real)]).unwrap();
        }
        q("INSERT INTO pings(check_id, ts, up, rtt) VALUES(?, '2026-02-01 12:00:00', 0, NULL)", p![cid]).unwrap(); // otro mes
        for (ts, v) in [("10:05", 50.0), ("10:35", 70.0)] {
            q("INSERT INTO metrics(source_id, ts, key, label, value, unit) VALUES(7, ?, 'disk:/', '/', ?, '%')", p![format!("2026-01-15 {ts}:00"), v]).unwrap();
        }
        rollup().unwrap();
        rollup().unwrap(); // repetir no duplica
        let h: Vec<Value> = q("SELECT hour, n, up, rtt, rtt_min, rtt_max FROM pings_h WHERE check_id=? ORDER BY hour", p![cid])
            .unwrap()
            .into_iter()
            .map(|r| Value::Array(r.into_iter().map(|x| x.1).collect()))
            .collect();
        assert_eq!(h, vec![json!(["2026-01-15 10:00:00", 4, 4, 25.0, 10.0, 40.0]), json!(["2026-01-15 11:00:00", 2, 0, null, null, null]), json!(["2026-02-01 12:00:00", 1, 0, null, null, null])]);
        let m = q("SELECT v, v_min, v_max FROM metrics_h WHERE source_id=7", p![]).unwrap().one().unwrap();
        assert_eq!((m.f("v"), m.f("v_min"), m.f("v_max")), (Some(60.0), Some(50.0), Some(70.0)));
        assert_eq!(series(7, MAX_HOURS).unwrap()["disk:/"]["points"], json!([["2026-01-15 10:00:00", 60.0]])); // más de 7 días: de los resúmenes
        let s = sla("2026-01").unwrap();
        let r = s["checks"].as_array().unwrap().iter().find(|x| x["id"] == cid).unwrap().clone();
        assert_eq!((r["n"].clone(), r["up"].clone(), r["down_min"].clone(), r["hours"].clone(), r["rtt"].clone()), (json!(6), json!(4), json!(2), json!(2), json!(25.0)));
        assert!((r["uptime"].as_f64().unwrap() - 4.0 / 6.0).abs() < 1e-9);
        assert_eq!(s["hours"], 31 * 24);
        assert!(sla("2026-13").is_err() && sla("2099-01").unwrap()["checks"][0]["uptime"].is_null());
    }

    #[test]
    fn aviso_de_caducidades_una_vez_al_dia() {
        test_init();
        q("DELETE FROM meta WHERE k='warranty_day'", p![]).unwrap();
        for (name, days) in [("caduca-hoy", 0), ("caduca-en-30", 30), ("caduca-en-31", 31)] {
            q("INSERT INTO items(name, warranty) VALUES(?, date('now', 'localtime', ?))", p![name, format!("+{days} days")]).unwrap();
        }
        q(
            "INSERT INTO expiries(name, kind, date) VALUES('midominio.es', 'dominio', date('now', 'localtime', '+30 days')), \
           ('Office', 'licencia', date('now', 'localtime', '+31 days'))",
            p![],
        )
        .unwrap();
        let t = warranties_due().unwrap().unwrap();
        assert!(warranties_due().unwrap().is_none());
        assert!(t.contains("caduca-hoy: hoy") && t.contains("caduca-en-30: el ") && !t.contains("caduca-en-31"), "{t}");
        assert!(t.contains("midominio.es: el ") && t.contains("(dominio)") && !t.contains("Office"), "{t}");
    }

    #[test]
    fn monitor_irrompible() {
        guarded("prueba", || anyhow::bail!("database is locked"));
        assert!(lock(&MON).error.contains("database is locked"));
        guarded("prueba", || panic!("división por cero"));
        assert!(lock(&MON).error.contains("división por cero"));
    }
}
