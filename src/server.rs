//! Servidor HTTP/1.1 mínimo: un hilo por conexión y una petición por conexión, como el ThreadingHTTPServer de antes.
//! HTTPS siempre, con rustls: el certificado del admin (CATLAN_CERT) o uno autofirmado que se crea en data/tls.pem.
//! En el mismo puerto también responde HTTP plano (se distingue por el primer byte): para el propio equipo, los proxies
//! y las Kitty antiguas; web.rs decide qué se sirve así.
use crate::config::{CERT, DATA, KEY, MAX_BODY, PORT, PROXIES};
use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

pub struct Req {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// La del cliente: la de la conexión o, si llega de un proxy de confianza, la que este pone en X-Forwarded-For.
    pub ip: String,
    /// Cifrada hasta el cliente: TLS con catlan, o con un proxy de confianza que dice X-Forwarded-Proto: https.
    pub tls: bool,
    /// Llega por un proxy de confianza: el certificado que ve el cliente es el del proxy, no el de catlan.
    pub proxied: bool,
    /// Cifrada, o en claro pero desde este mismo equipo (nadie en medio).
    pub secure: bool,
}

impl Req {
    pub fn header(&self, k: &str) -> &str {
        self.opt_header(k).unwrap_or("")
    }
    pub fn opt_header(&self, k: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str())
    }
}

pub struct Resp {
    pub code: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn new(code: u16, body: Vec<u8>, mime: &str) -> Resp {
        Resp { code, headers: vec![("Content-Type".into(), mime.into())], body }
    }
    pub fn header(mut self, k: &str, v: impl Into<String>) -> Resp {
        self.headers.push((k.into(), v.into()));
        self
    }
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        _ => "Internal Server Error",
    }
}

const MAX_CONNS: usize = 512;
/// Por IP (sin contar los proxies): un solo equipo con conexiones lentas (slowloris) no se queda con todas.
const MAX_PER_IP: usize = 64;
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
/// Conexiones rechazadas por estar lleno, para Salud de catlan.
pub static REJECTED: AtomicUsize = AtomicUsize::new(0);
static PER_IP: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<IpAddr, usize>>> = std::sync::LazyLock::new(Default::default);
/// Lo que puede tardar en llegar la petición entera (sin cuerpo): una conexión que habla gota a gota no retiene su hilo.
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);

/// 503 sin leer nada: se escribe en el búfer del socket recién aceptado, no bloquea.
fn busy(mut s: TcpStream) {
    REJECTED.fetch_add(1, Ordering::Relaxed);
    let _ = s.set_write_timeout(Some(Duration::from_millis(200)));
    let _ = s.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nRetry-After: 5\r\nConnection: close\r\n\r\n");
}

/// El certificado que sirve catlan. pin y spki solo si es el autofirmado (con uno del admin, la CA ya lo garantiza):
/// pin = sha256 del certificado en hexadecimal (PowerShell y Kitty), spki = sha256 de su clave pública en base64 (curl).
pub struct Tls {
    cfg: Arc<rustls::ServerConfig>,
    pub pin: String,
    pub spki: String,
}
pub static TLS: OnceLock<Tls> = OnceLock::new();

fn write_private(p: &std::path::Path, data: &str) -> io::Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600); // la clave privada, solo para catlan
    o.open(p)?.write_all(data.as_bytes())
}

fn tls_config() -> anyhow::Result<Tls> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let own = !CERT.is_empty();
    let path = if own { std::path::PathBuf::from(&*CERT) } else { DATA.join("tls.pem") };
    if !own && !path.exists() {
        std::fs::create_dir_all(&*DATA)?;
        let ck = rcgen::generate_simple_self_signed(vec!["catlan".to_string(), "localhost".to_string()])?;
        write_private(&path, &format!("{}{}", ck.cert.pem(), ck.signing_key.serialize_pem()))?;
        println!("HTTPS: certificado autofirmado nuevo en {} (para uno propio: CATLAN_CERT y CATLAN_KEY)", path.display());
    }
    let certs = CertificateDer::pem_file_iter(&path)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(if KEY.is_empty() || !own { path.as_path() } else { std::path::Path::new(&*KEY) })?;
    let (mut pin, mut spki) = (String::new(), String::new());
    if !own {
        use sha2::Digest;
        let pem = std::fs::read_to_string(&path)?;
        let kp = rcgen::KeyPair::from_pem(pem.get(pem.find("-----BEGIN PRIVATE KEY").unwrap_or(0)..).unwrap_or(""))?;
        let der = certs.first().ok_or_else(|| anyhow::anyhow!("{} no tiene certificado", path.display()))?;
        pin = crate::crypto::hex(&sha2::Sha256::digest(der)).to_uppercase();
        spki = data_encoding::BASE64.encode(&sha2::Sha256::digest(rcgen::PublicKeyData::subject_public_key_info(&kp)));
    }
    let cfg = Arc::new(rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)?);
    Ok(Tls { cfg, pin, spki })
}

pub fn serve(handler: fn(&Req) -> Resp) -> anyhow::Result<()> {
    let tls = TLS.get_or_init(|| {
        tls_config().unwrap_or_else(|e| {
            eprintln!("HTTPS: no puedo cargar el certificado ({e:#})");
            std::process::exit(2)
        })
    });
    if !tls.pin.is_empty() {
        println!("HTTPS autofirmado. Huella SHA-256 (compárala con la que enseña el navegador): {}", tls.pin);
    }
    let listener = TcpListener::bind(("0.0.0.0", *PORT))?;
    for s in listener.incoming() {
        let Ok(s) = s else { continue };
        let Ok(peer) = s.peer_addr().map(|a| a.ip().to_canonical()) else { continue };
        let limited = !PROXIES.contains(&peer);
        if ACTIVE.load(Ordering::Relaxed) >= MAX_CONNS {
            busy(s);
            continue;
        }
        if limited {
            let mut m = crate::util::lock(&PER_IP);
            let n = m.entry(peer).or_insert(0);
            if *n >= MAX_PER_IP {
                drop(m);
                busy(s);
                continue;
            }
            *n += 1;
        }
        ACTIVE.fetch_add(1, Ordering::Relaxed);
        let cfg = tls.cfg.clone();
        std::thread::spawn(move || {
            let _ = conn(s, cfg, handler); // escáneres y navegadores que rechazan el certificado: sin traza en la consola
            ACTIVE.fetch_sub(1, Ordering::Relaxed);
            if limited {
                let mut m = crate::util::lock(&PER_IP);
                if let Some(n) = m.get_mut(&peer) {
                    *n -= 1;
                    if *n == 0 {
                        m.remove(&peer);
                    }
                }
            }
        });
    }
    Ok(())
}

fn conn(s: TcpStream, cfg: Arc<rustls::ServerConfig>, handler: fn(&Req) -> Resp) -> io::Result<()> {
    // una conexión que no habla (ni termina el saludo TLS) suelta su hilo
    s.set_read_timeout(Some(HEAD_TIMEOUT))?; // cada lectura; el total de las cabeceras, en one()
    s.set_write_timeout(Some(Duration::from_secs(60)))?;
    let peer = s.peer_addr()?.ip().to_canonical();
    let mut first = [0u8; 1];
    if s.peek(&mut first)? == 1 && first[0] == 0x16 {
        // 0x16: empieza un saludo TLS
        let c = rustls::ServerConnection::new(cfg).map_err(io::Error::other)?;
        let mut st = rustls::StreamOwned::new(c, s);
        one(&mut st, peer, true, handler)?;
        st.conn.send_close_notify();
        st.flush()
    } else {
        let mut st = s;
        one(&mut st, peer, false, handler)
    }
}

/// En todas las respuestas: nada de meter catlan en un marco de otra web (clickjacking) ni cargar código de fuera.
/// La página lleva su JS y su CSS dentro, de ahí 'unsafe-inline'.
const CSP: &str = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; \
                   object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

fn write_resp(st: &mut impl Write, r: &Resp, hsts: bool) -> io::Result<()> {
    let mut head = format!("HTTP/1.1 {} {}\r\n", r.code, reason(r.code));
    for (k, v) in &r.headers {
        head += &format!("{k}: {v}\r\n");
    }
    if !r.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-security-policy")) {
        head += &format!("Content-Security-Policy: {CSP}\r\n");
    }
    head += "X-Frame-Options: DENY\r\nReferrer-Policy: same-origin\r\n";
    if hsts {
        // solo con el certificado del admin: con uno autofirmado, HSTS no deja al navegador aceptarlo
        head += "Strict-Transport-Security: max-age=31536000\r\n";
    }
    if r.code != 304 {
        head += &format!("Content-Length: {}\r\n", r.body.len());
    }
    head += "X-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n";
    st.write_all(head.as_bytes())?;
    if r.code != 304 {
        st.write_all(&r.body)?;
    }
    st.flush()
}

fn json_err(code: u16, msg: &str) -> Resp {
    Resp::new(code, serde_json::json!({"error": msg}).to_string().into_bytes(), "application/json")
}

/// Quién es el cliente y si la conexión va cifrada hasta él. Solo se cree a un proxy de la lista CATLAN_PROXIES, y de
/// X-Forwarded-For solo la última entrada (la que puso el proxy; las anteriores las puede inventar el cliente).
fn client(peer: IpAddr, enc: bool, headers: &[(String, String)]) -> (String, bool, bool, bool) {
    let h = |k: &str| headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| v.trim());
    let fwd = if PROXIES.contains(&peer) { h("x-forwarded-for").and_then(|v| v.rsplit(',').next()?.trim().parse::<IpAddr>().ok()) } else { None };
    let proxied = fwd.is_some();
    let tls = enc || proxied && h("x-forwarded-proto").is_some_and(|v| v.eq_ignore_ascii_case("https"));
    let secure = tls || !proxied && peer.is_loopback();
    (fwd.map_or(peer, |f| f.to_canonical()).to_string(), tls, proxied, secure)
}

fn one(st: &mut (impl Read + Write), peer: IpAddr, enc: bool, handler: fn(&Req) -> Resp) -> io::Result<()> {
    let hsts = enc && TLS.get().is_some_and(|t| t.pin.is_empty());
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];
    let t0 = std::time::Instant::now();
    let (len, method, path, headers) = loop {
        if t0.elapsed() > HEAD_TIMEOUT {
            return Ok(()); // cabeceras gota a gota: fuera
        }
        let n = st.read(&mut tmp)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        let mut hs = [httparse::EMPTY_HEADER; 100];
        let mut r = httparse::Request::new(&mut hs);
        match r.parse(&buf) {
            Ok(httparse::Status::Complete(len)) => {
                let headers: Vec<(String, String)> =
                    r.headers.iter().map(|h| (h.name.to_string(), String::from_utf8_lossy(h.value).into_owned())).collect();
                break (len, r.method.unwrap_or("").to_string(), r.path.unwrap_or("/").to_string(), headers);
            }
            Ok(httparse::Status::Partial) if buf.len() < 64 * 1024 => continue,
            Ok(httparse::Status::Partial) => return write_resp(st, &json_err(431, "cabeceras demasiado grandes"), hsts),
            Err(_) => return write_resp(st, &json_err(400, "petición no válida"), hsts),
        }
    };
    let n: usize = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.trim().parse().ok()).unwrap_or(0);
    if n > MAX_BODY {
        return write_resp(st, &json_err(400, "demasiado grande"), hsts);
    }
    let mut body = buf.split_off(len);
    body.truncate(n);
    if body.len() < n {
        let missing = n - body.len();
        st.take(missing as u64).read_to_end(&mut body)?;
        if body.len() < n {
            return Ok(()); // el cliente se fue a medias
        }
    }
    let (ip, tls, proxied, secure) = client(peer, enc, &headers);
    let req = Req { method, path, headers, body, ip, tls, proxied, secure };
    let resp = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(&req))).unwrap_or_else(|_| json_err(500, "error interno"));
    write_resp(st, &resp, hsts)
}

#[test]
fn client_behind_proxy() {
    let h = |xff: &str, proto: &str| vec![("X-Forwarded-For".to_string(), xff.to_string()), ("X-Forwarded-Proto".to_string(), proto.to_string())];
    let lo: IpAddr = "127.0.0.1".parse().unwrap();
    let lan: IpAddr = "192.168.1.9".parse().unwrap();
    // del proxy de confianza: la última IP de la lista, y cifrada si el proxy lo dice
    assert_eq!(client(lo, false, &h("6.6.6.6, 10.0.0.7", "https")), ("10.0.0.7".into(), true, true, true));
    assert_eq!(client(lo, false, &h("10.0.0.7", "http")), ("10.0.0.7".into(), false, true, false));
    // de cualquier otro: sus cabeceras no cuentan
    assert_eq!(client(lan, false, &h("127.0.0.1", "https")), ("192.168.1.9".into(), false, false, false));
    assert_eq!(client(lan, true, &[]), ("192.168.1.9".into(), true, false, true));
    // el propio equipo sin proxy: en claro, pero sin nadie en medio
    assert_eq!(client(lo, false, &[]), ("127.0.0.1".into(), false, false, true));
}
