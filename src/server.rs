//! Servidor HTTP/1.1 con hyper sobre tokio: conexiones que se reutilizan (keep-alive) y WebSockets.
//! HTTPS siempre, con rustls: el certificado del admin (CATLAN_CERT) o uno autofirmado que se crea en data/tls.pem.
//! En el mismo puerto también responde HTTP plano (se distingue por el primer byte): para el propio equipo, los proxies
//! y las Kitty antiguas; web decide qué se sirve así.
use crate::config::{CERT, DATA, KEY, PORT, PROXIES};
use std::io::{self, Write};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

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

/// La conexión de la que llega cada petición: quién está al otro lado del socket y si habla TLS con catlan.
#[derive(Clone, Copy, Debug)]
pub struct Conn {
    pub peer: IpAddr,
    pub enc: bool,
}

const MAX_CONNS: usize = 512;
/// Por IP (sin contar los proxies): un solo equipo con conexiones lentas (slowloris) no se queda con todas.
const MAX_PER_IP: usize = 64;
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
/// Conexiones rechazadas por estar lleno, para Salud de catlan.
pub static REJECTED: AtomicUsize = AtomicUsize::new(0);
static PER_IP: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<IpAddr, usize>>> = std::sync::LazyLock::new(Default::default);
/// Lo que puede tardar en llegar cada petición entera (sin cuerpo), y el saludo TLS: una conexión que habla gota a gota
/// (o que se queda callada entre peticiones) se cierra.
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(10);

/// 503 sin leer nada: se escribe en el búfer del socket recién aceptado, no espera.
fn busy(s: TcpStream) {
    REJECTED.fetch_add(1, Ordering::Relaxed);
    let _ = s.try_write(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nRetry-After: 5\r\nConnection: close\r\n\r\n");
}

/// Un hueco ocupado: se suelta al cerrar la conexión, pase lo que pase.
struct Slot(Option<IpAddr>);

impl Drop for Slot {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::Relaxed);
        if let Some(peer) = self.0 {
            let mut m = crate::util::lock(&PER_IP);
            if let Some(n) = m.get_mut(&peer) {
                *n -= 1;
                if *n == 0 {
                    m.remove(&peer);
                }
            }
        }
    }
}

/// Reserva un hueco para esta IP, o None si está lleno (todo catlan, o lo de esa IP).
fn take_slot(peer: IpAddr) -> Option<Slot> {
    let limited = !PROXIES.contains(&peer);
    if ACTIVE.load(Ordering::Relaxed) >= MAX_CONNS {
        return None;
    }
    if limited {
        let mut m = crate::util::lock(&PER_IP);
        let n = m.entry(peer).or_insert(0);
        if *n >= MAX_PER_IP {
            return None;
        }
        *n += 1;
    }
    ACTIVE.fetch_add(1, Ordering::Relaxed);
    Some(Slot(limited.then_some(peer)))
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
    let mut cfg = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Tls { cfg: Arc::new(cfg), pin, spki })
}

pub fn serve(app: axum::Router) -> anyhow::Result<()> {
    let tls = TLS.get_or_init(|| {
        tls_config().unwrap_or_else(|e| {
            eprintln!("HTTPS: no puedo cargar el certificado ({e:#})");
            std::process::exit(2)
        })
    });
    if !tls.pin.is_empty() {
        println!("HTTPS autofirmado. Huella SHA-256 (compárala con la que enseña el navegador): {}", tls.pin);
    }
    // los manejadores usan SQLite y esperan: van a hilos aparte (spawn_blocking), el resto es asíncrono
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().max_blocking_threads(MAX_CONNS).build()?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(("0.0.0.0", *PORT)).await?;
        let acceptor = tokio_rustls::TlsAcceptor::from(tls.cfg.clone());
        loop {
            let (s, addr) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(50)).await; // sin descriptores libres: no dar vueltas en vacío
                    continue;
                }
            };
            let peer = addr.ip().to_canonical();
            let Some(slot) = take_slot(peer) else {
                busy(s);
                continue;
            };
            let (acceptor, app) = (acceptor.clone(), app.clone());
            tokio::spawn(async move {
                let _slot = slot;
                let _ = conn(s, peer, acceptor, app).await; // escáneres y navegadores que rechazan el certificado: sin traza en la consola
            });
        }
    })
}

async fn conn(s: TcpStream, peer: IpAddr, acceptor: tokio_rustls::TlsAcceptor, app: axum::Router) -> io::Result<()> {
    let _ = s.set_nodelay(true);
    // una conexión que no habla (ni termina el saludo TLS) se cierra
    let mut first = [0u8; 1];
    let n = tokio::time::timeout(HEAD_TIMEOUT, s.peek(&mut first)).await.map_err(io::Error::other)??;
    if n == 1 && first[0] == 0x16 {
        // 0x16: empieza un saludo TLS
        let st = tokio::time::timeout(HEAD_TIMEOUT, acceptor.accept(s)).await.map_err(io::Error::other)??;
        http(st, Conn { peer, enc: true }, app).await
    } else {
        http(s, Conn { peer, enc: false }, app).await
    }
}

async fn http(io: impl AsyncRead + AsyncWrite + Unpin + Send + 'static, c: Conn, app: axum::Router) -> io::Result<()> {
    use tower::ServiceExt;
    let svc = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
        req.extensions_mut().insert(c);
        app.clone().oneshot(req.map(axum::body::Body::new))
    });
    hyper::server::conn::http1::Builder::new()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HEAD_TIMEOUT)
        .max_buf_size(64 * 1024) // cabeceras más grandes: 431 (hyper corta tras la lectura que pasa de aquí: unos 100 KB como mucho)
        .serve_connection(hyper_util::rt::TokioIo::new(io), svc)
        .with_upgrades()
        .await
        .map_err(io::Error::other)
}

/// Quién es el cliente y si la conexión va cifrada hasta él. Solo se cree a un proxy de la lista CATLAN_PROXIES, y de
/// X-Forwarded-For solo la última entrada (la que puso el proxy; las anteriores las puede inventar el cliente).
pub fn client(peer: IpAddr, enc: bool, headers: &[(String, String)]) -> (String, bool, bool, bool) {
    let h = |k: &str| headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| v.trim());
    let fwd = if PROXIES.contains(&peer) { h("x-forwarded-for").and_then(|v| v.rsplit(',').next()?.trim().parse::<IpAddr>().ok()) } else { None };
    let proxied = fwd.is_some();
    let tls = enc || proxied && h("x-forwarded-proto").is_some_and(|v| v.eq_ignore_ascii_case("https"));
    let secure = tls || !proxied && peer.is_loopback();
    (fwd.map_or(peer, |f| f.to_canonical()).to_string(), tls, proxied, secure)
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
