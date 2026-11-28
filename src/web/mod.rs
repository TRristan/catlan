//! La API y la página: sesiones, permisos, CRUD con historial y todo lo demás. Misma API que la versión en Python.
//! Las rutas son tablas (una por área, en su módulo): método, ruta, permiso y manejador. El permiso de cada una lo aplica
//! un middleware (`guard`) antes de llegar al manejador; lo común a todas (CSRF, lo que se sirve en claro, cabeceras de
//! seguridad) va en otro (`front`).
mod incidencias;
mod inventario;
mod kitty;
mod monitor;
mod pcs;
mod remoto;
mod usuarios;
mod wiki;

pub use usuarios::reset_password;

use crate::config::{COOKIE, MAX_BODY};
use crate::crypto::{pw_ok, sha256_hex, totp_ok};
use crate::db::{self, q};
use crate::p;
use crate::server::{Conn, Req, Resp};
use crate::sso;
use crate::util::{Bad, J, Row, Shape, lock, now, parse_qs, trunc};
use anyhow::Result;
use axum::extract::{RawPathParams, Request, State};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodFilter, on};
use flate2::{Compression, write::GzEncoder};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::Write;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

/// Quién puede usar cada ruta.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Perm {
    /// Sin sesión: la página, el login y Kitty (que se identifica con su clave).
    Free,
    /// Con sesión, también con la contraseña provisional: solo para cambiarla o salir.
    Pending,
    /// Con sesión; quien es de solo vista también escribe: el tablero personal no toca nada común.
    Own,
    /// Con sesión; quien es de solo vista, solo lee.
    User,
    /// Solo administradores.
    Admin,
}

pub type Sync = fn(&mut Ctx) -> Result<Resp>;
pub type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>;
/// Lo que llega a un WebSocket, ya con el permiso comprobado.
pub struct Ws {
    pub up: axum::extract::ws::WebSocketUpgrade,
    pub who: Who,
    pub req: Req,
    pub params: Vec<(String, String)>,
}

pub enum H {
    /// Un manejador normal: SQLite y espera, así que va en un hilo aparte.
    Sync(Sync),
    /// Un WebSocket: asíncrono, vive lo que dure la conexión.
    Ws(fn(Ws) -> Future),
}

pub struct Route {
    /// GET, POST, PUT, DELETE, o * para cualquiera.
    pub method: &'static str,
    pub path: &'static str,
    pub perm: Perm,
    pub h: H,
}

pub const fn r(method: &'static str, path: &'static str, perm: Perm, f: Sync) -> Route {
    Route { method, path, perm, h: H::Sync(f) }
}

/// Todas las rutas de la API, área por área.
pub fn routes() -> Vec<Route> {
    [
        kitty::routes(),
        usuarios::routes(),
        wiki::routes(),
        inventario::routes(),
        monitor::routes(),
        incidencias::routes(),
        remoto::routes(),
        pcs::routes(),
        vec![
            // lo que no es ninguna de las anteriores: con sesión, «no existe»
            r("*", "/api", Perm::User, nothing),
            r("*", "/api/{*rest}", Perm::User, nothing),
        ],
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn nothing(_: &mut Ctx) -> Result<Resp> {
    Ok(err(404, "no existe"))
}

pub fn app() -> axum::Router {
    let mut app = axum::Router::new();
    for rt in routes() {
        let filter = match rt.method {
            "GET" => MethodFilter::GET,
            "POST" => MethodFilter::POST,
            "PUT" => MethodFilter::PUT,
            "DELETE" => MethodFilter::DELETE,
            _ => MethodFilter::GET.or(MethodFilter::POST).or(MethodFilter::PUT).or(MethodFilter::DELETE).or(MethodFilter::PATCH),
        };
        let g = middleware::from_fn_with_state(rt.perm, guard);
        let path = rt.path;
        let mr = match rt.h {
            H::Sync(f) => on(filter, move |p: RawPathParams, req: Request| sync(f, path, p, req)),
            H::Ws(f) => on(filter, move |p: RawPathParams, req: Request| ws(f, p, req)),
        };
        // route_layer: solo a esta ruta y este método (el 405 de los demás métodos no pasa por aquí)
        let mr = mr.route_layer(g);
        app = app.route(path, mr);
    }
    app.fallback(page).method_not_allowed_fallback(|| async { out(err(405, "método no permitido")) }).layer(middleware::from_fn(front))
}

/// Lo que se sabe del cliente después de mirar la conexión y, si viene de un proxy de confianza, sus cabeceras.
#[derive(Clone, Debug)]
struct Client {
    ip: String,
    tls: bool,
    proxied: bool,
    secure: bool,
}

/// El usuario de la petición (vacío en las rutas libres).
#[derive(Clone, Default, Debug)]
pub struct Who {
    pub uid: Option<i64>,
    pub user: String,
    pub admin: bool,
    pub token: String,
}

/// En todas las respuestas: nada de meter catlan en un marco de otra web (clickjacking) ni cargar código de fuera.
/// La página lleva su JS y su CSS dentro, de ahí 'unsafe-inline'.
const CSP: &str = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; \
                   object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

fn headers_of(h: &axum::http::HeaderMap) -> Vec<(String, String)> {
    h.iter().map(|(k, v)| (k.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned())).collect()
}

/// Lo de todas las peticiones: CSRF, lo que se sirve en claro y las cabeceras de seguridad de la respuesta.
async fn front(mut req: Request, next: Next) -> Response {
    let c = req.extensions().get::<Conn>().copied().unwrap_or(Conn { peer: std::net::Ipv4Addr::UNSPECIFIED.into(), enc: false });
    let headers = headers_of(req.headers());
    let (ip, tls, proxied, secure) = crate::server::client(c.peer, c.enc, &headers);
    let h = |k: &str| headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str());
    let m = req.method().as_str().to_string();
    let full = req.uri().path_and_query().map_or("/", |p| p.as_str()).to_string();
    let mut early = None;
    // Escrituras desde otra web (CSRF): el navegador pone Origin; si no es este servidor, fuera. También al abrir un
    // WebSocket (es un GET, pero luego lleva teclado y ratón). Detrás de un proxy, este debe conservar la cabecera Host.
    let upgrade = h("upgrade").is_some();
    if let Some(o) = h("origin")
        && (m != "GET" || upgrade)
        && netloc(o) != h("host").unwrap_or("")
    {
        early = Some(err(403, "origen no permitido"));
    }
    // Sin Origin: un navegador moderno dice igualmente de dónde viene la petición. Scripts y Kitty no mandan ninguna.
    if early.is_none() && (m != "GET" || upgrade) && !matches!(h("sec-fetch-site").unwrap_or(""), "" | "same-origin" | "none") {
        early = Some(err(403, "origen no permitido"));
    }
    if early.is_none() && !secure {
        early = plain(&m, &full, h("host").unwrap_or(""));
    }
    let mut resp = match early {
        Some(r) => out(r),
        None => {
            req.extensions_mut().insert(Client { ip, tls, proxied, secure });
            next.run(req).await
        }
    };
    let hd = resp.headers_mut();
    let set = |hd: &mut axum::http::HeaderMap, k: &'static str, v: &'static str| {
        hd.insert(k, axum::http::HeaderValue::from_static(v));
    };
    if !hd.contains_key("content-security-policy") {
        set(hd, "content-security-policy", CSP);
    }
    set(hd, "x-frame-options", "DENY");
    set(hd, "referrer-policy", "same-origin");
    set(hd, "x-content-type-options", "nosniff");
    if c.enc && crate::server::TLS.get().is_some_and(|t| t.pin.is_empty()) {
        // solo con el certificado del admin: con uno autofirmado, HSTS no deja al navegador aceptarlo
        set(hd, "strict-transport-security", "max-age=31536000");
    }
    resp
}

/// HTTP en claro desde la red (no desde este equipo): solo lo que mandan las Kitty instaladas antes del HTTPS.
/// Nada de contraseñas, sesiones, pantalla ni teclas en claro. La página redirige a https.
fn plain(m: &str, full: &str, host: &str) -> Option<Resp> {
    let full = full.split('#').next().unwrap_or("");
    let path = full.split_once('?').map_or(full, |(p, _)| p);
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    let api = parts.first() == Some(&"api");
    let rest = parts.get(1..).unwrap_or(&[]);
    let legacy_kitty = api && rest.first() == Some(&"agent") && !matches!(rest.get(1), Some(&"remote" | &"quit"));
    if legacy_kitty || parts == ["kitty.json"] || parts == ["kitty.exe"] {
        return None;
    }
    let again = "Kitty ya no se instala por http: copia el comando nuevo de catlan (Inventario → Añadir con Kitty).";
    Some(match parts.first() {
        Some(&"kitty.ps1") => Resp::new(200, format!("throw '{again}'").into_bytes(), "text/plain; charset=utf-8"),
        Some(&"kitty.sh") => Resp::new(200, format!("echo '{again}' >&2; exit 1\n").into_bytes(), "text/plain; charset=utf-8"),
        _ if !api && m == "GET" && crate::validate::host_ok(host) => Resp::new(301, vec![], "text/plain").header("Location", format!("https://{host}{full}")),
        _ => err(403, &format!("conéctate por https://{}", if crate::validate::host_ok(host) { host } else { "catlan" })),
    })
}

/// Qué pasa con una petición según el permiso de su ruta y quién la hace: None, adelante; si no, la respuesta.
/// `u`: (contraseña provisional, admin, solo vista) del usuario con sesión.
fn decide(perm: Perm, write: bool, u: Option<(bool, bool, bool)>) -> Option<Resp> {
    match (perm, u) {
        (Perm::Free, _) => None,
        (_, None) => Some(err(401, "inicia sesión")),
        (Perm::Pending, Some(_)) => None,
        // contraseña provisional (admin/admin incluido): solo se puede cambiarla o salir
        (_, Some((true, _, _))) => Some(js(403, json!({"error": "cambia tu contraseña para continuar", "must_change": true}))),
        (Perm::Admin, Some((_, false, _))) => Some(err(403, "solo para administradores")),
        (Perm::User, Some((_, _, true))) if write => Some(err(403, "tu usuario es de solo vista")),
        _ => None,
    }
}

/// El permiso de la ruta, antes del manejador. Deja en la petición quién es (`Who`).
async fn guard(State(perm): State<Perm>, mut req: Request, next: Next) -> Response {
    if perm == Perm::Free {
        return next.run(req).await;
    }
    // en un bloque: lo que se presta de la petición no cruza ningún await (el cuerpo no es Sync)
    let (cookie, auth) = {
        let h = |k: &str| req.headers().get(k).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        (h("cookie"), h("authorization"))
    };
    let ip = req.extensions().get::<Client>().map(|c| c.ip.clone()).unwrap_or_default();
    let write = !matches!(*req.method(), axum::http::Method::GET | axum::http::Method::HEAD);
    let r = tokio::task::spawn_blocking(move || -> Result<std::result::Result<Who, Resp>> {
        let (u, token) = session(&cookie, &auth, &ip)?;
        let uid = u.as_ref().and_then(|u| u.i("id"));
        let ro = write && perm == Perm::User && uid.is_some_and(|id| readonly(id).unwrap_or(false));
        if let Some(no) = decide(perm, write, u.as_ref().map(|u| (u.t("must_change"), u.t("admin"), ro))) {
            return Ok(Err(no));
        }
        let u = u.unwrap_or_default();
        Ok(Ok(Who { uid, user: u.s("name").to_string(), admin: u.t("admin"), token }))
    })
    .await;
    match r {
        Ok(Ok(Ok(w))) => {
            req.extensions_mut().insert(w);
            next.run(req).await
        }
        Ok(Ok(Err(no))) => out(no),
        Ok(Err(e)) => {
            eprintln!("500 comprobando la sesión: {e:#}");
            out(err(500, &format!("error interno: {e}")))
        }
        Err(_) => out(err(500, "error interno")),
    }
}

/// Lo que puede tardar en llegar el cuerpo entero (subir un mapa o una copia por una red lenta).
const BODY_TIMEOUT: Duration = Duration::from_secs(120);

async fn read(req: Request) -> std::result::Result<(Req, Who), Resp> {
    let (parts, body) = req.into_parts();
    let body = match tokio::time::timeout(BODY_TIMEOUT, axum::body::to_bytes(body, MAX_BODY)).await {
        Ok(Ok(b)) => b.to_vec(),
        Ok(Err(_)) => return Err(err(400, "demasiado grande")),
        Err(_) => return Err(err(408, "el cuerpo de la petición tarda demasiado")),
    };
    let cl = parts.extensions.get::<Client>().cloned().unwrap_or(Client { ip: String::new(), tls: false, proxied: false, secure: false });
    let who = parts.extensions.get::<Who>().cloned().unwrap_or_default();
    let path = parts.uri.path_and_query().map_or("/", |p| p.as_str()).to_string();
    let req = Req { method: parts.method.as_str().to_string(), path, headers: headers_of(&parts.headers), body, ip: cl.ip, tls: cl.tls, proxied: cl.proxied, secure: cl.secure };
    Ok((req, who))
}

fn params(p: &RawPathParams) -> Vec<(String, String)> {
    p.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

async fn sync(f: Sync, route: &'static str, p: RawPathParams, req: Request) -> Response {
    let (req, who) = match read(req).await {
        Ok(x) => x,
        Err(r) => return out(r),
    };
    let params = params(&p);
    let r = tokio::task::spawn_blocking(move || run(f, route, req, who, params)).await;
    out(r.unwrap_or_else(|_| err(500, "error interno"))) // un pánico en el manejador
}

async fn ws(f: fn(Ws) -> Future, p: RawPathParams, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let up = match axum::extract::ws::WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let (req, who) = match read(Request::from_parts(parts, body)).await {
        Ok(x) => x,
        Err(r) => return out(r),
    };
    f(Ws { up, who, req, params: params(&p) }).await
}

use axum::extract::FromRequestParts;

fn run(f: Sync, route: &'static str, req: Req, who: Who, params: Vec<(String, String)>) -> Resp {
    let full = req.path.split('#').next().unwrap_or("");
    let qs = parse_qs(full.split_once('?').map_or("", |(_, q)| q));
    let mut c = Ctx { req, uid: who.uid, user: who.user, admin: who.admin, token: who.token, route, params, qs };
    let req = &c.req;
    let (method, path) = (req.method.clone(), req.path.clone());
    f(&mut c).unwrap_or_else(|e| {
        if let Some(b) = e.downcast_ref::<Bad>() {
            err(400, &b.0)
        } else if let Some(j) = e.downcast_ref::<serde_json::Error>() {
            err(400, &j.to_string())
        } else if e.downcast_ref::<Shape>().is_some() {
            println!("400 por datos raros en {path}");
            err(400, &Shape.to_string())
        } else {
            eprintln!("500 en {method} {path}: {e:#}");
            err(500, &format!("error interno: {e}"))
        }
    })
}

pub fn out(r: Resp) -> Response {
    let mut b = Response::builder().status(r.code);
    for (k, v) in &r.headers {
        b = b.header(k.as_str(), v.as_str());
    }
    b.body(axum::body::Body::from(r.body)).unwrap_or_else(|_| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "cabecera no válida").into_response())
}

pub struct Ctx {
    pub req: Req,
    pub uid: Option<i64>,
    pub user: String,
    pub admin: bool,
    pub token: String,
    /// La ruta de la tabla que ha casado, como /api/items/{id}.
    route: &'static str,
    params: Vec<(String, String)>,
    pub qs: HashMap<String, Vec<String>>,
}

impl Ctx {
    pub fn body(&self) -> Result<Value> {
        if self.req.body.is_empty() { Ok(json!({})) } else { Ok(serde_json::from_slice(&self.req.body)?) }
    }

    pub fn uid(&self) -> i64 {
        self.uid.unwrap_or(0)
    }

    /// Un trozo de la ruta, como el {id} de /api/items/{id}.
    pub fn param(&self, k: &str) -> Option<&str> {
        self.params.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }

    /// El {id} como número; -1 si no lo es (no existe ninguno así).
    pub fn id(&self) -> i64 {
        self.param("id").and_then(|r| r.parse().ok()).unwrap_or(-1)
    }

    /// La tabla de la ruta: «items» en /api/items/{id}.
    pub fn res(&self) -> &'static str {
        self.route.split('/').nth(2).unwrap_or("")
    }

    pub fn log(&self, action: &str, kind: &str, r: impl db::IntoSql, name: impl db::IntoSql, data: &Value) -> Result<()> {
        let r = r.sql();
        let snap = data.to_string();
        let last = q("SELECT id, action, who, ts > datetime('now', '-60 seconds') AS fresh FROM log WHERE kind=? AND ref=? ORDER BY id DESC LIMIT 1", p![kind, r.clone()])?.one();
        // esquemas y racks se autoguardan al arrastrar: agrupa ediciones seguidas en una sola entrada
        if let Some(l) = last.filter(|l| ["map", "rack"].contains(&kind) && action == "editar" && l.s("action") == "editar" && l.s("who") == self.user && l.t("fresh")) {
            q("UPDATE log SET ts=CURRENT_TIMESTAMP, name=?, data=? WHERE id=?", p![name, snap, &l["id"]])?;
        } else {
            q("INSERT INTO log(who, action, kind, ref, name, data) VALUES(?,?,?,?,?,?)", p![&self.user, action, kind, r, name, snap])?;
        }
        Ok(())
    }

    /// La huella del certificado autofirmado para anclarlo, si el cliente habla directamente con catlan.
    pub fn pins(&self) -> (&'static str, &'static str) {
        match crate::server::TLS.get() {
            Some(t) if !self.req.proxied => (t.pin.as_str(), t.spki.as_str()),
            _ => ("", ""),
        }
    }
}

pub fn js(code: u16, v: impl serde::Serialize) -> Resp {
    Resp::new(code, serde_json::to_vec(&v).unwrap_or_default(), "application/json")
}

pub fn err(code: u16, msg: &str) -> Resp {
    js(code, json!({"error": msg}))
}

pub fn no_content() -> Resp {
    Resp::new(204, vec![], "application/json")
}

/// Sin los secretos: nunca salen por la API ni al historial.
pub fn public(mut r: Row) -> Row {
    for k in crate::monitor::SECRET {
        r.shift_remove(k);
    }
    r
}

fn netloc(url: &str) -> &str {
    url.split_once("://").map(|(_, r)| r.split(['/', '?', '#']).next().unwrap_or("")).unwrap_or("")
}

pub fn cookie<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').filter_map(|c| c.trim().split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| v.trim_matches('"'))
}

// ── Sesiones ──

/// Fallos de login recientes por IP («u:nombre» por usuario): 10 en 15 minutos y esa IP espera.
static FAILS: LazyLock<Mutex<HashMap<String, Vec<f64>>>> = LazyLock::new(Default::default);
/// (nombre, HMAC de la contraseña con una clave de este proceso) -> (id, hash, caduca): con Basic no se repite PBKDF2
/// en cada petición. Sin la clave, lo que hay en memoria no sirve para probar contraseñas.
type BasicCache = HashMap<(String, String), (i64, String, f64)>; // (nombre, hmac) -> (id, hash, caduca)
pub static BASIC: LazyLock<Mutex<BasicCache>> = LazyLock::new(Default::default);
static BASIC_KEY: LazyLock<Vec<u8>> = LazyLock::new(|| crate::crypto::rand_bytes(32));
const BASIC_TTL: f64 = 600.0;
/// Por usuario, más alto que por IP: frena a quien prueba desde muchas IPs sin que un solo atacante bloquee a nadie.
const USER_FAILS: usize = 30;

fn recent(key: &str) -> usize {
    let mut f = lock(&FAILS);
    let t = now() - 900.0;
    let Some(v) = f.get_mut(key) else { return 0 };
    v.retain(|x| *x > t);
    v.len()
}

pub fn throttled(ip: &str) -> bool {
    recent(ip) >= 10
}

pub fn failed(key: &str) {
    let mut f = lock(&FAILS);
    let t = now() - 900.0;
    if f.len() > 1000 {
        f.retain(|_, v| {
            v.retain(|x| *x > t);
            !v.is_empty()
        }); // muchas IPs distintas: fuera las que ya no cuentan
    }
    f.entry(key.to_string()).or_default().push(now());
}

pub enum Login {
    No,
    NeedCode,
    Ok(i64),
    /// La contraseña del dominio valía (o el dominio no contesta), pero no entra: código de `sso::why`.
    Refused(&'static str),
}

/// Por Basic no hay código: quien tiene 2FA no entra por Basic (para scripts, un usuario sin 2FA).
pub fn login_ok(name: &str, pw: &str, code: &str) -> Result<Login> {
    let who = format!("u:{}", name.to_lowercase());
    if recent(&who) >= USER_FAILS {
        return Ok(Login::No);
    }
    let key = (name.to_lowercase(), crate::crypto::hex(&crate::crypto::hmac_sha256(&BASIC_KEY, pw.as_bytes())));
    let u = q("SELECT id, hash, totp, ext FROM users WHERE name=?", p![name])?.one();
    // los usuarios locales (admin incluido) nunca pasan por el dominio: así siempre se puede entrar, aunque esté caído
    if u.as_ref().map_or_else(|| sso::ldap_on(&sso::conf()), |u| u.s("ext").starts_with("ldap:")) {
        return ldap_ok(name, pw, &who, key, u.and_then(|u| u.i("id")));
    }
    let Some(u) = u.filter(|u| u.s("ext").is_empty()) else { return Ok(Login::No) }; // los de OIDC no tienen contraseña aquí
    let (id, hash, totp) = (u.i("id").unwrap_or(0), u.s("hash").to_string(), u.s("totp").to_string());
    let code_ok = || if totp_ok(&totp, code) { Login::Ok(id) } else { Login::NeedCode };
    // La caché solo vale si el hash guardado sigue siendo el mismo: otro proceso (catlan restablecer) puede haberlo cambiado
    let t = now();
    let cached = lock(&BASIC).get(&key).is_some_and(|(i, h, exp)| *i == id && *h == hash && *exp > t);
    if !cached {
        lock(&BASIC).retain(|k, (_, _, exp)| *k != key && *exp > t);
        if !pw_ok(pw, &hash) {
            failed(&who);
            return Ok(Login::No);
        }
        if !totp.is_empty() {
            return Ok(code_ok()); // sin caché: cada vez, su código
        }
        lock(&BASIC).insert(key, (id, hash, t + BASIC_TTL));
    } else if !totp.is_empty() {
        // activó la 2FA en otro proceso después de entrar por aquí
        lock(&BASIC).remove(&key);
        return Ok(code_ok());
    }
    Ok(Login::Ok(id))
}

/// Contraseña del dominio: el mismo límite de intentos por usuario y la misma caché para Basic que los locales.
/// shortcut: sin 2FA de catlan; la verificación en dos pasos del dominio, si la hay, no pasa por LDAP.
fn ldap_ok(name: &str, pw: &str, who: &str, key: (String, String), id: Option<i64>) -> Result<Login> {
    let t = now();
    if let Some((i, _, _)) = lock(&BASIC).get(&key).filter(|(i, h, exp)| Some(*i) == id && h == "ldap" && *exp > t) {
        return Ok(Login::Ok(*i));
    }
    match sso::ldap_login(name, pw) {
        Ok(Some(x)) => Ok(match ext_user(&x)? {
            Ok(id) => {
                lock(&BASIC).insert(key, (id, "ldap".into(), t + BASIC_TTL));
                Login::Ok(id)
            }
            Err(why) => Login::Refused(why),
        }),
        Ok(None) => {
            failed(who);
            Ok(Login::No)
        }
        Err(e) => {
            eprintln!("LDAP: {e:#}");
            Ok(Login::Refused("dominio"))
        }
    }
}

/// Alguien que el dominio ha reconocido: se crea la primera vez y, en cada entrada, sus grupos del dominio mandan su
/// admin y sus grupos de catlan. Nunca toma un usuario local con el mismo nombre (admin incluido).
pub fn ext_user(x: &sso::Ext) -> Result<std::result::Result<i64, &'static str>> {
    let Some((admin, groups)) = sso::roles(&sso::conf(), &x.groups) else {
        println!("{}: sin acceso a catlan (sus grupos: {})", x.name, x.groups.join("; "));
        return Ok(Err("acceso"));
    };
    let id = match q("SELECT id FROM users WHERE ext=?", p![&x.key])?.one() {
        Some(u) => u.i("id").unwrap_or(0),
        None => {
            let name = sso::local_name(&x.name);
            let id = match q("INSERT INTO users(name, hash, ext) VALUES(?, '', ?)", p![&name, &x.key]) {
                Ok(r) => r.lastrowid,
                Err(e) if db::is_constraint(&e) => return Ok(Err("nombre")),
                Err(e) => return Err(e),
            };
            q("INSERT INTO log(who, action, kind, ref, name, data) VALUES(?, 'crear', 'user', ?, ?, ?)", p![&name, id, &name, json!({"dominio": &x.key[..4]}).to_string()])?;
            id
        }
    };
    q("UPDATE users SET admin=? WHERE id=?", p![admin, id])?;
    q("DELETE FROM members WHERE user_id=?", p![id])?;
    for g in groups {
        q("INSERT OR IGNORE INTO members(group_id, user_id) SELECT id, ? FROM groups WHERE id=?", p![id, g])?; // un grupo borrado después, fuera
    }
    Ok(Ok(id))
}

/// Usuario del dominio (LDAP u OIDC): su contraseña, su 2FA y su admin no se cambian en catlan.
pub fn is_ext(id: i64) -> Result<bool> {
    Ok(q("SELECT ext FROM users WHERE id=?", p![id])?.one().is_some_and(|u| !u.s("ext").is_empty()))
}

/// Solo vista: está en algún grupo de solo vista y en ninguno que pueda editar (los administradores siempre editan).
pub fn readonly(uid: i64) -> Result<bool> {
    let r = q(
        "SELECT u.admin, max(g.role = 'edit') AS e, max(g.role = 'view') AS v FROM users u LEFT JOIN members m ON m.user_id = u.id \
         LEFT JOIN groups g ON g.id = m.group_id WHERE u.id=?",
        p![uid],
    )?
    .one()
    .unwrap_or_default();
    Ok(!r.t("admin") && r.t("v") && !r.t("e"))
}

/// Sesión por cookie (navegador) o Basic (scripts): el usuario y el token de la sesión (sha256 de la cookie).
/// Sin WWW-Authenticate: el login es la página de catlan.
fn session(cookies: &str, h: &str, ip: &str) -> Result<(Option<Row>, String)> {
    if let Some(v) = cookie(cookies, &COOKIE).filter(|v| !v.is_empty()) {
        let token = sha256_hex(v);
        let u = q("SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token=? AND s.expires > datetime('now')", p![&token])?.one();
        return Ok((u, token));
    }
    let (Some(b64), false) = (h.strip_prefix("Basic "), throttled(ip)) else { return Ok((None, String::new())) };
    let decoded = data_encoding::BASE64.decode(b64.trim().as_bytes()).ok().and_then(|b| String::from_utf8(b).ok());
    // Err(true): fallo que cuenta para el límite por IP; Err(false): el dominio no deja entrar (o no contesta), no cuenta
    let uid = match decoded.as_deref().and_then(|s| s.split_once(':')) {
        Some((n, pw)) => match login_ok(&trunc(n, 100), &trunc(pw, 200), "")? {
            Login::Ok(id) => Ok(id),
            Login::Refused(_) => Err(false),
            _ => Err(true),
        },
        None => Err(true),
    };
    if uid == Err(true) {
        failed(ip);
    }
    Ok((
        match uid {
            Ok(id) => q("SELECT * FROM users WHERE id=?", p![id])?.one(),
            Err(_) => None,
        },
        String::new(),
    ))
}

// ── La página ──

/// La página (src/ui/ unida por build.rs) en memoria y comprimida una sola vez.
struct Page {
    raw: &'static [u8],
    gz: Vec<u8>,
    etag: String,
}
static PAGE: LazyLock<Page> = LazyLock::new(|| {
    let raw: &'static [u8] = include_bytes!(concat!(env!("OUT_DIR"), "/index.html"));
    let mut e = GzEncoder::new(vec![], Compression::best());
    let _ = e.write_all(raw);
    Page { raw, gz: e.finish().unwrap_or_default(), etag: format!("\"{}\"", &crate::crypto::hex(&<sha2::Sha256 as sha2::Digest>::digest(raw))[..20]) }
});

/// Todo lo que no es la API ni lo de Kitty: la página (la web decide qué enseñar según la ruta).
async fn page(req: Request) -> Response {
    let h = |k: &str| req.headers().get(k).and_then(|v| v.to_str().ok()).unwrap_or("");
    let pg = &*PAGE;
    if h("if-none-match") == pg.etag {
        // ya la tiene: 304 sin cuerpo
        return out(Resp { code: 304, headers: vec![], body: vec![] }.header("Cache-Control", "no-cache").header("Vary", "Accept-Encoding").header("ETag", &pg.etag));
    }
    let gz = h("accept-encoding").contains("gzip");
    let mut r =
        Resp::new(200, if gz { pg.gz.clone() } else { pg.raw.to_vec() }, "text/html; charset=utf-8").header("Cache-Control", "no-cache").header("Vary", "Accept-Encoding").header("ETag", &pg.etag);
    if gz {
        r = r.header("Content-Encoding", "gzip");
    }
    out(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    /// El permiso de cada ruta, escrito aparte: cambiar uno en las tablas sin cambiarlo aquí hace fallar la prueba.
    const EXPECTED: &[(&str, &str, Perm)] = &[
        ("GET", "/kitty.exe", Perm::Free),
        ("GET", "/kitty.json", Perm::Free),
        ("GET", "/kitty.ps1", Perm::Free),
        ("GET", "/kitty.sh", Perm::Free),
        ("POST", "/api/agent", Perm::Free),
        ("POST", "/api/agent/incident", Perm::Free),
        ("POST", "/api/agent/mine", Perm::Free),
        ("POST", "/api/agent/quit", Perm::Free),
        ("POST", "/api/agent/{other}", Perm::Free),
        ("POST", "/api/agent/remote", Perm::Free),
        ("POST", "/api/agent/remote/answer", Perm::Free),
        ("POST", "/api/agent/remote/frame", Perm::Free),
        ("GET", "/api/agent/remote/ws", Perm::Free),
        ("GET", "/api/agents", Perm::Admin),
        ("PUT", "/api/agents/{id}", Perm::Admin),
        ("DELETE", "/api/agents/{id}", Perm::Admin),
        ("GET", "/api/software", Perm::User),
        ("POST", "/api/items/{id}/wake", Perm::User),
        ("POST", "/api/agent/thread", Perm::Free),
        ("POST", "/api/agent/reply", Perm::Free),
        ("POST", "/api/agent/help", Perm::Free),
        ("GET", "/api/notices", Perm::User),
        ("POST", "/api/notices", Perm::User),
        ("DELETE", "/api/notices/{id}", Perm::User),
        ("GET", "/api/files/{id}", Perm::User),
        ("POST", "/api/files", Perm::User),
        ("PUT", "/api/me/photo", Perm::Own),
        ("DELETE", "/api/me/photo", Perm::Own),
        ("GET", "/api/users/{id}/photo", Perm::User),
        ("GET", "/api/scripts", Perm::Admin),
        ("POST", "/api/scripts", Perm::Admin),
        ("GET", "/api/scripts/{id}", Perm::Admin),
        ("PUT", "/api/scripts/{id}", Perm::Admin),
        ("DELETE", "/api/scripts/{id}", Perm::Admin),
        ("POST", "/api/scripts/{id}/run", Perm::Admin),
        ("GET", "/api/runs", Perm::Admin),
        ("POST", "/api/remote/{id}/files", Perm::User),
        ("GET", "/api/remote/{id}/files/{fid}", Perm::User),
        ("POST", "/api/agent/remote/file", Perm::Free),
        ("POST", "/api/agent/remote/upload", Perm::Free),
        ("PUT", "/api/software", Perm::Admin),
        ("POST", "/api/login", Perm::Free),
        ("POST", "/api/logout", Perm::Pending),
        ("GET", "/api/me", Perm::Pending),
        ("POST", "/api/me/password", Perm::Pending),
        ("POST", "/api/me/totp", Perm::User),
        ("GET", "/api/sso", Perm::Free),
        ("GET", "/api/sso/start", Perm::Free),
        ("GET", "/api/sso/callback", Perm::Free),
        ("GET", "/api/sso/config", Perm::Admin),
        ("PUT", "/api/sso/config", Perm::Admin),
        ("GET", "/api/users", Perm::User),
        ("POST", "/api/users", Perm::Admin),
        ("PUT", "/api/users/{id}", Perm::Admin),
        ("DELETE", "/api/users/{id}", Perm::Admin),
        ("GET", "/api/groups", Perm::User),
        ("POST", "/api/groups", Perm::Admin),
        ("PUT", "/api/groups/{id}", Perm::Admin),
        ("DELETE", "/api/groups/{id}", Perm::Admin),
        ("GET", "/api/backup", Perm::Admin),
        ("POST", "/api/backup", Perm::Admin),
        ("POST", "/api/wipe", Perm::Admin),
        ("GET", "/api/update", Perm::Admin),
        ("PUT", "/api/update", Perm::Admin),
        ("POST", "/api/update/check", Perm::Admin),
        ("POST", "/api/update/apply", Perm::Admin),
        ("GET", "/api/pages", Perm::User),
        ("POST", "/api/pages", Perm::User),
        ("GET", "/api/pages/{id}", Perm::User),
        ("PUT", "/api/pages/{id}", Perm::User),
        ("DELETE", "/api/pages/{id}", Perm::User),
        ("GET", "/api/log", Perm::User),
        ("POST", "/api/log/{id}/undo", Perm::User),
        ("GET", "/api/items", Perm::User),
        ("POST", "/api/items", Perm::User),
        ("GET", "/api/items/{id}", Perm::User),
        ("PUT", "/api/items/{id}", Perm::User),
        ("DELETE", "/api/items/{id}", Perm::User),
        ("GET", "/api/items/{id}/refs", Perm::User),
        ("GET", "/api/items/{id}/syslog", Perm::User),
        ("GET", "/api/syslog", Perm::User),
        ("GET", "/api/expiries", Perm::User),
        ("POST", "/api/expiries", Perm::User),
        ("GET", "/api/expiries/{id}", Perm::User),
        ("PUT", "/api/expiries/{id}", Perm::User),
        ("DELETE", "/api/expiries/{id}", Perm::User),
        ("GET", "/api/subnets", Perm::User),
        ("POST", "/api/subnets", Perm::User),
        ("GET", "/api/subnets/{id}", Perm::User),
        ("PUT", "/api/subnets/{id}", Perm::User),
        ("DELETE", "/api/subnets/{id}", Perm::User),
        ("GET", "/api/subnets/{id}/ips", Perm::User),
        ("GET", "/api/subnets/{id}/scan", Perm::User),
        ("POST", "/api/subnets/{id}/scan", Perm::User),
        ("GET", "/api/apps", Perm::User),
        ("POST", "/api/apps", Perm::Admin),
        ("GET", "/api/apps/{id}", Perm::User),
        ("PUT", "/api/apps/{id}", Perm::Admin),
        ("DELETE", "/api/apps/{id}", Perm::Admin),
        ("GET", "/api/maps", Perm::User),
        ("POST", "/api/maps", Perm::User),
        ("GET", "/api/maps/{id}", Perm::User),
        ("PUT", "/api/maps/{id}", Perm::User),
        ("DELETE", "/api/maps/{id}", Perm::User),
        ("GET", "/api/maps/{id}/image", Perm::User),
        ("POST", "/api/maintenance", Perm::User),
        ("GET", "/api/checks", Perm::User),
        ("POST", "/api/checks", Perm::User),
        ("GET", "/api/checks/{id}", Perm::User),
        ("PUT", "/api/checks/{id}", Perm::User),
        ("DELETE", "/api/checks/{id}", Perm::User),
        ("POST", "/api/checks/{id}/mute", Perm::User),
        ("GET", "/api/sources", Perm::User),
        ("POST", "/api/sources", Perm::User),
        ("GET", "/api/sources/{id}", Perm::User),
        ("PUT", "/api/sources/{id}", Perm::User),
        ("DELETE", "/api/sources/{id}", Perm::User),
        ("POST", "/api/sources/{id}/mute", Perm::User),
        ("POST", "/api/sources/{id}/topology", Perm::User),
        ("POST", "/api/sources/test", Perm::User),
        ("GET", "/api/monitor", Perm::User),
        ("POST", "/api/monitor/test", Perm::User),
        ("GET", "/api/alerts", Perm::Admin),
        ("PUT", "/api/alerts", Perm::Admin),
        ("GET", "/api/retention", Perm::User),
        ("PUT", "/api/retention", Perm::Admin),
        ("GET", "/api/system", Perm::Admin),
        ("POST", "/api/ping", Perm::User),
        ("GET", "/api/sounds", Perm::User),
        ("POST", "/api/sounds", Perm::User),
        ("DELETE", "/api/sounds/{id}", Perm::User),
        ("GET", "/api/sounds/{id}/audio", Perm::User),
        ("GET", "/api/dashboard", Perm::User),
        ("PUT", "/api/dashboard", Perm::User),
        ("POST", "/api/discover", Perm::User),
        ("GET", "/api/latency", Perm::User),
        ("GET", "/api/sla", Perm::User),
        ("GET", "/api/health", Perm::User),
        ("GET", "/api/health/ws", Perm::User),
        ("GET", "/api/metrics", Perm::User),
        ("GET", "/api/incidents", Perm::User),
        ("POST", "/api/incidents", Perm::User),
        ("GET", "/api/incidents/{id}", Perm::User),
        ("PUT", "/api/incidents/{id}", Perm::User),
        ("DELETE", "/api/incidents/{id}", Perm::Admin),
        ("POST", "/api/incidents/{id}/notes", Perm::User),
        ("GET", "/api/tasks", Perm::Own),
        ("POST", "/api/tasks", Perm::Own),
        ("PUT", "/api/tasks/{id}", Perm::Own),
        ("DELETE", "/api/tasks/{id}", Perm::Own),
        ("POST", "/api/remote", Perm::User),
        ("GET", "/api/remote/{id}", Perm::User),
        ("DELETE", "/api/remote/{id}", Perm::User),
        ("GET", "/api/remote/{id}/ws", Perm::User),
        ("*", "/api", Perm::User),
        ("*", "/api/{*rest}", Perm::User),
    ];

    #[test]
    fn cada_ruta_con_su_permiso() {
        let rs = routes();
        let mut got: Vec<(&str, &str, Perm)> = rs.iter().map(|r| (r.method, r.path, r.perm)).collect();
        let mut want = EXPECTED.to_vec();
        got.sort_by_key(|x| (x.1, x.0));
        want.sort_by_key(|x| (x.1, x.0));
        assert_eq!(got, want);
    }

    /// Para cada ruta, quién pasa: sin sesión, con la contraseña provisional, de solo vista, normal y administrador.
    #[test]
    fn cada_ruta_deja_pasar_a_quien_toca() {
        let code = |perm, write, u| decide(perm, write, u).map_or(0, |r: Resp| r.code);
        for rt in routes() {
            let write = rt.method != "GET";
            let (anon, pending, ro, user, admin) = (None, Some((true, false, false)), Some((false, false, true)), Some((false, false, false)), Some((false, true, false)));
            let got = [anon, pending, ro, user, admin].map(|u| code(rt.perm, write, u));
            let want = match rt.perm {
                Perm::Free => [0, 0, 0, 0, 0],
                Perm::Pending => [401, 0, 0, 0, 0],
                Perm::Own => [401, 403, 0, 0, 0],
                Perm::User if write => [401, 403, 403, 0, 0],
                Perm::User => [401, 403, 0, 0, 0],
                Perm::Admin => [401, 403, 403, 403, 0],
            };
            // el método * se prueba también como escritura
            assert_eq!(got, want, "{} {}", rt.method, rt.path);
            if rt.method == "*" {
                assert_eq!(code(rt.perm, true, ro), 403, "{}", rt.path);
            }
        }
    }

    fn concrete(path: &str) -> String {
        path.replace("{id}", "1").replace("{fid}", "1").replace("{other}", "nada").replace("{*rest}", "x/y")
    }

    /// Por el router de verdad: sin sesión, toda ruta que no es libre responde 401 (y nunca llega a su manejador).
    #[tokio::test]
    async fn sin_sesion_401_en_el_router() {
        let app = app();
        for rt in routes().into_iter().filter(|r| r.perm != Perm::Free) {
            let m = if rt.method == "*" { "PATCH" } else { rt.method };
            let mut req = axum::http::Request::builder().method(m).uri(concrete(rt.path)).body(axum::body::Body::empty()).unwrap();
            req.extensions_mut().insert(Conn { peer: std::net::Ipv4Addr::LOCALHOST.into(), enc: true });
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), 401, "{m} {}", rt.path);
            assert_eq!(resp.headers()["x-frame-options"], "DENY");
        }
    }

    /// En claro desde la red: solo pasa la telemetría de las Kitty antiguas y lo que se ve sin secretos.
    #[tokio::test]
    async fn en_claro_desde_la_red() {
        let app = app();
        let lan: std::net::IpAddr = "192.168.1.9".parse().unwrap();
        let send = |m: &str, path: &str| {
            let mut req = axum::http::Request::builder().method(m).uri(path).header("host", "catlan:8080").body(axum::body::Body::empty()).unwrap();
            req.extensions_mut().insert(Conn { peer: lan, enc: false });
            app.clone().oneshot(req)
        };
        assert_eq!(send("GET", "/inventario").await.unwrap().status(), 301);
        for (m, p) in [("POST", "/api/login"), ("GET", "/api/items"), ("POST", "/api/agent/remote"), ("GET", "/api/agent/remote/ws"), ("GET", "/api/remote/x/ws"), ("POST", "/api/agent/quit")] {
            assert_eq!(send(m, p).await.unwrap().status(), 403, "{m} {p}");
        }
        assert!(plain("POST", "/api/agent", "catlan").is_none() && plain("GET", "/kitty.json", "catlan").is_none());
    }

    /// Un WebSocket desde otra web no se abre: lleva la sesión del navegador y luego teclado y ratón.
    #[tokio::test]
    async fn websocket_de_otra_web() {
        let mut req = axum::http::Request::builder()
            .uri("/api/remote/x/ws")
            .header("host", "catlan:8080")
            .header("origin", "https://malo.example")
            .header("upgrade", "websocket")
            .body(axum::body::Body::empty())
            .unwrap();
        req.extensions_mut().insert(Conn { peer: std::net::Ipv4Addr::LOCALHOST.into(), enc: true });
        assert_eq!(app().oneshot(req).await.unwrap().status(), 403);
    }
}
