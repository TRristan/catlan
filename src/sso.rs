//! Usuarios del dominio: LDAP/Active Directory (bind con el propio usuario) y OIDC (Entra ID, Google Workspace, Keycloak)
//! con PKCE. La configuración va en meta 'sso', como la retención; el secreto del cliente OIDC nunca sale por la API.
//! Los usuarios locales (el `admin` incluido) entran siempre con su contraseña de catlan: ni el dominio caído ni un
//! usuario del dominio con el mismo nombre los tapan.
use crate::crypto::{ct_eq, token_urlsafe};
use crate::db::{q, val};
use crate::snmp::{ber_int, ber_read, tlv};
use crate::util::{Bad, J, bad, lock, now};
use crate::{p, re};
use anyhow::{Result, anyhow, bail};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

const KEYS: [&str; 9] = ["ldap_url", "ldap_domain", "ldap_base", "ldap_pin", "oidc_issuer", "oidc_client", "oidc_secret", "oidc_name", "oidc_groups"];
/// Nunca sale por la API (como los de SNMP y SMTP); vacío al guardar = conservar el guardado.
pub const SSO_SECRET: [&str; 1] = ["oidc_secret"];

pub fn conf() -> Map<String, Value> {
    val("SELECT v FROM meta WHERE k='sso'", p![]).ok().and_then(|v| v.as_str().and_then(|s| serde_json::from_str(s).ok())).unwrap_or_default()
}

pub fn ldap_on(c: &Map<String, Value>) -> bool {
    !c.s("ldap_url").is_empty() && !c.s("ldap_domain").is_empty()
}

pub fn oidc_on(c: &Map<String, Value>) -> bool {
    !c.s("oidc_issuer").is_empty() && !c.s("oidc_client").is_empty()
}

/// Para Opciones: todo menos el secreto, que solo dice si está guardado.
pub fn view() -> Value {
    let c = conf();
    let mut out: Map<String, Value> = KEYS.iter().filter(|k| !SSO_SECRET.contains(k)).map(|k| (k.to_string(), c.s(k).into())).collect();
    out.insert("map".into(), c.get("map").cloned().unwrap_or(json!([])));
    out.insert("set".into(), SSO_SECRET.iter().map(|k| (k.to_string(), Value::from(!c.s(k).is_empty()))).collect::<Map<_, _>>().into());
    out.into()
}

/// Para la página de login, sin sesión: qué hay y, si se vuelve de un intento fallido, por qué.
pub fn public(code: &str) -> Value {
    let c = conf();
    let name = if c.s("oidc_name").is_empty() { "la cuenta de empresa" } else { c.s("oidc_name") };
    json!({"ldap": ldap_on(&c), "oidc": if oidc_on(&c) { Value::from(name) } else { Value::Null }, "error": if code.is_empty() { Value::Null } else { why(code).into() }})
}

/// Los motivos van por código en la dirección (`/?sso=acceso`): así nadie pone su texto en la página de login con un enlace.
pub fn why(code: &str) -> &'static str {
    match code {
        "acceso" => "Tu usuario del dominio no está en ningún grupo con acceso a catlan. Pide a IT que te añada.",
        "nombre" => "Ya hay un usuario local de catlan con tu nombre: un administrador tiene que borrarlo para que entres con el del dominio.",
        "caducado" => "El inicio de sesión ha caducado o no empezó en este navegador. Vuelve a probar.",
        "intentos" => "Demasiados intentos: espera 15 minutos.",
        "config" => "El inicio de sesión con la cuenta de empresa no está configurado.",
        "dominio" => "El dominio no contesta. Entra con un usuario local de catlan o prueba más tarde.",
        "cancelado" => "El proveedor no te ha dejado entrar.",
        _ => "No se ha podido terminar de entrar con el proveedor. Vuelve a probar; si sigue, mira el registro de catlan.",
    }
}

/// Sin cifrar solo a este mismo equipo (pruebas): por la red, la contraseña o el código viajarían en claro.
fn local(host: &str) -> bool {
    matches!(host, "localhost" | "::1") || host.starts_with("127.")
}

/// (cifrado, host, puerto) de ldap[s]://host[:puerto] o http[s]://host[:puerto]/…
fn split_url(url: &str) -> Option<(bool, &str, Option<u16>)> {
    let (tls, rest) = url.split_once("://").map(|(s, r)| (s.ends_with('s'), r))?;
    let hp = rest.split(['/', '?', '#']).next().unwrap_or("");
    let (h, port) = match hp.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') || h.ends_with(']') => (h, Some(p.parse().ok()?)),
        _ => (hp, None),
    };
    Some((tls, h.trim_start_matches('[').trim_end_matches(']'), port))
}

fn url_ok(url: &str) -> bool {
    split_url(url).is_some_and(|(tls, h, _)| crate::validate::host_ok(h) && (tls || local(h)))
}

/// Valida y deja en su forma guardada un campo de la configuración.
fn check(k: &str, v: &str) -> Result<String> {
    let ok = match k {
        "ldap_url" if re!(r"^ldaps?://\S+$").is_match(v) && !url_ok(v) => return bad("LDAP sin cifrar no: usa ldaps:// (la contraseña viajaría en claro)"),
        "ldap_url" => re!(r"^ldaps?://\[?[A-Za-z0-9.:-]+\]?(:\d{1,5})?/?$").is_match(v),
        "ldap_domain" => re!(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$").is_match(v),
        "ldap_base" => v.contains('=') && !v.chars().any(char::is_control),
        "ldap_pin" => {
            let h: String = v.chars().filter(|c| !matches!(c, ':' | ' ')).collect::<String>().to_uppercase();
            if !re!(r"^[0-9A-F]{64}$").is_match(&h) {
                return bad("huella del certificado: los 64 caracteres hex de su SHA-256");
            }
            return Ok(h);
        }
        "oidc_issuer" if !url_ok(v) || !v.starts_with("http") => return bad("el emisor OIDC es una dirección https://"),
        "oidc_issuer" => re!(r"^https?://\S+$").is_match(v),
        "oidc_client" => re!(r"^\S{1,200}$").is_match(v),
        "oidc_secret" => re!(r"^\S{1,500}$").is_match(v),
        "oidc_name" => v.chars().count() <= 40 && !v.chars().any(char::is_control),
        "oidc_groups" => re!(r"^[\w:/.-]{1,100}$").is_match(v),
        _ => false,
    };
    if !ok {
        return bad(format!("{k} no válido"));
    }
    Ok(if k.ends_with("_url") || k == "oidc_issuer" { v.trim_end_matches('/') } else { v }.to_string())
}

/// [{from: grupo del dominio, to: id de un grupo de catlan o "admin"}]
fn check_map(m: &Value) -> Result<Value> {
    let Some(a) = m.as_array().filter(|a| a.len() <= 100) else { return bad("map: una lista de hasta 100 grupos") };
    let groups: Vec<i64> = q("SELECT id FROM groups", p![])?.into_iter().filter_map(|r| r.i("id")).collect();
    let mut out = vec![];
    for x in a {
        let from = x.s("from").trim();
        if from.is_empty() || from.chars().count() > 300 || from.chars().any(char::is_control) {
            return bad("cada grupo del dominio necesita su nombre (hasta 300 caracteres)");
        }
        let to = match x.val("to") {
            Value::String(s) if s == "admin" => json!("admin"),
            v if v.as_i64().is_some_and(|g| groups.contains(&g)) => v.clone(),
            _ => return bad(format!("{from}: elige un grupo de catlan o administrador")),
        };
        out.push(json!({"from": from, "to": to}));
    }
    Ok(out.into())
}

pub fn set(b: &Value) -> Result<Value> {
    let Some(b) = b.as_object() else { return bad("envía un objeto") };
    let mut c = conf();
    for k in KEYS {
        let Some(v) = b.get(k) else { continue };
        if v.is_null() {
            c.shift_remove(k);
            continue;
        }
        let Some(v) = v.as_str().filter(|s| s.chars().count() <= 500) else { return bad(format!("{k} no válido")) };
        let v = v.trim();
        if v.is_empty() {
            if !SSO_SECRET.contains(&k) {
                c.shift_remove(k);
            }
            continue; // secreto vacío = conservar el guardado
        }
        c.insert(k.into(), check(k, v)?.into());
    }
    if let Some(m) = b.get("map") {
        c.insert("map".into(), check_map(m)?);
    }
    q("INSERT OR REPLACE INTO meta(k, v) VALUES('sso', ?)", p![Value::Object(c).to_string()])?;
    *lock(&DISCO) = None;
    Ok(view())
}

/// Alguien que el dominio ha reconocido: `key` lo identifica siempre (aunque cambie de nombre), `name` es su usuario.
#[derive(Debug)]
pub struct Ext {
    pub key: String,
    pub name: String,
    pub groups: Vec<String>,
}

/// Su nombre como usuario de catlan (letras, números y . _ @ -, hasta 40).
pub fn local_name(n: &str) -> String {
    n.chars().map(|c| if c.is_ascii_alphanumeric() || "._@-".contains(c) { c } else { '_' }).take(40).collect()
}

/// «CN=IT,OU=Grupos,DC=empresa,DC=local» vale escrito entero o solo «IT»; el «/IT» de Keycloak, como «IT».
fn same_group(g: &str, from: &str) -> bool {
    let (g, from) = (g.trim(), from.trim());
    if from.contains('=') {
        return g.to_lowercase() == from.to_lowercase();
    }
    let cn = g.split(',').next().and_then(|r| r.split_once('=')).filter(|(k, _)| k.trim().eq_ignore_ascii_case("cn")).map_or(g, |(_, v)| v.trim());
    cn.trim_start_matches('/').to_lowercase() == from.trim_start_matches('/').to_lowercase()
}

/// (admin, grupos de catlan) que le dan sus grupos del dominio. None: ninguno tiene acceso a catlan.
pub fn roles(c: &Map<String, Value>, groups: &[String]) -> Option<(bool, Vec<i64>)> {
    let (mut hit, mut admin, mut ids) = (false, false, vec![]);
    for m in c.get("map").and_then(Value::as_array).into_iter().flatten() {
        if !groups.iter().any(|g| same_group(g, m.s("from"))) {
            continue;
        }
        hit = true;
        match m.val("to") {
            Value::String(s) if s == "admin" => admin = true,
            v => ids.extend(v.as_i64()),
        }
    }
    hit.then_some((admin, ids))
}

// ── LDAP: lo justo de RFC 4511 en BER a mano (bind simple, «¿quién soy?» y una búsqueda), como el SNMP ──

trait Conn: Read + Write {}
impl<T: Read + Write> Conn for T {}

/// Acepta solo el certificado con esta huella (sha256 en hex): para el controlador de dominio con uno autofirmado.
#[derive(Debug)]
struct Pinned(String, Arc<rustls::crypto::CryptoProvider>);
impl rustls::client::danger::ServerCertVerifier for Pinned {
    fn verify_server_cert(&self, c: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let h = crate::crypto::hex(&<sha2::Sha256 as sha2::Digest>::digest(c));
        if h.eq_ignore_ascii_case(&self.0) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!("el certificado del dominio no es el anclado (es {h})")))
        }
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.1.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.1.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.1.signature_verification_algorithms.supported_schemes()
    }
}

/// Los certificados raíz del sistema (en un equipo del dominio, también la CA de la empresa).
static ROOTS: LazyLock<Arc<rustls::RootCertStore>> = LazyLock::new(|| {
    let mut r = rustls::RootCertStore::empty();
    r.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    Arc::new(r)
});

fn tls_cfg(pin: &str) -> Result<Arc<rustls::ClientConfig>> {
    let prov = Arc::new(rustls::crypto::ring::default_provider());
    let b = rustls::ClientConfig::builder_with_provider(prov.clone()).with_safe_default_protocol_versions()?;
    Ok(Arc::new(if pin.is_empty() {
        b.with_root_certificates(ROOTS.clone()).with_no_client_auth()
    } else {
        b.dangerous().with_custom_certificate_verifier(Arc::new(Pinned(pin.into(), prov))).with_no_client_auth()
    }))
}

fn open(url: &str, pin: &str) -> Result<Box<dyn Conn>> {
    let Some((tls, host, port)) = split_url(url).filter(|_| url.starts_with("ldap")) else { bail!("dirección LDAP no válida") };
    if !tls && !local(host) {
        bail!("LDAP sin cifrar no: usa ldaps://"); // nunca una contraseña en claro por la red
    }
    let s = crate::monitor::connect(host, port.unwrap_or(if tls { 636 } else { 389 }), Duration::from_secs(5)).map_err(|e| anyhow!("{host}: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;
    if !tls {
        return Ok(Box::new(s));
    }
    let c = rustls::ClientConnection::new(tls_cfg(pin)?, ServerName::try_from(host.to_string())?)?;
    Ok(Box::new(rustls::StreamOwned::new(c, s)))
}

fn os(s: &str) -> Vec<u8> {
    tlv(4, s.as_bytes())
}

fn msg(id: i64, op: &[u8]) -> Vec<u8> {
    tlv(0x30, &[ber_int(id as i128, 2), op.to_vec()].concat())
}

fn eq(attr: &str, v: &str) -> Vec<u8> {
    tlv(0xa3, &[os(attr), os(v)].concat())
}

fn int(v: &[u8]) -> i64 {
    v.iter().fold(0, |a, x| (a << 8) | *x as i64)
}

/// Un mensaje entero del servidor (hasta 1 MB).
fn read_msg(s: &mut dyn Conn) -> Result<Vec<u8>> {
    let mut h = [0u8; 2];
    s.read_exact(&mut h)?;
    let mut out = h.to_vec();
    let n = if h[1] & 0x80 == 0 {
        h[1] as usize
    } else {
        let mut b = vec![0; (h[1] & 0x7f) as usize];
        if b.is_empty() || b.len() > 4 {
            bail!("respuesta LDAP rara");
        }
        s.read_exact(&mut b)?;
        out.extend(&b);
        b.iter().fold(0, |a, x| (a << 8) | *x as usize)
    };
    if n > 1 << 20 {
        bail!("respuesta LDAP enorme");
    }
    let mut body = vec![0; n];
    s.read_exact(&mut body)?;
    out.extend(body);
    Ok(out)
}

/// (etiqueta, contenido) de la operación que responde al mensaje `id`.
fn reply(s: &mut dyn Conn, id: i64) -> Result<(u8, Vec<u8>)> {
    loop {
        let raw = read_msg(s)?;
        let (_, m, _) = ber_read(&raw, 0)?;
        let (_, mid, i) = ber_read(m, 0)?;
        let (tag, op, _) = ber_read(m, i)?;
        if int(mid) == id {
            return Ok((tag, op.to_vec()));
        }
    }
}

/// (código, mensaje) de un LDAPResult; lo que sigue (p. ej. el valor de una operación extendida) va en el tercero.
fn result(op: &[u8]) -> Result<(i64, String, usize)> {
    let (_, code, i) = ber_read(op, 0)?;
    let (_, _, i) = ber_read(op, i)?;
    let (_, diag, i) = ber_read(op, i)?;
    Ok((int(code), String::from_utf8_lossy(diag).into(), i))
}

fn each(b: &[u8]) -> Result<Vec<(u8, &[u8])>> {
    let (mut out, mut i) = (vec![], 0);
    while i < b.len() {
        let (t, v, n) = ber_read(b, i)?;
        out.push((t, v));
        i = n;
    }
    Ok(out)
}

/// SearchResultEntry: sus atributos en minúsculas.
fn entry(op: &[u8]) -> Result<HashMap<String, Vec<String>>> {
    let (_, _, i) = ber_read(op, 0)?;
    let (_, attrs, _) = ber_read(op, i)?;
    let mut out = HashMap::new();
    for (_, a) in each(attrs)? {
        let (_, name, i) = ber_read(a, 0)?;
        let (_, vals, _) = ber_read(a, i)?;
        let vals = each(vals)?.into_iter().map(|(_, v)| String::from_utf8_lossy(v).into_owned()).collect();
        out.insert(String::from_utf8_lossy(name).to_lowercase(), vals);
    }
    Ok(out)
}

pub fn ldap_login(user: &str, pw: &str) -> Result<Option<Ext>> {
    ldap_with(&conf(), user, pw)
}

/// Ok(None): usuario o contraseña incorrectos. Err: el dominio no contesta o está mal configurado.
/// Vale «juan», «juan@empresa.local» y «EMPRESA\juan»; quién es lo dice el propio dominio después del bind.
fn ldap_with(c: &Map<String, Value>, user: &str, pw: &str) -> Result<Option<Ext>> {
    if !ldap_on(c) {
        bail!("LDAP sin configurar");
    }
    let domain = c.s("ldap_domain");
    // contraseña vacía = bind anónimo, que el servidor da por bueno: nunca
    if pw.is_empty() || user.trim().is_empty() || user.chars().any(char::is_control) {
        return Ok(None);
    }
    let user = user.rsplit('\\').next().unwrap_or(user);
    let upn = if user.contains('@') { user.to_string() } else { format!("{user}@{domain}") };
    let base = match c.s("ldap_base") {
        "" => domain.split('.').map(|p| format!("DC={p}")).collect::<Vec<_>>().join(","),
        b => b.to_string(),
    };
    let mut s = open(c.s("ldap_url"), c.s("ldap_pin"))?;
    s.write_all(&msg(1, &tlv(0x60, &[ber_int(3, 2), os(&upn), tlv(0x80, pw.as_bytes())].concat())))?;
    let (tag, op) = reply(&mut *s, 1)?;
    let (code, diag, _) = result(&op).ok().filter(|_| tag == 0x61).ok_or_else(|| anyhow!("respuesta LDAP inesperada"))?;
    match code {
        0 => {}
        49 => return Ok(None), // invalidCredentials (también cuenta deshabilitada o caducada)
        _ => bail!("el dominio no acepta el bind ({code}): {diag}"),
    }
    // ¿quién soy? (RFC 4532): AD contesta «u:EMPRESA\juan»; otros, «dn:uid=juan,…»
    s.write_all(&msg(2, &tlv(0x77, &tlv(0x80, b"1.3.6.1.4.1.4203.1.11.3"))))?;
    let (_, op) = reply(&mut *s, 2)?;
    let (code, diag, i) = result(&op)?;
    let me = each(&op[i..])?.into_iter().find(|(t, _)| *t == 0x8b).map(|(_, v)| String::from_utf8_lossy(v).into_owned()).unwrap_or_default();
    if code != 0 || me.is_empty() {
        bail!("el dominio no dice quién es el usuario ({code}): {diag}");
    }
    // la búsqueda se hace por lo que dice el dominio, no por lo que se escribió: otro UPN no se cuela como este usuario
    let (base, scope, filter) = match (me.strip_prefix("u:"), me.strip_prefix("dn:")) {
        (Some(u), _) => (base, 2, tlv(0xa0, &[eq("objectClass", "user"), eq("sAMAccountName", u.rsplit('\\').next().unwrap_or(u))].concat())),
        (_, Some(dn)) => (dn.to_string(), 0, tlv(0x87, b"objectClass")),
        _ => bail!("respuesta rara del dominio a «¿quién soy?»: {me}"),
    };
    let attrs = tlv(0x30, &[os("sAMAccountName"), os("uid"), os("memberOf")].concat());
    let search = [os(&base), ber_int(scope, 0x0a), ber_int(0, 0x0a), ber_int(2, 2), ber_int(10, 2), tlv(1, &[0]), filter, attrs].concat();
    s.write_all(&msg(3, &tlv(0x63, &search)))?;
    let mut found = vec![];
    loop {
        let (tag, op) = reply(&mut *s, 3)?;
        match tag {
            0x64 => found.push(entry(&op)?),
            0x65 => {
                let (code, diag, _) = result(&op)?;
                if code != 0 && code != 4 {
                    bail!("el dominio no deja buscar el usuario en {base} ({code}): {diag}");
                }
                break;
            }
            _ => {} // referencias a otros dominios del bosque
        }
    }
    let _ = s.write_all(&msg(4, &tlv(0x42, &[]))); // unbind
    let [e] = &found[..] else { bail!("{me}: {} entradas en {base} (debe haber una)", found.len()) };
    let one = |k: &str| e.get(k).and_then(|v| v.first()).cloned().unwrap_or_default();
    let name = [one("samaccountname"), one("uid")].into_iter().find(|n| !n.is_empty()).ok_or_else(|| anyhow!("{me} no tiene sAMAccountName"))?;
    // shortcut: solo los grupos directos (memberOf); los anidados de AD, con la regla 1.2.840.113556.1.4.1941 si alguien los pide
    Ok(Some(Ext { key: format!("ldap:{}", name.to_lowercase()), name, groups: e.get("memberof").cloned().unwrap_or_default() }))
}

// ── OIDC: flujo de código con PKCE (S256), state y nonce ──

struct Pending {
    verifier: String,
    nonce: String,
    redirect: String,
    exp: f64,
}
/// Inicios de sesión a medias, por su `state` (10 minutos).
static PENDING: LazyLock<Mutex<HashMap<String, Pending>>> = LazyLock::new(Default::default);
/// (emisor, documento de descubrimiento, hasta cuándo vale)
static DISCO: LazyLock<Mutex<Option<(String, Value, f64)>>> = LazyLock::new(Default::default);

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(Duration::from_secs(10)).redirects(0).build()
}

fn discovery(issuer: &str) -> Result<Value> {
    if let Some((i, d, t)) = &*lock(&DISCO)
        && i == issuer
        && *t > now()
    {
        return Ok(d.clone());
    }
    let d: Value = agent().get(&format!("{issuer}/.well-known/openid-configuration")).call()?.into_string()?.parse()?;
    for k in ["issuer", "authorization_endpoint", "token_endpoint"] {
        if !url_ok(d.s(k)) || !d.s(k).starts_with("http") {
            bail!("el proveedor OIDC no da {k} por https");
        }
    }
    *lock(&DISCO) = Some((issuer.into(), d.clone(), now() + 3600.0));
    Ok(d)
}

pub fn oidc_start(redirect: &str) -> Result<(String, String)> {
    oidc_start_with(&conf(), redirect)
}

/// La dirección del proveedor a la que va el navegador y el `state`, que vuelve en una cookie para atarlo a este navegador.
fn oidc_start_with(c: &Map<String, Value>, redirect: &str) -> Result<(String, String)> {
    let d = discovery(c.s("oidc_issuer"))?;
    let (state, nonce, verifier) = (token_urlsafe(24), token_urlsafe(24), token_urlsafe(48));
    let challenge = data_encoding::BASE64URL_NOPAD.encode(&<sha2::Sha256 as sha2::Digest>::digest(verifier.as_bytes()));
    {
        let mut p = lock(&PENDING);
        let t = now();
        p.retain(|_, x| x.exp > t);
        if p.len() >= 1000 {
            return Err(Bad("demasiados inicios de sesión a la vez: espera un poco".into()).into()); // sin sesión: que nadie llene la memoria
        }
        p.insert(state.clone(), Pending { verifier, nonce: nonce.clone(), redirect: redirect.into(), exp: t + 600.0 });
    }
    let qs = form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", c.s("oidc_client"))
        .append_pair("redirect_uri", redirect)
        .append_pair("scope", "openid profile email")
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();
    let a = d.s("authorization_endpoint");
    Ok((format!("{a}{}{qs}", if a.contains('?') { '&' } else { '?' }), state))
}

pub fn oidc_finish(state: &str, code: &str) -> Result<Ext> {
    oidc_finish_with(&conf(), state, code)
}

fn claims(id_token: &str) -> Result<Value> {
    let part = id_token.split('.').nth(1).ok_or_else(|| anyhow!("el proveedor no ha dado id_token"))?;
    Ok(serde_json::from_slice(&data_encoding::BASE64URL_NOPAD.decode(part.trim_end_matches('=').as_bytes())?)?)
}

/// shortcut: la firma del id_token no se comprueba: llega directo del proveedor por TLS (OIDC Core 3.1.3.7, punto 6);
/// comprobarla con su JWKS si algún día llega por el navegador (flujo implícito o híbrido).
fn check_claims(t: &Value, iss: &str, client: &str, nonce: &str, at: f64) -> Result<()> {
    let aud = match t.val("aud") {
        Value::String(a) => a == client,
        Value::Array(a) => a.iter().any(|x| x == client) && (a.len() == 1 || t.s("azp") == client),
        _ => false,
    };
    let bad_one = if t.s("iss") != iss {
        "emisor"
    } else if !aud {
        "destinatario (aud)"
    } else if !t.val("exp").as_f64().is_some_and(|e| e + 60.0 > at) {
        "caducado"
    } else if !ct_eq(t.s("nonce").as_bytes(), nonce.as_bytes()) {
        "nonce"
    } else if t.s("sub").is_empty() {
        "sin sub"
    } else {
        return Ok(());
    };
    bail!("id_token no válido: {bad_one}")
}

fn oidc_finish_with(c: &Map<String, Value>, state: &str, code: &str) -> Result<Ext> {
    let Some(p) = lock(&PENDING).remove(state).filter(|p| p.exp > now()) else { return Err(Bad("caducado".into()).into()) };
    let d = discovery(c.s("oidc_issuer"))?;
    let mut form = vec![("grant_type", "authorization_code"), ("code", code), ("redirect_uri", p.redirect.as_str()), ("client_id", c.s("oidc_client")), ("code_verifier", p.verifier.as_str())];
    if !c.s("oidc_secret").is_empty() {
        form.push(("client_secret", c.s("oidc_secret")));
    }
    let tok: Value = match agent().post(d.s("token_endpoint")).set("Accept", "application/json").send_form(&form) {
        Ok(r) => r.into_string()?.parse()?,
        Err(ureq::Error::Status(n, r)) => {
            let e: Value = r.into_string().ok().and_then(|t| t.parse().ok()).unwrap_or_default();
            bail!("el proveedor no da el token ({n}): {} {}", e.s("error"), e.s("error_description"));
        }
        Err(e) => return Err(e.into()),
    };
    let t = claims(tok.s("id_token"))?;
    check_claims(&t, d.s("issuer"), c.s("oidc_client"), &p.nonce, now())?;
    let name = [t.s("preferred_username"), t.s("email"), t.s("sub")].into_iter().find(|s| !s.is_empty()).unwrap_or("").to_string();
    let claim = if c.s("oidc_groups").is_empty() { "groups" } else { c.s("oidc_groups") };
    let mut groups: Vec<String> = match t.val(claim) {
        Value::Array(a) => a.iter().filter_map(|g| g.as_str().map(String::from)).collect(),
        Value::String(s) => vec![s.clone()],
        _ => vec![],
    };
    // Google Workspace no manda grupos: su dominio de correo (verificado) cuenta como el grupo «@empresa.com»
    if (t.val("email_verified") == &json!(true) || t.s("email_verified") == "true")
        && let Some((_, dom)) = t.s("email").rsplit_once('@')
    {
        groups.push(format!("@{}", dom.to_lowercase()));
    }
    Ok(Ext { key: format!("oidc:{}|{}", d.s("issuer"), t.s("sub")), name, groups })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn cfg(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap()
    }

    #[test]
    fn grupos_del_dominio() {
        assert!(same_group("CN=IT,OU=Grupos,DC=empresa,DC=local", "it"));
        assert!(same_group("CN=IT,OU=Grupos,DC=empresa,DC=local", "cn=it,ou=grupos,dc=empresa,dc=local"));
        assert!(!same_group("CN=IT,OU=Otros,DC=empresa,DC=local", "CN=IT,OU=Grupos,DC=empresa,DC=local")); // escrito entero, solo ese
        assert!(same_group("/Técnicos", "técnicos") && !same_group("CN=ITX,DC=e", "IT"));
        let c = cfg(json!({"map": [{"from": "IT", "to": 3}, {"from": "Jefes", "to": "admin"}, {"from": "@empresa.com", "to": 4}]}));
        assert_eq!(roles(&c, &["CN=IT,DC=e".into()]), Some((false, vec![3])));
        assert_eq!(roles(&c, &["CN=jefes,DC=e".into(), "CN=IT,DC=e".into()]), Some((true, vec![3])));
        assert_eq!(roles(&c, &["@empresa.com".into()]), Some((false, vec![4])));
        assert_eq!(roles(&c, &["CN=Ventas,DC=e".into()]), None);
        assert_eq!(local_name("José Pérez@x"), "Jos__P_rez@x");
    }

    #[test]
    fn urls_sin_cifrar_solo_a_este_equipo() {
        assert!(url_ok("ldaps://dc1.empresa.local") && url_ok("ldaps://10.0.0.5:3269") && url_ok("ldap://127.0.0.1:3389"));
        assert!(!url_ok("ldap://dc1.empresa.local") && !url_ok("http://idp.empresa.com") && url_ok("https://idp.empresa.com/realms/x"));
        assert!(check("ldap_url", "ldap://dc1").is_err() && check("oidc_issuer", "http://idp").is_err());
        assert_eq!(check("ldap_pin", &"ab:".repeat(32)).unwrap(), "AB".repeat(32));
    }

    #[test]
    fn id_token() {
        let t = json!({"iss": "https://idp", "aud": ["catlan", "otro"], "azp": "catlan", "exp": 1000, "nonce": "n1", "sub": "42"});
        assert!(check_claims(&t, "https://idp", "catlan", "n1", 900.0).is_ok());
        assert!(check_claims(&t, "https://otro", "catlan", "n1", 900.0).is_err());
        assert!(check_claims(&t, "https://idp", "catlan", "n2", 900.0).is_err());
        assert!(check_claims(&t, "https://idp", "catlan", "n1", 1100.0).is_err());
        assert!(check_claims(&t, "https://idp", "otro", "n1", 900.0).is_err()); // varios aud: azp tiene que ser este cliente
        assert!(check_claims(&json!({"iss": "https://idp", "aud": "catlan", "exp": 1000, "nonce": "n1"}), "https://idp", "catlan", "n1", 0.0).is_err());
    }

    /// Un controlador de dominio de mentira: juan / clave-buena, que está en IT. Cuenta las conexiones.
    fn fake_ldap(tls: Option<Arc<rustls::ServerConfig>>) -> (u16, Arc<Mutex<usize>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let (port, n) = (l.local_addr().unwrap().port(), Arc::new(Mutex::new(0)));
        let seen = n.clone();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                *lock(&seen) += 1;
                let mut s: Box<dyn Conn> = match &tls {
                    Some(t) => Box::new(rustls::StreamOwned::new(rustls::ServerConnection::new(t.clone()).unwrap(), s)),
                    None => Box::new(s),
                };
                let _ = serve_ldap(&mut *s);
            }
        });
        (port, n)
    }

    fn serve_ldap(s: &mut dyn Conn) -> Result<()> {
        let done = |code: i64, tag: u8| tlv(tag, &[ber_int(code as i128, 0x0a), os(""), os("")].concat());
        loop {
            let raw = read_msg(s)?;
            let (_, m, _) = ber_read(&raw, 0)?;
            let (_, id, i) = ber_read(m, 0)?;
            let (tag, op, _) = ber_read(m, i)?;
            let id = int(id);
            match tag {
                0x60 => {
                    let f = each(op)?;
                    let ok = f[1].1 == b"juan@empresa.local" && f[2].1 == b"clave-buena";
                    s.write_all(&msg(id, &done(if ok { 0 } else { 49 }, 0x61)))?;
                }
                0x77 => s.write_all(&msg(id, &tlv(0x78, &[ber_int(0, 0x0a), os(""), os(""), tlv(0x8b, b"u:EMPRESA\\juan")].concat())))?,
                0x63 => {
                    assert!(raw.windows(4).any(|w| w == b"juan") && raw.windows(17).any(|w| w == b"DC=empresa,DC=loc"));
                    let attr = |k: &str, vs: &[&str]| tlv(0x30, &[os(k), tlv(0x31, &vs.iter().map(|v| os(v)).collect::<Vec<_>>().concat())].concat());
                    let attrs = tlv(0x30, &[attr("sAMAccountName", &["Juan"]), attr("memberOf", &["CN=IT,OU=Grupos,DC=empresa,DC=local", "CN=Todos,DC=empresa,DC=local"])].concat());
                    s.write_all(&msg(id, &tlv(0x64, &[os("CN=Juan,DC=empresa,DC=local"), attrs].concat())))?;
                    s.write_all(&msg(id, &tlv(0x73, &os("ldap://otro/DC=otro"))))?; // una referencia: se ignora
                    s.write_all(&msg(id, &done(0, 0x65)))?;
                }
                _ => return Ok(()), // unbind
            }
        }
    }

    #[test]
    fn ldap_bind_con_el_usuario_y_sus_grupos() {
        let (port, conns) = fake_ldap(None);
        let c = cfg(json!({"ldap_url": format!("ldap://127.0.0.1:{port}"), "ldap_domain": "empresa.local"}));
        for user in ["juan", "EMPRESA\\juan", "juan@empresa.local"] {
            let x = ldap_with(&c, user, "clave-buena").unwrap().unwrap();
            assert_eq!((x.key.as_str(), x.name.as_str()), ("ldap:juan", "Juan"));
            assert_eq!(x.groups, ["CN=IT,OU=Grupos,DC=empresa,DC=local", "CN=Todos,DC=empresa,DC=local"]);
        }
        assert!(ldap_with(&c, "juan", "mala").unwrap().is_none());
        let before = *lock(&conns);
        assert!(ldap_with(&c, "juan", "").unwrap().is_none()); // sin contraseña ni se pregunta (sería un bind anónimo)
        assert_eq!(*lock(&conns), before);
        let off = cfg(json!({"ldap_url": "ldap://127.0.0.1:1", "ldap_domain": "empresa.local"}));
        assert!(ldap_with(&off, "juan", "clave-buena").is_err()); // dominio caído: error, no «contraseña mal»
        let lan = cfg(json!({"ldap_url": format!("ldap://10.255.255.1:{port}"), "ldap_domain": "empresa.local"}));
        assert!(ldap_with(&lan, "juan", "clave-buena").unwrap_err().to_string().contains("ldaps"));
    }

    #[test]
    fn ldaps_anclado_al_certificado() {
        let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let der = ck.cert.der().to_vec();
        let key = rustls::pki_types::PrivateKeyDer::try_from(ck.signing_key.serialize_der()).unwrap();
        let prov = Arc::new(rustls::crypto::ring::default_provider());
        let srv = rustls::ServerConfig::builder_with_provider(prov).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(vec![der.clone().into()], key).unwrap();
        let (port, _) = fake_ldap(Some(Arc::new(srv)));
        let pin = crate::crypto::hex(&<sha2::Sha256 as sha2::Digest>::digest(&der));
        let c = |pin: &str| cfg(json!({"ldap_url": format!("ldaps://127.0.0.1:{port}"), "ldap_domain": "empresa.local", "ldap_pin": pin}));
        assert_eq!(ldap_with(&c(&pin), "juan", "clave-buena").unwrap().unwrap().name, "Juan");
        assert!(ldap_with(&c(&"0".repeat(64)), "juan", "clave-buena").is_err()); // otro certificado: ni se manda la contraseña
        assert!(ldap_with(&c(""), "juan", "clave-buena").is_err()); // autofirmado sin anclar: no es de una CA del sistema
    }

    /// Un proveedor OIDC de mentira: descubrimiento y token. Comprueba PKCE y devuelve un id_token con el nonce que le den.
    fn fake_oidc(claims: Arc<Mutex<Value>>, challenge: Arc<Mutex<String>>) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
        let me = base.clone();
        std::thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                let mut buf = vec![];
                let mut b = [0u8; 4096];
                while let Ok(n) = s.read(&mut b) {
                    buf.extend(&b[..n]);
                    let txt = String::from_utf8_lossy(&buf).to_string();
                    if let Some((head, body)) = txt.split_once("\r\n\r\n") {
                        let len = head.lines().find_map(|l| l.to_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0))).unwrap_or(0);
                        if body.len() >= len {
                            break;
                        }
                    }
                    if n == 0 {
                        break;
                    }
                }
                let txt = String::from_utf8_lossy(&buf).to_string();
                let (head, body) = txt.split_once("\r\n\r\n").unwrap_or((&txt, ""));
                let (code, out) = if head.starts_with("GET /.well-known/openid-configuration") {
                    (200, json!({"issuer": me, "authorization_endpoint": format!("{me}/auth"), "token_endpoint": format!("{me}/token")}))
                } else {
                    let f: HashMap<String, String> = form_urlencoded::parse(body.as_bytes()).into_owned().collect();
                    let pkce = data_encoding::BASE64URL_NOPAD.encode(&<sha2::Sha256 as sha2::Digest>::digest(f["code_verifier"].as_bytes()));
                    if pkce != *lock(&challenge) || f["code"] != "el-codigo" || f["client_secret"] != "s3creto" {
                        (400, json!({"error": "invalid_grant"}))
                    } else {
                        let enc = |v: &Value| data_encoding::BASE64URL_NOPAD.encode(v.to_string().as_bytes());
                        (200, json!({"id_token": format!("{}.{}.firma", enc(&json!({"alg": "RS256"})), enc(&lock(&claims)))}))
                    }
                };
                let out = out.to_string();
                let _ = write!(s, "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}", out.len());
            }
        });
        base
    }

    #[test]
    fn oidc_con_pkce() {
        let (claims, challenge) = (Arc::new(Mutex::new(json!({}))), Arc::new(Mutex::new(String::new())));
        let iss = fake_oidc(claims.clone(), challenge.clone());
        let c = cfg(json!({"oidc_issuer": iss, "oidc_client": "catlan", "oidc_secret": "s3creto", "oidc_groups": "roles"}));
        let start = |c: &Map<String, Value>| {
            let (url, state) = oidc_start_with(c, "https://catlan.empresa.local/api/sso/callback").unwrap();
            assert!(url.starts_with(&format!("{iss}/auth?")));
            let q: HashMap<String, String> = form_urlencoded::parse(url.split_once('?').unwrap().1.as_bytes()).into_owned().collect();
            assert_eq!((q["state"].as_str(), q["code_challenge_method"].as_str(), q["client_id"].as_str()), (state.as_str(), "S256", "catlan"));
            assert_eq!(q["redirect_uri"], "https://catlan.empresa.local/api/sso/callback");
            *lock(&challenge) = q["code_challenge"].clone();
            (state, q["nonce"].clone())
        };
        let (state, nonce) = start(&c);
        *lock(&claims) = json!({"iss": iss, "aud": "catlan", "exp": now() + 300.0, "nonce": nonce, "sub": "abc", "preferred_username": "ana@empresa.com",
                               "email": "ana@Empresa.com", "email_verified": true, "roles": ["it"]});
        let x = oidc_finish_with(&c, &state, "el-codigo").unwrap();
        assert_eq!((x.key, x.name, x.groups), (format!("oidc:{iss}|abc"), "ana@empresa.com".into(), vec!["it".to_string(), "@empresa.com".into()]));
        assert!(oidc_finish_with(&c, &state, "el-codigo").is_err()); // el mismo state no vale dos veces
        let (state, _) = start(&c); // el id_token trae el nonce de otro intento
        assert!(oidc_finish_with(&c, &state, "el-codigo").unwrap_err().to_string().contains("nonce"));
        let (state, _) = start(&c);
        *lock(&challenge) = "otro".into(); // quien robe el código no tiene el verificador
        assert!(oidc_finish_with(&c, &state, "el-codigo").unwrap_err().to_string().contains("invalid_grant"));
        assert!(oidc_finish_with(&c, "inventado", "el-codigo").is_err());
    }
}
