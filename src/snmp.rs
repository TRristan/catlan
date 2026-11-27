//! SNMP mínimo: GET y GETBULK sobre UDP, codificación BER a mano, v2c y v3 (USM con firma HMAC y cifrado AES-128).
//! shortcut: sin DES ni AES-192/256 (DES está obsoleto y AES-128 lo admiten todos los fabricantes); añadirlos si un equipo solo da esos.
use crate::crypto::{aes_cfb, auth_len, ct_eq, hmac, rand_bytes, usm_key};
use anyhow::{Result, anyhow, bail};
use indexmap::IndexMap;
use std::net::{ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

fn blen(n: usize) -> Vec<u8> {
    if n < 128 {
        return vec![n as u8];
    }
    let b: Vec<u8> = n.to_be_bytes().into_iter().skip_while(|x| *x == 0).collect();
    [vec![0x80 | b.len() as u8], b].concat()
}

pub fn tlv(tag: u8, v: &[u8]) -> Vec<u8> {
    [&[tag][..], &blen(v.len()), v].concat()
}

/// Entero BER en complemento a dos, con los bytes justos (como `int.to_bytes` de Python).
pub fn ber_int(n: i128, tag: u8) -> Vec<u8> {
    let bits = 128 - n.unsigned_abs().leading_zeros() as usize;
    let len = ((bits + 8) / 8).max(1);
    tlv(tag, &n.to_be_bytes()[16 - len..])
}

pub fn ber_oid(oid: &str) -> Result<Vec<u8>> {
    let p: Vec<u64> = oid.split('.').map(|x| x.parse()).collect::<Result<_, _>>().map_err(|_| anyhow!("OID no válido: {oid}"))?;
    if p.len() < 2 {
        bail!("OID no válido: {oid}");
    }
    let mut out = vec![(40 * p[0] + p[1]) as u8];
    for &x in &p[2..] {
        let mut chunk = vec![(x & 0x7F) as u8];
        let mut x = x >> 7;
        while x > 0 {
            chunk.push(0x80 | (x & 0x7F) as u8);
            x >>= 7;
        }
        out.extend(chunk.iter().rev());
    }
    Ok(tlv(6, &out))
}

/// Lee un TLV en la posición i: (etiqueta, valor, posición siguiente).
pub fn ber_read(b: &[u8], i: usize) -> Result<(u8, &[u8], usize)> {
    let short = || anyhow!("respuesta BER cortada");
    let (tag, n) = (*b.get(i).ok_or_else(short)?, *b.get(i + 1).ok_or_else(short)? as usize);
    let mut i = i + 2;
    let mut n = n;
    if n & 0x80 != 0 {
        let k = n & 0x7F;
        let bytes = b.get(i..i + k).ok_or_else(short)?;
        if k > 8 {
            bail!("longitud BER enorme");
        }
        n = bytes.iter().fold(0usize, |a, x| (a << 8) | *x as usize);
        i += k;
    }
    Ok((tag, b.get(i..i + n).ok_or_else(short)?, i + n))
}

pub fn oid_str(v: &[u8]) -> String {
    let Some(&first) = v.first() else { return String::new() };
    let mut p = vec![(first / 40) as u64, (first % 40) as u64];
    let mut x = 0u64;
    for &c in &v[1..] {
        x = (x << 7) | (c & 0x7F) as u64;
        if c & 0x80 == 0 {
            p.push(x);
            x = 0;
        }
    }
    p.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(".")
}

/// Un valor SNMP. Str es un OCTET STRING: se usa como texto, y guarda los bytes tal cual (MAC, IP en binario, capacidades).
#[derive(Clone, Debug, PartialEq)]
pub enum SV {
    Null,
    Int(i128),
    Str(String, Vec<u8>),
    Oid(String),
}

impl SV {
    pub fn int(&self) -> Option<i128> {
        if let SV::Int(n) = self { Some(*n) } else { None }
    }
    /// `str(v)` de Python.
    pub fn text(&self) -> String {
        match self {
            SV::Null => "None".into(),
            SV::Int(n) => n.to_string(),
            SV::Str(s, _) | SV::Oid(s) => s.clone(),
        }
    }
    /// `str(v or "")`: lo vacío (None, 0, "") como "".
    pub fn txt(&self) -> String {
        if self.truthy() { self.text() } else { String::new() }
    }
    pub fn truthy(&self) -> bool {
        match self {
            SV::Null => false,
            SV::Int(n) => *n != 0,
            SV::Str(s, _) | SV::Oid(s) => !s.is_empty(),
        }
    }
    /// Los bytes de un OCTET STRING (o el texto en latin-1, como `raw()` en Python).
    pub fn raw(&self) -> Vec<u8> {
        match self {
            SV::Str(_, r) => r.clone(),
            SV::Oid(s) => s.chars().map(|c| if (c as u32) < 256 { c as u8 } else { b'?' }).collect(),
            _ => vec![],
        }
    }
    /// `v or 0` para cuentas.
    pub fn num(&self) -> i128 {
        self.int().unwrap_or(0)
    }
}

fn be_int(v: &[u8], signed: bool) -> Option<i128> {
    if v.len() > 16 {
        return None;
    }
    let neg = signed && v.first().is_some_and(|b| b & 0x80 != 0);
    let mut buf = [if neg { 0xFF } else { 0 }; 16];
    buf[16 - v.len()..].copy_from_slice(v);
    Some(i128::from_be_bytes(buf))
}

pub fn ber_val(tag: u8, v: &[u8]) -> SV {
    match tag {
        2 => be_int(v, true).map_or(SV::Null, SV::Int),
        0x41 | 0x42 | 0x43 | 0x46 => be_int(v, false).map_or(SV::Null, SV::Int), // Counter32, Gauge32, TimeTicks, Counter64
        4 => SV::Str(String::from_utf8_lossy(v).into_owned(), v.to_vec()),
        6 => SV::Oid(oid_str(v)),
        0x40 => SV::Oid(v.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(".")),
        _ => SV::Null, // NULL, noSuchObject, noSuchInstance, endOfMibView
    }
}

pub type VarBinds = Vec<(String, u8, SV)>;

fn varbinds(oids: &[&str]) -> Result<Vec<u8>> {
    let mut out = vec![];
    for o in oids {
        out.extend(tlv(0x30, &[ber_oid(o)?, vec![5, 0]].concat()));
    }
    Ok(out)
}

pub fn snmp_msg(community: &str, pdu: u8, rid: i64, oids: &[&str], a: i128, b: i128) -> Result<Vec<u8>> {
    let body = [ber_int(rid as i128, 2), ber_int(a, 2), ber_int(b, 2), tlv(0x30, &varbinds(oids)?)].concat();
    Ok(tlv(0x30, &[ber_int(1, 2), tlv(4, community.as_bytes()), tlv(pdu, &body)].concat()))
}

pub fn snmp_parse(data: &[u8]) -> Result<(i64, i128, VarBinds)> {
    let (_, msg, _) = ber_read(data, 0)?;
    let (_, _, i) = ber_read(msg, 0)?; // versión
    let (_, _, i) = ber_read(msg, i)?; // comunidad
    let (_, pdu, _) = ber_read(msg, i)?;
    pdu_parse(pdu)
}

pub fn pdu_parse(pdu: &[u8]) -> Result<(i64, i128, VarBinds)> {
    let (_, rid, j) = ber_read(pdu, 0)?;
    let (_, err, j) = ber_read(pdu, j)?;
    let (_, _, j) = ber_read(pdu, j)?;
    let (_, vbl, _) = ber_read(pdu, j)?;
    let mut out = vec![];
    let mut k = 0;
    while k < vbl.len() {
        let (_, vb, nk) = ber_read(vbl, k)?;
        k = nk;
        let (_, o, m) = ber_read(vb, 0)?;
        let (t, v, _) = ber_read(vb, m)?;
        out.push((oid_str(o), t, ber_val(t, v)));
    }
    Ok((be_int(rid, true).unwrap_or(0) as i64, be_int(err, false).unwrap_or(0), out))
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// `bytes.replace(old, new, 1)`
fn replace1(hay: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
    match find(hay, old) {
        Some(i) => [&hay[..i], new, &hay[i + old.len()..]].concat(),
        None => hay.to_vec(),
    }
}

fn usm_err(why: &str) -> Option<&'static str> {
    Some(match why {
        "1" => "el equipo no admite ese nivel de seguridad: revisa autenticación y cifrado",
        "3" => "usuario SNMPv3 desconocido en el equipo",
        "5" => "la firma no coincide: revisa la contraseña y el algoritmo de autenticación",
        "6" => "no se pudo descifrar: revisa la contraseña y el algoritmo de cifrado",
        _ => return None,
    })
}

#[derive(Clone, Default)]
pub struct V3 {
    pub user: String,
    pub auth: String,
    pub pass: String,
    pub privp: String,
    pub priv_pass: String,
}

pub struct Snmp {
    host: String,
    port: u16,
    c: String,
    t: Duration,
    pub rid: i64,
    v3: Option<V3>,
    pub eng: Option<Vec<u8>>,
    pub boots: i64,
    pub etime: i64,
    pub at: Instant,
    pub ka: Vec<u8>,
    pub kp: Vec<u8>,
    pub lvl: u8,
}

type Parsed = (i64, u8, i128, VarBinds);

impl Snmp {
    /// Sin v3 habla v2c con la comunidad.
    pub fn new(host: &str, community: &str, port: u16, timeout: f64, v3: Option<V3>) -> Snmp {
        let r = rand_bytes(4);
        let lvl = match &v3 {
            Some(v) if v.auth == "none" => 0,
            Some(v) if v.privp == "none" => 1,
            Some(_) => 3, // bits: 1 firma, 2 cifra
            None => 0,
        };
        Snmp {
            host: host.into(),
            port,
            c: community.into(),
            t: Duration::from_secs_f64(timeout),
            rid: 1 + (u32::from_be_bytes([r[0], r[1], r[2], r[3]]) >> 2) as i64,
            v3,
            eng: None,
            boots: 0,
            etime: 0,
            at: Instant::now(),
            ka: vec![],
            kp: vec![],
            lvl,
        }
    }

    fn ask(&mut self, pdu: u8, oids: &[&str], b: i128) -> Result<VarBinds> {
        let addr = (self.host.as_str(), self.port).to_socket_addrs()?.next().ok_or_else(|| anyhow!("el nombre no resuelve"))?;
        let s = UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })?;
        s.set_read_timeout(Some(self.t))?;
        s.connect(addr)?; // solo llegan respuestas de ese equipo y ese puerto
        let (_, err, vbs) = if self.v3.is_none() {
            self.rid += 1;
            let msg = snmp_msg(&self.c, pdu, self.rid, oids, 0, b)?;
            self.xchg(&s, &msg, |_, d| snmp_parse(d).ok().map(|(rid, err, vbs)| (rid, 0xA2, err, vbs)))?
        } else {
            let mut got = None;
            for _ in 0..3 {
                // descubrir el equipo y, si su reloj ha cambiado, resincronizar
                if self.eng.is_none() {
                    let m = self.v3_msg(0xA0, &[], 0, true)?;
                    self.xchg(&s, &m, |me, d| me.v3_parse(d))?;
                }
                let m = self.v3_msg(pdu, oids, b, false)?;
                let (tag, err, vbs) = self.xchg(&s, &m, |me, d| me.v3_parse(d))?;
                if tag != 0xA8 {
                    got = Some((tag, err, vbs));
                    break;
                }
                let oid = vbs.first().map(|v| v.0.clone()).unwrap_or_default();
                let parts: Vec<&str> = oid.split('.').collect();
                let why = if parts.len() >= 2 { parts[parts.len() - 2] } else { "" }; // informe vacío: sin motivo
                if !oid.starts_with("1.3.6.1.6.3.15.1.1.") || !["2", "4"].contains(&why) {
                    // 2 reloj, 4 engineID
                    bail!("{}", usm_err(why).map(String::from).unwrap_or_else(|| format!("el equipo rechazó la petición SNMPv3 ({})", if oid.is_empty() { "sin detalle" } else { &oid })));
                }
            }
            got.ok_or_else(|| anyhow!("no se pudo sincronizar con el reloj SNMPv3 del equipo"))?
        };
        if err != 0 {
            bail!("el equipo respondió con error SNMP {err}");
        }
        Ok(vbs)
    }

    fn xchg(&mut self, s: &UdpSocket, msg: &[u8], parse: impl Fn(&mut Snmp, &[u8]) -> Option<Parsed>) -> Result<(u8, i128, VarBinds)> {
        let rid = self.rid;
        let mut buf = vec![0u8; 65535];
        for _ in 0..2 {
            // un reintento: UDP pierde paquetes
            s.send(msg)?;
            loop {
                match s.recv(&mut buf) {
                    Ok(n) => {
                        if let Some(r) = parse(self, &buf[..n]) {
                            if r.0 == rid {
                                return Ok((r.1, r.2, r.3));
                            }
                        }
                    }
                    // tiempo agotado, o el «puerto cerrado» (ICMP) que Windows y Linux devuelven así
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused) => {
                        break;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
        let v3 = self.v3.is_some();
        bail!("sin respuesta SNMP: revisa la IP, {} y que SNMP{} esté activado en el equipo", if v3 { "el usuario" } else { "la comunidad" }, if v3 { " v3" } else { "" })
    }

    pub fn v3_msg(&mut self, pdu: u8, oids: &[&str], b: i128, discover: bool) -> Result<Vec<u8>> {
        self.rid += 1;
        let v = self.v3.clone().unwrap_or_default();
        let lvl = if discover { 0 } else { self.lvl };
        let eng = if discover { vec![] } else { self.eng.clone().unwrap_or_default() };
        let (boots, et) = if discover { (0, 0) } else { (self.boots, self.etime + self.at.elapsed().as_secs() as i64) };
        let mut body = tlv(0x30, &[tlv(4, &eng), tlv(4, b""), tlv(pdu, &[ber_int(self.rid as i128, 2), ber_int(0, 2), ber_int(b, 2), tlv(0x30, &varbinds(oids)?)].concat())].concat());
        let salt = if lvl & 2 != 0 { rand_bytes(8) } else { vec![] };
        if lvl & 2 != 0 {
            let iv = [&(boots as u32).to_be_bytes()[..], &(et as u32).to_be_bytes(), &salt].concat();
            body = tlv(4, &aes_cfb(&self.kp, &iv, &body, true));
        }
        // hueco de la firma, se rellena al final
        let mark = if lvl & 1 != 0 { rand_bytes(auth_len(&v.auth).unwrap_or(12)) } else { vec![] };
        let user = if discover { vec![] } else { v.user.as_bytes().to_vec() };
        let sec = tlv(0x30, &[tlv(4, &eng), ber_int(boots as i128, 2), ber_int(et as i128, 2), tlv(4, &user), tlv(4, &mark), tlv(4, &salt)].concat());
        let head = tlv(0x30, &[ber_int(self.rid as i128, 2), ber_int(65507, 2), tlv(4, &[lvl | 4]), ber_int(3, 2)].concat());
        let msg = tlv(0x30, &[ber_int(3, 2), head, tlv(4, &sec), body].concat());
        if mark.is_empty() {
            return Ok(msg);
        }
        let sig = self.sign(&replace1(&msg, &mark, &vec![0; mark.len()]));
        Ok(replace1(&msg, &mark, &sig))
    }

    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let auth = self.v3.as_ref().map(|v| v.auth.as_str()).unwrap_or("sha");
        let mut h = hmac(auth, &self.ka, msg);
        h.truncate(auth_len(auth).unwrap_or(12));
        h
    }

    pub fn v3_parse(&mut self, data: &[u8]) -> Option<Parsed> {
        let (_, m, _) = ber_read(data, 0).ok()?;
        let (_, ver, i) = ber_read(m, 0).ok()?;
        if ver != [3] {
            return None;
        }
        let (_, g, i) = ber_read(m, i).ok()?;
        let (_, sp, i) = ber_read(m, i).ok()?;
        let (t, body, _) = ber_read(m, i).ok()?;
        let (_, mid, k) = ber_read(g, 0).ok()?;
        let (_, _, k) = ber_read(g, k).ok()?;
        let (_, flags, _) = ber_read(g, k).ok()?;
        let flags = *flags.first()?;
        let (_, sq, _) = ber_read(sp, 0).ok()?;
        let mut f = vec![];
        let mut k = 0;
        while k < sq.len() {
            let (_, x, nk) = ber_read(sq, k).ok()?;
            f.push(x);
            k = nk;
        }
        if f.len() != 6 {
            return None;
        }
        let (eng, mac, salt) = (f[0].to_vec(), f[4], f[5]);
        let boots = be_int(f[1], false)? as i64;
        let et = be_int(f[2], false)? as i64;
        if flags & 1 != 0 {
            // respuesta firmada: comprobar que la firma es buena
            if self.eng.is_none() || !ct_eq(mac, &self.sign(&replace1(data, mac, &vec![0; mac.len()]))) {
                return None;
            }
        }
        let plain;
        let body = if flags & 2 != 0 {
            let iv = [&(boots as u32).to_be_bytes()[..], &(et as u32).to_be_bytes(), salt].concat();
            if self.kp.len() != 16 || iv.len() != 16 {
                return None;
            }
            plain = aes_cfb(&self.kp, &iv, body, false);
            ber_read(&plain, 0).ok()?.1
        } else if t != 0x30 {
            return None;
        } else {
            body
        };
        let (_, _, k) = ber_read(body, 0).ok()?; // contextEngineID
        let (_, _, k) = ber_read(body, k).ok()?; // contextName
        let (tag, pdu, _) = ber_read(body, k).ok()?;
        if tag != 0xA8 && (flags & 3) != self.lvl {
            return None; // solo los informes van sin firma; una respuesta sin ella es falsa
        }
        if tag == 0xA8 {
            // informe: el equipo nos dice su engineID y su reloj
            let v = self.v3.clone().unwrap_or_default();
            if self.eng.as_ref() != Some(&eng) && v.auth != "none" {
                self.ka = usm_key(&v.auth, &v.pass, &eng);
                self.kp = if self.lvl & 2 != 0 { usm_key(&v.auth, &v.priv_pass, &eng)[..16].to_vec() } else { vec![] };
            }
            self.eng = Some(eng);
            self.boots = boots;
            self.etime = et;
            self.at = Instant::now();
        }
        let (_, err, vbs) = pdu_parse(pdu).ok()?;
        Some((be_int(mid, true)? as i64, tag, err, vbs))
    }

    pub fn get(&mut self, oids: &[&str]) -> Result<IndexMap<String, SV>> {
        Ok(self.ask(0xA0, oids, 0)?.into_iter().map(|(o, t, v)| (o, if (0x80..=0x82).contains(&t) { SV::Null } else { v })).collect())
    }

    /// Un GET de un solo OID.
    pub fn get1(&mut self, oid: &str) -> Result<SV> {
        Ok(self.get(&[oid])?.swap_remove(oid).unwrap_or(SV::Null))
    }

    pub fn table(&mut self, base: &str) -> Result<IndexMap<String, IndexMap<String, SV>>> {
        let mut rows: IndexMap<String, IndexMap<String, SV>> = IndexMap::new();
        for (k, v) in self.walk(base)? {
            let (col, idx) = k.split_once('.').unwrap_or((&k, ""));
            rows.entry(idx.to_string()).or_default().insert(col.to_string(), v);
        }
        Ok(rows)
    }
}

/// Recorrer una rama: {sufijo del OID: valor}. Rasgo aparte para probar las interfaces sin red.
pub trait Walk {
    fn walk(&mut self, base: &str) -> Result<IndexMap<String, SV>>;
}

impl Walk for Snmp {
    fn walk(&mut self, base: &str) -> Result<IndexMap<String, SV>> {
        let mut out = IndexMap::new();
        let mut cur = base.to_string();
        let prefix = format!("{base}.");
        while out.len() < 5000 {
            let vbs = self.ask(0xA5, &[&cur], 25)?;
            if vbs.is_empty() {
                return Ok(out);
            }
            for (o, t, v) in vbs {
                if t == 0x82 || !o.starts_with(&prefix) || o == cur {
                    return Ok(out);
                }
                out.insert(o[prefix.len()..].to_string(), v);
                cur = o;
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{hex, unhex};

    #[test]
    fn get_request_byte_a_byte() {
        assert_eq!(hex(&snmp_msg("public", 0xA0, 1, &["1.3.6.1.2.1.1.1.0"], 0, 0).unwrap()), "302602010104067075626c6963a019020101020100020100300e300c06082b060102010101000500");
        assert_eq!(oid_str(&ber_oid("1.3.6.1.4.1.14988.1").unwrap()[2..]), "1.3.6.1.4.1.14988.1"); // arcos grandes
        assert_eq!(hex(&ber_int(128, 2)), "02020080");
        assert_eq!(hex(&ber_int(-1, 2)), "0201ff");
        assert_eq!(ber_val(2, &[0xff]), SV::Int(-1));
    }

    #[test]
    fn v3_solo_vale_una_respuesta_con_la_misma_seguridad() {
        let e = unhex("000000000000000000000002").unwrap();
        let v3 = V3 { user: "lector".into(), auth: "sha".into(), pass: "clave-larga".into(), privp: "aes".into(), priv_pass: "otra-clave".into() };
        let mut s = Snmp::new("127.0.0.1", "", 161, 2.0, Some(v3));
        s.eng = Some(e.clone());
        s.boots = 1;
        s.etime = 100;
        s.ka = usm_key("sha", "clave-larga", &e);
        s.kp = usm_key("sha", "otra-clave", &e)[..16].to_vec();
        let ok = s.v3_msg(0xA2, &["1.3.6.1.2.1.1.5.0"], 0, false).unwrap();
        assert_eq!(s.v3_parse(&ok), Some((s.rid, 0xA2, 0, vec![("1.3.6.1.2.1.1.5.0".into(), 5, SV::Null)])));
        let mut bad = ok.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(s.v3_parse(&bad), None); // un bit cambiado: la firma ya no vale
        for lvl in [0, 1] {
            // respuesta falsa sin firma, o firmada pero sin cifrar
            s.lvl = lvl;
            let forged = s.v3_msg(0xA2, &["1.3.6.1.2.1.1.5.0"], 0, false).unwrap();
            s.lvl = 3;
            assert_eq!(s.v3_parse(&forged), None, "{lvl}");
        }
    }
}
