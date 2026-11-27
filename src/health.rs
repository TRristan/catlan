//! Salud: qué leer de cada fabricante por SNMP, interfaces, auto-topología, grabadores Hikvision, Kitty y descubrimiento de red.
use crate::snmp::{SV, Snmp, V3, Walk};
use crate::util::{J, Row, bad, fmt_g, lock, now, round, trunc};
use crate::{db::q, p, re};
use anyhow::{Result, bail};
use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeDelta, Utc};
use indexmap::IndexMap;
use serde_json::{Map, Value, json};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{LazyLock, Mutex};

/// Una lectura: (clave, etiqueta, valor, unidad).
pub type M = (String, String, f64, String);

fn m(k: impl Into<String>, label: impl Into<String>, v: f64, unit: &str) -> M {
    (k.into(), label.into(), v, unit.into())
}

pub fn metrics_json(out: &[M]) -> Value {
    Value::Array(out.iter().map(|(k, l, v, u)| json!([k, l, v, u])).collect())
}

pub fn sv_json(v: &SV) -> Value {
    match v {
        SV::Null => Value::Null,
        SV::Int(n) => i64::try_from(*n).map(Value::from).unwrap_or_else(|_| json!(*n as f64)),
        SV::Str(s, _) | SV::Oid(s) => Value::String(s.clone()),
    }
}

static NULL_SV: SV = SV::Null;
fn g<'a>(r: &'a IndexMap<String, SV>, k: &str) -> &'a SV {
    r.get(k).unwrap_or(&NULL_SV)
}

/// Un número de un valor SNMP (los hay que llegan como texto).
fn fl(v: &SV) -> Option<f64> {
    match v {
        SV::Int(n) => Some(*n as f64),
        SV::Str(s, _) => s.trim().parse().ok(),
        _ => None,
    }
}

/// El primer número de un texto: "48 C" -> 48.
pub fn num(v: &str) -> Option<f64> {
    re!(r"-?\d+(?:[.,]\d+)?").find(v).and_then(|m| m.as_str().replace(',', ".").parse().ok())
}

/// QNAP da tamaños como texto: "1.80 TB"
fn size_bytes(v: &str) -> Option<f64> {
    let c = re!(r"(?i)([\d.,]+)\s*([KMGTP]?)B").captures(v)?;
    let n: f64 = c[1].replace(',', ".").parse().ok()?;
    Some(n * 1024f64.powi("_KMGTP".find(c[2].to_uppercase().chars().next().unwrap_or('_')).unwrap_or(0) as i32))
}

/// HOST-RESOURCES-MIB: CPU, memoria y discos de cualquier equipo con net-snmp (NAS, Linux, MikroTik, UniFi…).
fn host_resources(s: &mut Snmp, out: &mut Vec<M>) -> Result<()> {
    for r in s.table("1.3.6.1.2.1.25.2.3.1")?.values() {
        let (size, used, name) = (g(r, "5").num(), g(r, "6").num(), g(r, "3").txt());
        let unit = if g(r, "4").truthy() { g(r, "4").num() } else { 1 };
        if size == 0 {
            continue;
        }
        let typ = g(r, "2").text();
        if typ == "1.3.6.1.2.1.25.2.1.2" {
            out.push(m("mem", "Memoria", 100.0 * used as f64 / size as f64, "%"));
        } else if typ == "1.3.6.1.2.1.25.2.1.4" && size * unit >= 1 << 30 && !["/dev", "/run", "/sys", "/proc", "/boot", "/tmp"].iter().any(|p| name.starts_with(p)) {
            out.push(m(format!("disk:{name}"), name.clone(), 100.0 * used as f64 / size as f64, "%"));
        }
    }
    let loads: Vec<i128> = s.walk("1.3.6.1.2.1.25.3.3.1.2")?.values().filter_map(SV::int).collect();
    if !loads.is_empty() {
        out.push(m("cpu", "CPU", loads.iter().sum::<i128>() as f64 / loads.len() as f64, "%"));
    }
    Ok(())
}

/// ENTITY-SENSOR-MIB: sensores de temperatura de switches modernos (Cisco, Aruba CX, HPE…).
fn entity_temps(s: &mut Snmp, out: &mut Vec<M>) -> Result<()> {
    let types = s.walk("1.3.6.1.2.1.99.1.1.1.1")?;
    if !types.values().any(|t| *t == SV::Int(8)) {
        return Ok(());
    }
    let (prec, val, names) = (s.walk("1.3.6.1.2.1.99.1.1.1.3")?, s.walk("1.3.6.1.2.1.99.1.1.1.4")?, s.walk("1.3.6.1.2.1.47.1.1.1.1.7")?);
    for (i, t) in &types {
        if let (SV::Int(8), Some(v)) = (t, g(&val, i).int()) {
            let name = names.get(i).map(SV::txt).filter(|s| !s.is_empty()).unwrap_or_else(|| format!("Sensor {i}"));
            out.push(m(format!("temp:{name}"), name, v as f64 / 10f64.powi(g(&prec, i).num() as i32), "°C"));
        }
    }
    Ok(())
}

fn p_synology(s: &mut Snmp, out: &mut Vec<M>, probs: &mut Vec<String>) -> Result<()> {
    host_resources(s, out)?;
    let b = "1.3.6.1.4.1.6574.";
    let oids: Vec<String> = ["1.1.0", "1.2.0", "1.3.0", "1.4.1.0", "1.4.2.0"].iter().map(|o| format!("{b}{o}")).collect();
    let gv = s.get(&oids.iter().map(String::as_str).collect::<Vec<_>>())?;
    if let Some(t) = fl(g(&gv, &oids[1])) {
        out.push(m("temp:sistema", "Sistema", t, "°C"));
    }
    for (o, msg) in
        [(&oids[0], "Estado del sistema: fallo"), (&oids[2], "Fuente de alimentación con fallo"), (&oids[3], "Ventilador del sistema con fallo"), (&oids[4], "Ventilador de la CPU con fallo")]
    {
        if *g(&gv, o) == SV::Int(2) {
            probs.push(msg.into());
        }
    }
    for d in s.table(&format!("{b}2.1.1"))?.values() {
        let name = Some(g(d, "2").txt()).filter(|s| !s.is_empty()).unwrap_or("Disco".into());
        if let Some(t) = g(d, "6").int() {
            out.push(m(format!("temp:{name}"), name.clone(), t as f64, "°C"));
        }
        match g(d, "5").int() {
            Some(4) => probs.push(format!("{name}: partición del sistema dañada")),
            Some(5) => probs.push(format!("{name}: disco dañado")),
            _ => {}
        }
    }
    for r in s.table(&format!("{b}3.1.1"))?.values() {
        let name = Some(g(r, "2").txt()).filter(|s| !s.is_empty()).unwrap_or("Volumen".into());
        match g(r, "3").int() {
            Some(11) => probs.push(format!("{name}: degradado")),
            Some(12) => probs.push(format!("{name}: caído")),
            _ => {}
        }
    }
    Ok(())
}

fn p_qnap(s: &mut Snmp, out: &mut Vec<M>, probs: &mut Vec<String>) -> Result<()> {
    host_resources(s, out)?;
    let b = "1.3.6.1.4.1.24681.1.2.";
    let (o5, o6) = (format!("{b}5.0"), format!("{b}6.0"));
    let gv = s.get(&[&o5, &o6])?;
    for (o, key, label) in [(&o5, "temp:cpu", "CPU"), (&o6, "temp:sistema", "Sistema")] {
        if let Some(v) = num(&g(&gv, o).txt()) {
            out.push(m(key, label, v, "°C"));
        }
    }
    for d in s.table(&format!("{b}11.1"))?.values() {
        let name = Some(g(d, "2").txt()).filter(|s| !s.is_empty()).unwrap_or("Disco".into());
        if let Some(v) = num(&g(d, "3").txt()) {
            out.push(m(format!("temp:{name}"), name.clone(), v, "°C"));
        }
        let smart = g(d, "7").txt().trim().to_uppercase();
        if !smart.is_empty() && !["GOOD", "NORMAL", "--"].contains(&smart.as_str()) {
            probs.push(format!("{name}: SMART {}", smart.to_lowercase()));
        }
    }
    for v in s.table(&format!("{b}17.1"))?.values() {
        let name = Some(g(v, "2").txt()).filter(|s| !s.is_empty()).unwrap_or("Volumen".into());
        if let Some(tot) = size_bytes(&g(v, "4").txt()).filter(|t| *t != 0.0) {
            let free = size_bytes(&g(v, "5").txt()).unwrap_or(0.0);
            out.push(m(format!("disk:{name}"), name.clone(), 100.0 * (tot - free) / tot, "%"));
        }
        let st = g(v, "6").txt();
        if re!(r"(?i)degrad|error|fail|crash").is_match(&st) {
            probs.push(format!("{name}: {st}"));
        }
    }
    Ok(())
}

fn env_state(v: &SV) -> Option<&'static str> {
    Some(match v.int()? {
        2 => "en aviso",
        3 => "crítico",
        4 => "apagado",
        6 => "averiado",
        _ => return None,
    })
}

fn p_cisco(s: &mut Snmp, out: &mut Vec<M>, probs: &mut Vec<String>) -> Result<()> {
    let b = "1.3.6.1.4.1.9.9.";
    if let Some(c) = s.walk(&format!("{b}109.1.1.1.1.8"))?.values().find_map(SV::int) {
        out.push(m("cpu", "CPU", c as f64, "%")); // cpmCPUTotal5minRev
    }
    for r in s.table(&format!("{b}48.1.1.1"))?.values() {
        // ciscoMemoryPool
        let (used, free) = (g(r, "5").num(), g(r, "6").num());
        if g(r, "2").text().to_lowercase().starts_with("processor") && used + free != 0 {
            out.push(m("mem", "Memoria", 100.0 * used as f64 / (used + free) as f64, "%"));
        }
    }
    let temps = s.table(&format!("{b}13.1.3.1"))?;
    for t in temps.values() {
        let name = Some(g(t, "2").txt()).filter(|s| !s.is_empty()).unwrap_or("Temperatura".into());
        if let Some(v) = g(t, "3").int() {
            out.push(m(format!("temp:{name}"), name.clone(), v as f64, "°C"));
        }
        if let Some(st) = env_state(g(t, "6")) {
            probs.push(format!("{name}: {st}"));
        }
    }
    for (base, what) in [(format!("{b}13.1.4.1"), "Ventilador"), (format!("{b}13.1.5.1"), "Fuente")] {
        for f in s.table(&base)?.values() {
            if let Some(st) = env_state(g(f, "3")) {
                let name = Some(g(f, "2").txt()).filter(|s| !s.is_empty()).unwrap_or(what.into());
                probs.push(format!("{name}: {st}"));
            }
        }
    }
    if temps.is_empty() {
        entity_temps(s, out)?;
    }
    Ok(())
}

fn p_hp(s: &mut Snmp, out: &mut Vec<M>, probs: &mut Vec<String>) -> Result<()> {
    let b = "1.3.6.1.4.1.11.2.14.11.";
    if let Some(c) = s.get1(&format!("{b}5.1.9.6.1.0"))?.int() {
        out.push(m("cpu", "CPU", c as f64, "%"));
    }
    for r in s.table(&format!("{b}5.1.1.2.1.1.1"))?.values() {
        // hpLocalMem: total (5) y en uso (7)
        if g(r, "5").truthy() {
            out.push(m("mem", "Memoria", 100.0 * g(r, "7").num() as f64 / g(r, "5").num() as f64, "%"));
            break;
        }
    }
    for r in s.table(&format!("{b}1.2.6.1"))?.values() {
        // hpicfSensor: 2 mal, 3 aviso
        let name = Some(g(r, "7").txt()).filter(|s| !s.is_empty()).unwrap_or("Sensor".into());
        match g(r, "4").int() {
            Some(2) => probs.push(format!("{name}: fallo")),
            Some(3) => probs.push(format!("{name}: en aviso")),
            _ => {}
        }
    }
    entity_temps(s, out)
}

fn p_ubiquiti(s: &mut Snmp, out: &mut Vec<M>, probs: &mut Vec<String>) -> Result<()> {
    host_resources(s, out)?;
    let b = "1.3.6.1.4.1.4413.1.1.43.1."; // EdgeSwitch / UniFi Switch (FASTPATH)
    for (i, t) in s.table(&format!("{b}8.1"))? {
        if let Some(v) = g(&t, "5").int() {
            out.push(m(format!("temp:sensor {i}"), format!("Sensor {i}"), v as f64, "°C"));
        }
    }
    for (i, f) in s.table(&format!("{b}6.1"))? {
        if *g(&f, "3") == SV::Int(3) {
            probs.push(format!("Ventilador {i}: fallo"));
        }
        if let Some(v) = g(&f, "4").int() {
            out.push(m(format!("fan:{i}"), format!("Ventilador {i}"), v as f64, "rpm"));
        }
    }
    if !out.iter().any(|x| x.0.starts_with("temp:")) {
        entity_temps(s, out)?;
    }
    Ok(())
}

fn p_mikrotik(s: &mut Snmp, out: &mut Vec<M>, _probs: &mut Vec<String>) -> Result<()> {
    host_resources(s, out)?;
    let b = "1.3.6.1.4.1.14988.1.1.3.";
    let gauges = s.table(&format!("{b}100.1"))?; // RouterOS 7: nombre (2), valor (3), unidad (4: 1 °C, 2 rpm)
    for gg in gauges.values() {
        let name = Some(g(gg, "2").txt()).filter(|s| !s.is_empty()).unwrap_or("Sensor".into());
        match (g(gg, "4").int(), g(gg, "3").int()) {
            (Some(1), Some(v)) => out.push(m(format!("temp:{name}"), name, v as f64, "°C")),
            (Some(2), Some(v)) => out.push(m(format!("fan:{name}"), name, v as f64, "rpm")),
            _ => {}
        }
    }
    if gauges.is_empty() {
        // RouterOS 6: décimas de grado
        let (o10, o11) = (format!("{b}10.0"), format!("{b}11.0"));
        let gv = s.get(&[&o10, &o11])?;
        for (o, key, label) in [(&o10, "temp:placa", "Placa"), (&o11, "temp:cpu", "CPU")] {
            if let Some(v) = g(&gv, o).int() {
                out.push(m(key, label, v as f64 / 10.0, "°C"));
            }
        }
    }
    Ok(())
}

pub const PROFILES: &[&str] = &["generic", "synology", "qnap", "cisco", "hp", "ubiquiti", "mikrotik", "hikvision"];

fn profile(kind: &str, s: &mut Snmp, out: &mut Vec<M>, probs: &mut Vec<String>) -> Result<()> {
    match kind {
        "generic" => {
            host_resources(s, out)?;
            entity_temps(s, out)
        }
        "synology" => p_synology(s, out, probs),
        "qnap" => p_qnap(s, out, probs),
        "cisco" => p_cisco(s, out, probs),
        "hp" => p_hp(s, out, probs),
        "ubiquiti" => p_ubiquiti(s, out, probs),
        "mikrotik" => p_mikrotik(s, out, probs),
        other => bail!("tipo de equipo desconocido: {other}"),
    }
}

/// Discos de un grabador Hikvision (ISAPI /ContentMgmt/Storage).
pub fn parse_hik(xml: &[u8]) -> Result<(Vec<M>, Vec<String>)> {
    let text = String::from_utf8_lossy(xml);
    let doc = roxmltree::Document::parse(&text)?;
    let (mut out, mut probs) = (vec![], vec![]);
    for hdd in doc.descendants().filter(|n| n.is_element() && n.tag_name().name() == "hdd") {
        let f: HashMap<&str, String> = hdd.children().filter(|c| c.is_element()).map(|c| (c.tag_name().name(), c.text().unwrap_or("").trim().to_string())).collect();
        let fs = |k: &str| f.get(k).cloned().unwrap_or_default();
        let name = Some(fs("hddName")).filter(|s| !s.is_empty()).unwrap_or_else(|| format!("Disco {}", fs("id")).trim().to_string());
        if let Some(cap) = num(&fs("capacity")).filter(|c| *c != 0.0) {
            out.push(m(format!("disk:{name}"), name.clone(), 100.0 * (cap - num(&fs("freeSpace")).unwrap_or(0.0)) / cap, "%"));
        }
        let status = f.get("status").cloned().unwrap_or("ok".into());
        if !["ok", "idle", "sleeping", "standby"].contains(&status.to_lowercase().as_str()) {
            probs.push(format!("{name}: {status}"));
        }
    }
    if out.is_empty() && probs.is_empty() {
        return bad("el grabador no devolvió discos");
    }
    Ok((out, probs))
}

fn p_hikvision(src: &Row) -> Result<(Vec<M>, Vec<String>)> {
    let url = format!("http://{}/ISAPI/ContentMgmt/Storage", src.s("host"));
    let user = Some(src.s("user")).filter(|s| !s.is_empty()).unwrap_or("admin");
    match crate::monitor::get_with_auth(&url, user, src.s("pass")) {
        Ok(body) => parse_hik(&body),
        Err(crate::monitor::HttpErr::Status(401)) => bad("usuario o contraseña del grabador incorrectos"),
        Err(crate::monitor::HttpErr::Status(c)) => bad(format!("el grabador respondió {c}")),
        Err(crate::monitor::HttpErr::Other(e)) => bad(e),
    }
}

// ── Interfaces (IF-MIB): tráfico, errores y puertos caídos de cualquier equipo con SNMP ──
pub const IF: &[(&str, &str)] = &[
    ("type", "1.3.6.1.2.1.2.2.1.3"),
    ("descr", "1.3.6.1.2.1.2.2.1.2"),
    ("admin", "1.3.6.1.2.1.2.2.1.7"),
    ("oper", "1.3.6.1.2.1.2.2.1.8"),
    ("ierr", "1.3.6.1.2.1.2.2.1.14"),
    ("oerr", "1.3.6.1.2.1.2.2.1.20"),
    ("lspeed", "1.3.6.1.2.1.2.2.1.5"),
    ("name", "1.3.6.1.2.1.31.1.1.1.1"),
    ("alias", "1.3.6.1.2.1.31.1.1.1.18"),
    ("speed", "1.3.6.1.2.1.31.1.1.1.15"),
    ("hin", "1.3.6.1.2.1.31.1.1.1.6"),
    ("hout", "1.3.6.1.2.1.31.1.1.1.10"),
];
const PORT_TYPES: &[i128] = &[6, 23, 62, 69, 71, 117, 161]; // ethernet, PPP (WAN), fast/gigabit, wifi, LAG; fuera loopback, VLAN, túneles

type Counters = HashMap<String, (f64, i128, i128, i128)>;
/// id de la fuente -> {ifIndex: (hora, entrada, salida, errores)}: un contador solo dice algo frente al anterior
pub static IF_PREV: LazyLock<Mutex<HashMap<i64, Counters>>> = LazyLock::new(Default::default);

/// Puertos con su estado y, desde la segunda lectura, Mbps de entrada/salida y errores por minuto.
pub fn interfaces(s: &mut dyn Walk, sid: Option<i64>, out: &mut Vec<M>, probs: &mut Vec<String>) -> Result<Vec<Value>> {
    let mut c: HashMap<&str, IndexMap<String, SV>> = HashMap::new();
    for (k, o) in IF {
        c.insert(k, s.walk(o)?);
    }
    let hc = !c["hin"].is_empty();
    if !hc {
        // sin contadores de 64 bits: los de 32 (dan la vuelta cada ~34 s a 1 Gbps)
        c.insert("hin", s.walk("1.3.6.1.2.1.2.2.1.10")?);
        c.insert("hout", s.walk("1.3.6.1.2.1.2.2.1.16")?);
    }
    let t = now();
    let prev = sid.and_then(|i| lock(&IF_PREV).get(&i).cloned()).unwrap_or_default();
    let (mut nowc, mut ports) = (Counters::new(), vec![]);
    for (i, typ) in &c["type"] {
        if !typ.int().is_some_and(|t| PORT_TYPES.contains(&t)) {
            continue;
        }
        let name = trunc(&Some(g(&c["name"], i).txt()).filter(|s| !s.is_empty()).or(Some(g(&c["descr"], i).txt()).filter(|s| !s.is_empty())).unwrap_or(format!("if{i}")), 60);
        let alias = trunc(&g(&c["alias"], i).txt(), 80);
        let (up, admin) = (*g(&c["oper"], i) == SV::Int(1), *g(&c["admin"], i) == SV::Int(1));
        let speed = if g(&c["speed"], i).truthy() { g(&c["speed"], i).num() } else { g(&c["lspeed"], i).num() / 1_000_000 };
        let mut p = json!({"i": i.parse::<i64>().unwrap_or(0), "name": name, "alias": alias, "up": up, "admin": admin, "speed": speed as i64});
        let rin = c["hin"].get(i).and_then(SV::int);
        let (rout, err) = (g(&c["hout"], i).num(), g(&c["ierr"], i).num() + g(&c["oerr"], i).num());
        if let Some(rin) = rin {
            nowc.insert(i.clone(), (t, rin, rout, err));
        }
        if let (Some(&(pt, pin, pout, perr)), Some(rin)) = (prev.get(i), rin) {
            if t > pt {
                let dt = t - pt;
                // shortcut: con 32 bits solo se corrige una vuelta del contador; para enlaces rápidos hace falta ifHCInOctets (SNMP v2c/v3)
                let d = |a: i128, b: i128| {
                    if a >= b {
                        Some(a - b)
                    } else if hc {
                        None
                    } else {
                        Some(a + (1i128 << 32) - b)
                    }
                }; // None: contador reiniciado
                if let (Some(din), Some(dout)) = (d(rin, pin), d(rout, pout)) {
                    let rx = round(din as f64 * 8.0 / dt / 1e6, 3);
                    let tx = round(dout as f64 * 8.0 / dt / 1e6, 3);
                    let er = round((err - perr).max(0) as f64 / dt * 60.0, 2);
                    p["rx"] = json!(rx);
                    p["tx"] = json!(tx);
                    p["err"] = json!(er);
                    if up {
                        out.push(m(format!("rx:{name}"), format!("{name} ↓"), rx, "Mbps"));
                        out.push(m(format!("tx:{name}"), format!("{name} ↑"), tx, "Mbps"));
                        out.push(m(format!("err:{name}"), name.clone(), er, "/min"));
                    }
                    if er > 10.0 {
                        probs.push(format!("{name}: {} errores/min", fmt_g(er)));
                    }
                    if up && speed != 0 && rx.max(tx) > speed as f64 * 0.9 {
                        probs.push(format!("{name}: al {:.0} % de su capacidad", rx.max(tx) / speed as f64 * 100.0));
                    }
                }
            }
        }
        if !alias.is_empty() && admin && !up {
            probs.push(format!("{name} ({alias}): caído")); // con descripción = puerto importante (uplink, servidor…): caído es noticia
        }
        ports.push(p);
    }
    if let Some(sid) = sid.filter(|s| *s != 0) {
        lock(&IF_PREV).insert(sid, nowc);
    }
    Ok(ports)
}

/// El cliente SNMP (v2c o v3) con las credenciales guardadas de una fuente de Salud.
pub fn snmp_for(src: &Row) -> Result<Snmp> {
    let v3 = if src.t("v3") {
        let gs = |k: &str| src.s(k).to_string();
        let mut v = V3 { user: gs("user"), auth: gs("auth"), pass: gs("pass"), privp: gs("priv"), priv_pass: gs("priv_pass") };
        if v.auth.is_empty() {
            v.auth = "sha".into();
        }
        if v.privp.is_empty() {
            v.privp = "aes".into();
        }
        if v.auth != "none" && v.pass.is_empty() || v.auth != "none" && v.privp != "none" && v.priv_pass.is_empty() {
            return bad("faltan las contraseñas SNMPv3");
        }
        Some(v)
    } else {
        None
    };
    let community = Some(src.s("community")).filter(|s| !s.is_empty()).unwrap_or("public");
    let port = src.i("port").filter(|p| *p != 0).unwrap_or(161) as u16;
    Ok(Snmp::new(src.s("host"), community, port, 2.0, v3))
}

// ── Auto-topología: quién está conectado a qué puerto, leído del switch por LLDP, CDP y su tabla MAC ──
pub const LLDP_REM: &str = "1.0.8802.1.1.2.1.4.1.1";
pub const LLDP_LOC: &str = "1.0.8802.1.1.2.1.3.7.1";
pub const LLDP_MAN: &str = "1.0.8802.1.1.2.1.4.2.1";
pub const CDP: &str = "1.3.6.1.4.1.9.9.23.1.2.1.1";
const FDB_Q: &str = "1.3.6.1.2.1.17.7.1.2.2.1.2";
const FDB_D: &str = "1.3.6.1.2.1.17.4.3.1.2";
pub const BRIDGE_IF: &str = "1.3.6.1.2.1.17.1.4.1.2";
const ARP: &str = "1.3.6.1.2.1.4.22.1.2";
const MAX_MACS: usize = 4; // un puerto con más MAC detrás es un enlace a otro switch o a un AP: no es «un equipo»

fn mac_txt(b: &[u8]) -> Option<String> {
    (b.len() == 6).then(|| b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":"))
}

/// Icono según las capacidades que anuncia el vecino (LLDP: bits desde el más alto; CDP: máscara de 32 bits).
fn caps_icon(bits: &[u8], cdp: bool) -> Option<&'static str> {
    if cdp {
        let n = if bits.len() >= 4 { u32::from_be_bytes([bits[0], bits[1], bits[2], bits[3]]) } else { 0 };
        return if n & 1 != 0 {
            Some("router")
        } else if n & 8 != 0 {
            Some("switch")
        } else if n & 0x80 != 0 {
            Some("phone")
        } else {
            None
        };
    }
    let n = bits.first().copied().unwrap_or(0); // other, repeater, bridge, wlanAP, router, telephone, docsis, station
    [(0x08, "router"), (0x10, "ap"), (0x20, "switch"), (0x04, "phone"), (0x01, "pc")].iter().find(|(b, _)| n & b != 0).map(|x| x.1)
}

/// Orden natural: Gi1/0/2 antes que Gi1/0/10.
fn natural(s: &str) -> Vec<(u128, String)> {
    let mut out = vec![];
    let mut last = 0;
    for mt in re!(r"\d+").find_iter(s) {
        out.push((0, s[last..mt.start()].to_string()));
        out.push((mt.as_str().parse().unwrap_or(u128::MAX), String::new()));
        last = mt.end();
    }
    out.push((0, s[last..].to_string()));
    out
}

/// Vecinos del switch, por puerto: [{port, via: lldp|cdp|mac, name, ip, mac, rport, icon}]. Cada tabla que falte, se salta.
pub fn topology(s: &mut Snmp) -> Vec<Map<String, Value>> {
    fn safe(s: &mut Snmp, base: &str) -> IndexMap<String, SV> {
        s.walk(base).unwrap_or_default()
    }
    fn safe_t(s: &mut Snmp, base: &str) -> IndexMap<String, IndexMap<String, SV>> {
        s.table(base).unwrap_or_default()
    }
    let if_name = IF.iter().find(|x| x.0 == "name").unwrap().1;
    let if_descr = IF.iter().find(|x| x.0 == "descr").unwrap().1;
    let mut names = safe(s, if_name);
    if names.is_empty() {
        names = safe(s, if_descr); // ifIndex -> Gi1/0/1
    }
    let by_name: HashMap<String, String> = names.iter().map(|(k, v)| (v.text(), k.clone())).collect();
    type Found = IndexMap<String, Vec<Map<String, Value>>>;
    let mut found: Found = IndexMap::new();
    let mut seen = HashSet::new();
    fn add(found: &mut Found, seen: &mut HashSet<(String, String)>, ifi: String, n: Value) {
        let key = n["name"].as_str().filter(|s| !s.is_empty()).or(n["mac"].as_str()).unwrap_or("").to_lowercase();
        if seen.insert((ifi.clone(), key)) {
            // el mismo vecino por LLDP y por CDP: una vez
            found.entry(ifi).or_default().push(n.as_object().cloned().unwrap_or_default());
        }
    }
    // LLDP: el puerto local va por su número; casi siempre es el ifIndex, si no, su nombre o descripción
    let loc = safe_t(s, LLDP_LOC);
    let lldp_if = |num: &str| -> String {
        for col in ["3", "4"] {
            let v = loc.get(num).and_then(|r| r.get(col)).map(SV::text).unwrap_or_default();
            if let Some(i) = by_name.get(&v) {
                return i.clone();
            }
        }
        num.to_string()
    };
    let mut ips = HashMap::new();
    for k in safe(s, LLDP_MAN).keys() {
        // índice: col.timeMark.puerto.índice.tipo(1=IPv4).4.a.b.c.d
        let p: Vec<&str> = k.split('.').collect();
        if p.len() >= 10 && p[4] == "1" && p[5] == "4" {
            ips.insert((p[2].to_string(), p[3].to_string()), p[6..10].join("."));
        }
    }
    for (idx, r) in safe_t(s, LLDP_REM) {
        let p: Vec<&str> = idx.split('.').collect();
        if p.len() < 3 {
            continue;
        }
        let chassis = g(&r, "5").raw();
        let name = Some(g(&r, "9").txt().trim().to_string()).filter(|s| !s.is_empty()).or_else(|| mac_txt(&chassis)).unwrap_or_else(|| g(&r, "5").txt());
        let rport = if g(&r, "8").truthy() { g(&r, "8").text() } else { g(&r, "7").txt() };
        add(
            &mut found,
            &mut seen,
            lldp_if(p[1]),
            json!({"via": "lldp", "name": name, "ip": ips.get(&(p[1].to_string(), p[2].to_string())), "mac": mac_txt(&chassis),
                   "rport": rport.trim(), "icon": caps_icon(&g(&r, "12").raw(), false)}),
        );
    }
    // CDP (Cisco): índice ifIndex.n; la dirección llega en 4 bytes
    for (idx, r) in safe_t(s, CDP) {
        let a = g(&r, "4").raw();
        let ip = (a.len() == 4).then(|| a.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("."));
        add(
            &mut found,
            &mut seen,
            idx.split('.').next().unwrap_or("").to_string(),
            json!({"via": "cdp", "name": g(&r, "6").txt().trim(), "ip": ip, "mac": null, "rport": g(&r, "7").txt().trim(),
                   "icon": caps_icon(&g(&r, "9").raw(), true)}),
        );
    }
    // Tabla MAC (Q-BRIDGE con VLAN, o BRIDGE clásica): en los puertos sin vecino LLDP/CDP y con pocas MAC, un equipo por MAC
    let port_if = safe(s, BRIDGE_IF); // puerto del bridge -> ifIndex
    let mut fdb = safe(s, FDB_Q);
    if fdb.is_empty() {
        fdb = safe(s, FDB_D);
    }
    let mut macs: IndexMap<String, BTreeSet<String>> = IndexMap::new();
    for (k, bp) in &fdb {
        let parts: Vec<&str> = k.split('.').collect();
        if parts.len() >= 6 {
            let mac = parts[parts.len() - 6..].iter().map(|x| format!("{:02x}", x.parse::<u64>().unwrap_or(0))).collect::<Vec<_>>().join(":");
            let ifi = port_if.get(&bp.text()).unwrap_or(bp).text();
            macs.entry(ifi).or_default().insert(mac);
        }
    }
    let mut arp = HashMap::new();
    for (k, v) in safe(s, ARP) {
        // índice: ifIndex.a.b.c.d -> MAC en binario
        let p: Vec<&str> = k.split('.').collect();
        if let (5, Some(mac)) = (p.len(), mac_txt(&v.raw())) {
            arp.insert(mac, p[1..].join("."));
        }
    }
    for (ifi, ms) in &macs {
        if found.contains_key(ifi) || !names.contains_key(ifi) || ms.len() > MAX_MACS {
            continue;
        }
        for mac in ms {
            add(&mut found, &mut seen, ifi.clone(), json!({"via": "mac", "name": "", "ip": arp.get(mac), "mac": mac, "rport": "", "icon": null}));
        }
    }
    let port_name = |ifi: &str| names.get(ifi).map(SV::text).unwrap_or_else(|| ifi.to_string());
    let mut keys: Vec<String> = found.keys().cloned().collect();
    keys.sort_by_key(|k| natural(&port_name(k)));
    let mut out = vec![];
    for ifi in keys {
        for n in &found[&ifi] {
            let mut o = Map::new();
            o.insert("port".into(), port_name(&ifi).into());
            o.extend(n.clone());
            out.push(o);
        }
    }
    out
}

const KIND_ICON: &[(&str, &str)] = &[
    ("router", "router"),
    ("switch", "switch"),
    ("firewall", "firewall"),
    ("servidor", "server"),
    ("server", "server"),
    ("nas", "nas"),
    ("port", "laptop"),
    ("impres", "printer"),
    ("printer", "printer"),
    ("tel", "phone"),
    ("cám", "camera"),
    ("cam", "camera"),
    ("sai", "ups"),
    ("ups", "ups"),
    ("ap", "ap"),
    ("wifi", "ap"),
    ("pc", "pc"),
];

/// Lee la topología del switch de una fuente de Salud y la dibuja en un esquema «Topología · switch» (lo rehace si existe).
pub fn auto_map(src: &Row) -> Result<(i64, String, Vec<Map<String, Value>>, bool)> {
    let mut nbrs = topology(&mut snmp_for(src)?);
    let items = q("SELECT id, name, kind, ip FROM items", p![])?;
    let mut by_ip: HashMap<String, &Row> = HashMap::new();
    let mut by_name: HashMap<String, &Row> = HashMap::new();
    for i in items.iter() {
        if !i.s("ip").is_empty() {
            by_ip.insert(i.s("ip").into(), i);
        }
        if !i.s("name").is_empty() {
            by_name.insert(i.s("name").to_lowercase(), i);
        }
    }
    let me = src.i("item").filter(|x| *x != 0).and_then(|id| items.iter().find(|i| i.i("id") == Some(id))).or_else(|| by_ip.get(src.s("host")).copied());
    let title = [src.s("label"), me.map(|m| m.s("name")).unwrap_or(""), src.s("host")].into_iter().find(|s| !s.is_empty()).unwrap_or("").to_string();
    let mut sw = json!({"id": "sw", "t": "switch", "x": 600, "y": 90});
    match me {
        Some(m) => sw["item"] = m["id"].clone(),
        None => sw["label"] = title.clone().into(),
    }
    let (mut nodes, mut links) = (vec![sw], vec![]);
    let per_row = 9.max(nbrs.len().div_ceil(4)); // como mucho 4 filas: el lienzo mide 1200 x 800
    for (k, n) in nbrs.iter_mut().enumerate() {
        let name = n.s("name").to_string();
        let it = by_ip.get(n.s("ip")).or_else(|| by_name.get(&name.to_lowercase())).or_else(|| by_name.get(&name.split('.').next().unwrap_or("").to_lowercase())).copied();
        let kind = it.map(|i| i.s("kind").to_lowercase()).unwrap_or_default();
        let icon = KIND_ICON
            .iter()
            .find(|(w, _)| kind.contains(w))
            .map(|x| x.1.to_string()) // manda el inventario
            .or_else(|| n.get("icon").and_then(|v| v.as_str()).map(String::from))
            .unwrap_or_else(|| if n.s("via") != "mac" { "switch".into() } else { "pc".into() });
        let (row, col) = (k / per_row, k % per_row);
        let mut node = json!({"id": format!("p{k}"), "t": icon,
            "x": (200.0 + (col as f64 + 0.5) * 950.0 / per_row as f64).round_ties_even() as i64,
            "y": 260 + row * 140 + col % 2 * 45}); // en zigzag: los nombres de al lado no se pisan
        match it {
            Some(i) => node["item"] = i["id"].clone(),
            None => {
                let base = [n.s("name"), n.s("ip"), n.s("mac")].into_iter().find(|s| !s.is_empty()).unwrap_or("?").to_string();
                let rport = n.s("rport");
                node["label"] = (if rport.is_empty() { base } else { format!("{base} ({rport})") }).into();
            }
        }
        nodes.push(node);
        n.insert("item".into(), it.map(|i| i["id"].clone()).unwrap_or(Value::Null));
        links.push(json!(["sw", format!("p{k}"), n.s("port")])); // el puerto del switch, en la línea
    }
    let name = trunc(&format!("Topología · {title}"), 200);
    let data = json!({"nodes": nodes, "links": links, "auto": {"source": src["id"], "at": crate::util::local("%Y-%m-%d %H:%M:%S")}});
    if let Some(row) = q("SELECT id FROM maps WHERE name=? AND json_extract(data, '$.auto.source')=?", p![&name, &src["id"]])?.one() {
        let id = row.i("id").unwrap_or(0);
        q("UPDATE maps SET data=?, version=version+1 WHERE id=?", p![data.to_string(), id])?;
        return Ok((id, name, nbrs, false));
    }
    let id = q("INSERT INTO maps(name, mime, image, data) VALUES(?, '', ?, ?)", p![&name, Vec::<u8>::new(), data.to_string()])?.lastrowid;
    Ok((id, name, nbrs, true))
}

/// Lee un equipo y aplica sus umbrales. Devuelve (métricas, problemas, info).
pub fn collect(src: &Row) -> Result<(Vec<M>, Vec<String>, Map<String, Value>)> {
    let mut info = Map::new();
    let (out, mut probs) = if src.s("kind") == "hikvision" {
        p_hikvision(src)?
    } else {
        let mut s = snmp_for(src)?;
        let sys = s.get(&["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0"])?;
        info.insert("descr".into(), sv_json(g(&sys, "1.3.6.1.2.1.1.1.0")));
        info.insert("name".into(), sv_json(g(&sys, "1.3.6.1.2.1.1.5.0")));
        info.insert("uptime".into(), json!((g(&sys, "1.3.6.1.2.1.1.3.0").num() / 100) as i64));
        let (mut out, mut probs) = (vec![], vec![]);
        profile(src.s("kind"), &mut s, &mut out, &mut probs)?;
        // sin tabla de interfaces (o con una rara) se queda lo leído por el perfil
        match interfaces(&mut s, src.i("id"), &mut out, &mut probs) {
            Ok(ports) => {
                info.insert("ports".into(), Value::Array(ports));
            }
            Err(e) => println!("interfaces de {} sin leer: {e}", src.s("host")),
        }
        (out, probs)
    };
    let out = limits(src, out, &mut probs);
    Ok((out, probs, info))
}

/// Redondea las lecturas y añade a probs las que pasan los umbrales del equipo.
pub fn limits(src: &Row, out: Vec<M>, probs: &mut Vec<String>) -> Vec<M> {
    let out: Vec<M> = out.into_iter().map(|(k, l, v, u)| (trunc(&k, 120), trunc(&l, 120), round(v, 2), u)).collect();
    let tmax = src.f("temp_max").filter(|v| *v != 0.0).unwrap_or(65.0);
    let dmax = src.f("disk_max").filter(|v| *v != 0.0).unwrap_or(90.0);
    for (k, label, v, u) in &out {
        if u == "°C" && *v > tmax {
            probs.push(format!("{label}: {} °C (límite {})", fmt_g(*v), fmt_g(tmax)));
        }
        if k.starts_with("disk:") && *v > dmax {
            probs.push(format!("{}: {:.0} % lleno (límite {} %)", label.trim_end_matches(':'), v, fmt_g(dmax))); // «C:» de Windows: sin «C::»
        }
    }
    out
}

pub const KITTY_LOST: &str = "Kitty no responde: el equipo puede estar apagado o sin red";

/// Lo que cuenta Kitty -> (métricas, info), con tipos y tamaños acotados: llega de la red sin sesión.
pub fn kitty_read(name: &str, x: &Value) -> (Vec<M>, Map<String, Value>) {
    let empty = Map::new();
    let x = x.as_object().unwrap_or(&empty);
    let num = |v: Option<&Value>| -> Option<Value> {
        let v = v?;
        let f = v.as_f64()?;
        (v.is_number() && (0.0..9.223372036854776e18).contains(&f)).then(|| v.clone())
    };
    let nf = |v: Option<&Value>| num(v).and_then(|v| v.as_f64());
    let txt = |v: Option<&Value>, n: usize| v.and_then(Value::as_str).map(|s| trunc(s.trim(), n)).unwrap_or_default();
    let disks: Vec<Value> = x
        .get("disks")
        .and_then(Value::as_array)
        .map(|a| a.iter().take(32).filter_map(Value::as_object).map(|d| json!({"name": txt(d.get("name"), 60), "total": num(d.get("total")), "free": num(d.get("free"))})).collect())
        .unwrap_or_default();
    let (mt, mf) = (nf(x.get("mem_total")), nf(x.get("mem_free")));
    let mut out = vec![];
    if let Some(load) = nf(x.get("load")) {
        out.push(m("cpu", "CPU", load.min(100.0), "%"));
    }
    if let (Some(mt), Some(mf)) = (mt, mf) {
        if mt != 0.0 && mf <= mt {
            out.push(m("mem", "Memoria", 100.0 * (mt - mf) / mt, "%"));
        }
    }
    for d in &disks {
        let (name, total, free) = (d.s("name"), d.f("total"), d.f("free"));
        if let (false, Some(t), Some(f)) = (name.is_empty(), total, free) {
            if t != 0.0 && f <= t {
                out.push(m(format!("disk:{name}"), name, 100.0 * (t - f) / t, "%"));
            }
        }
    }
    let ips: Vec<Value> = x.get("ips").and_then(Value::as_array).map(|a| a.iter().take(16).filter_map(Value::as_str).map(|s| Value::from(trunc(s.trim(), 45))).collect()).unwrap_or_default();
    let mut info = Map::new();
    info.insert("descr".into(), txt(x.get("osver"), 200).into());
    info.insert("name".into(), name.into());
    info.insert("uptime".into(), (nf(x.get("uptime")).unwrap_or(0.0) as i64).into());
    info.insert("model".into(), txt(x.get("model"), 200).into());
    info.insert("cpu".into(), txt(x.get("cpu"), 200).into());
    info.insert("cores".into(), (nf(x.get("cores")).unwrap_or(0.0) as i64).into());
    info.insert("mem_total".into(), num(x.get("mem_total")).unwrap_or(Value::Null));
    info.insert("serial".into(), txt(x.get("serial"), 100).into());
    info.insert("ips".into(), ips.into());
    info.insert("disks".into(), disks.into());
    (out, info)
}

/// Fecha ISO 8601 como `datetime.fromisoformat`; sin zona, en UTC.
pub fn parse_iso(s: &str, naive_local: bool) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return Some(t.with_timezone(&Utc));
    }
    for f in ["%Y-%m-%dT%H:%M:%S%.f%:z", "%Y-%m-%d %H:%M:%S%.f%:z", "%Y-%m-%dT%H:%M%:z", "%Y-%m-%d %H:%M%:z"] {
        if let Ok(t) = DateTime::parse_from_str(s, f) {
            return Some(t.with_timezone(&Utc));
        }
    }
    let naive = ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M"]
        .iter()
        .find_map(|f| NaiveDateTime::parse_from_str(s, f).ok())
        .or_else(|| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok().and_then(|d| d.and_hms_opt(0, 0, 0)))?;
    if naive_local { naive.and_local_timezone(chrono::Local).single().map(|t| t.with_timezone(&Utc)) } else { Some(naive.and_utc()) }
}

/// Eventos de Windows que envía Kitty, junto a los ya guardados -> (los de 7 días, máx. 30, el más nuevo primero; avisos).
/// Avisan los críticos de las últimas 24 h (un apagado inesperado, un pantallazo azul): los errores, que Windows tiene muchos, solo se ven.
pub fn kitty_events(new: &Value, prev: &Value) -> (Vec<Value>, Vec<String>) {
    let txt = |v: &Value, n: usize| v.as_str().map(|s| trunc(s.trim(), n)).unwrap_or_default();
    let now = Utc::now();
    let mut seen = HashSet::new();
    let mut out: Vec<(TimeDelta, Value)> = vec![];
    let all = new.as_array().map(|a| &a[..a.len().min(50)]).unwrap_or(&[]).iter().chain(prev.as_array().map(|a| &a[..]).unwrap_or(&[]));
    for e in all {
        let (Some(o), Some(rec)) = (e.as_object(), e.get("rec").filter(|r| crate::util::is_int(r)).and_then(Value::as_i64)) else { continue };
        let Some(level) = o.get("level").filter(|l| crate::util::is_int(l)).and_then(Value::as_i64).filter(|l| *l == 1 || *l == 2) else { continue };
        let Some(t) = parse_iso(&txt(o.get("time").unwrap_or(&Value::Null), 40), false) else { continue };
        let age = now - t;
        let log = txt(o.get("log").unwrap_or(&Value::Null), 40);
        // -10 min: relojes un poco adelantados
        if !(TimeDelta::minutes(-10) < age && age < TimeDelta::days(7)) || !seen.insert((log.clone(), rec)) {
            continue;
        }
        let code = o.get("code").filter(|c| crate::util::is_int(c)).and_then(Value::as_i64).unwrap_or(0);
        out.push((
            age,
            json!({"rec": rec, "log": log, "time": t.format("%Y-%m-%d %H:%M:%S").to_string(), "level": level,
                   "source": txt(o.get("source").unwrap_or(&Value::Null), 100), "code": code, "msg": txt(o.get("msg").unwrap_or(&Value::Null), 400)}),
        ));
    }
    out.sort_by_key(|x| x.0);
    out.truncate(30);
    let probs = out
        .iter()
        .filter(|(age, e)| e["level"] == 1 && *age < TimeDelta::days(1))
        .take(3)
        .map(|(_, e)| {
            let msg = e.s("msg");
            format!("Crítico en el registro: {} {}{}", e.s("source"), e["code"], if msg.is_empty() { String::new() } else { format!(" · {}", trunc(msg, 140)) })
        })
        .collect();
    (out.into_iter().map(|x| x.1).collect(), probs)
}

// ── Descubrimiento: ping a toda una red y, a quien responde, SNMP y DNS inverso ──
fn vendor(n: &str) -> Option<(&'static str, &'static str)> {
    Some(match n {
        "9" => ("Cisco", "switch"),
        "11" => ("HP", "switch"),
        "2636" => ("Juniper", "router"),
        "4413" => ("Ubiquiti", "switch"),
        "41112" => ("Ubiquiti", "ap"),
        "14988" => ("MikroTik", "router"),
        "14823" => ("Aruba", "ap"),
        "25506" => ("H3C", "switch"),
        "6574" => ("Synology", "nas"),
        "24681" => ("QNAP", "nas"),
        "12356" => ("Fortinet", "firewall"),
        "25461" => ("Palo Alto", "firewall"),
        "2604" => ("Sophos", "firewall"),
        "311" => ("Microsoft", "server"),
        "8072" => ("Net-SNMP", "server"),
        "674" => ("Dell", "server"),
        "232" => ("HPE", "server"),
        "6876" => ("VMware", "server"),
        "318" => ("APC", "ups"),
        "534" => ("Eaton", "ups"),
        "2435" => ("Brother", "printer"),
        "367" => ("Ricoh", "printer"),
        "1602" => ("Canon", "printer"),
        "18334" => ("Konica Minolta", "printer"),
        "253" => ("Xerox", "printer"),
        "1347" => ("Kyocera", "printer"),
        "39165" => ("Hikvision", "camera"),
        "1004849" => ("Dahua", "camera"),
        _ => return None,
    })
}

/// Fabricante y tipo probables de un equipo, por su sysObjectID y su sysDescr.
pub fn guess(descr: &str, oid: &str) -> (String, String) {
    let (v, k) = re!(r"^1\.3\.6\.1\.4\.1\.(\d+)").captures(oid).and_then(|c| vendor(&c[1])).unwrap_or(("", ""));
    let words: &[(&str, &regex::Regex)] = &[
        ("printer", re!(r"(?i)printer|laserjet|officejet|mfp|impresora")),
        ("ap", re!(r"(?i)access point|unifi ap|\buap\b|aironet|wireless")),
        ("firewall", re!(r"(?i)firewall|fortigate|pfsense|opnsense|asa\b")),
        ("nas", re!(r"(?i)synology|qnap|\bnas\b|diskstation|readynas")),
        ("ups", re!(r"(?i)\bups\b|smart-ups")),
        ("camera", re!(r"(?i)camera|ipc|nvr|dvr")),
        ("router", re!(r"(?i)router|routeros|edgeos|ios xe")),
        ("switch", re!(r"(?i)switch|catalyst|procurve|aruba")),
        ("server", re!(r"(?i)linux|windows server|esxi|vmware|freebsd")),
    ];
    // la descripción manda: un HP puede ser impresora o switch
    let k = words.iter().find(|(_, rx)| rx.is_match(descr)).map(|x| x.0).unwrap_or(k);
    (v.into(), k.into())
}

fn identify(ip: &str, community: &str) -> Map<String, Value> {
    let mut name = String::new();
    if let Ok(a) = ip.parse::<std::net::IpAddr>() {
        if let Ok(n) = dns_lookup::lookup_addr(&a) {
            if n != ip {
                name = n;
            }
        }
    }
    let mut out = json!({"ip": ip, "name": name, "descr": "", "vendor": "", "kind": "", "snmp": false});
    // un solo intento corto: quien no tiene SNMP no debe frenar el escaneo
    if let Ok(r) = Snmp::new(ip, community, 161, 0.7, None).get(&["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.5.0"]) {
        let descr = trunc(&g(&r, "1.3.6.1.2.1.1.1.0").txt(), 200);
        let (v, k) = guess(&descr, &g(&r, "1.3.6.1.2.1.1.2.0").txt());
        out["snmp"] = true.into();
        if g(&r, "1.3.6.1.2.1.1.5.0").truthy() {
            out["name"] = g(&r, "1.3.6.1.2.1.1.5.0").text().into();
        }
        out["descr"] = descr.into();
        out["vendor"] = v.into();
        out["kind"] = k.into();
    }
    out.as_object().cloned().unwrap_or_default()
}

/// Ping a todas las direcciones y, a quien responde, DNS inverso y SNMP. Marca lo que ya está en el inventario y en el monitor.
pub fn discover(hosts: &[String], community: &str) -> Result<Vec<Value>> {
    let pings = crate::util::par_map(hosts, 64, |h| crate::monitor::ping(h));
    let alive: Vec<(String, Option<f64>)> = hosts.iter().zip(pings).filter(|(_, (up, _))| *up).map(|(h, (_, rtt))| (h.clone(), rtt)).collect();
    let found = crate::util::par_map(&alive, 64, |(h, rtt)| {
        let mut o = identify(h, community);
        o.insert("rtt".into(), json!(rtt));
        o
    });
    let items: HashMap<String, Value> = q("SELECT id, ip FROM items WHERE ip != ''", p![])?.into_iter().map(|r| (r.s("ip").to_string(), r["id"].clone())).collect();
    let watched: HashSet<String> = q("SELECT host FROM checks", p![])?.into_iter().map(|r| r.s("host").to_string()).collect();
    Ok(found
        .into_iter()
        .map(|mut f| {
            let ip = f.s("ip").to_string();
            f.insert("item".into(), items.get(&ip).cloned().unwrap_or(Value::Null));
            f.insert("watched".into(), watched.contains(&ip).into());
            Value::Object(f)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeIf(HashMap<String, IndexMap<String, SV>>);
    impl Walk for FakeIf {
        fn walk(&mut self, oid: &str) -> Result<IndexMap<String, SV>> {
            Ok(self.0.get(oid).cloned().unwrap_or_default())
        }
    }
    fn ifo(k: &str) -> String {
        IF.iter().find(|x| x.0 == k).unwrap().1.to_string()
    }
    fn col(v: &[(&str, SV)]) -> IndexMap<String, SV> {
        v.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }
    fn s(t: &str) -> SV {
        SV::Str(t.into(), t.as_bytes().to_vec())
    }

    #[test]
    fn interfaces_mbps_reinicio_y_vuelta_del_contador() {
        use SV::Int;
        let t0 = now();
        let sw: HashMap<String, IndexMap<String, SV>> = [
            (ifo("type"), col(&[("1", Int(6)), ("2", Int(6)), ("3", Int(24)), ("4", Int(6))])),
            (ifo("name"), col(&[("1", s("Gi1")), ("2", s("Gi2")), ("3", s("lo")), ("4", s("Gi4"))])),
            (ifo("alias"), col(&[("1", s("UPLINK")), ("4", s("SRV"))])),
            (ifo("oper"), col(&[("1", Int(1)), ("2", Int(1)), ("3", Int(1)), ("4", Int(2))])),
            (ifo("admin"), col(&[("1", Int(1)), ("2", Int(1)), ("3", Int(1)), ("4", Int(1))])),
            (ifo("speed"), col(&[("1", Int(1000)), ("2", Int(100)), ("4", Int(1000))])),
            (ifo("hin"), col(&[("1", Int(1_000_000_000_000 + 7_500_000_000)), ("2", Int(100)), ("4", Int(0))])),
            (ifo("hout"), col(&[("1", Int(1_000_000_000_000)), ("2", Int(100)), ("4", Int(0))])),
        ]
        .into_iter()
        .collect();
        lock(&IF_PREV).insert(99, [("1".into(), (t0 - 60.0, 1_000_000_000_000, 1_000_000_000_000, 0)), ("2".into(), (t0 - 60.0, 200, 100, 0))].into_iter().collect()); // Gi2: el contador bajó (reinicio)
        let (mut out, mut probs) = (vec![], vec![]);
        let ports = interfaces(&mut FakeIf(sw), Some(99), &mut out, &mut probs).unwrap();
        assert_eq!(ports.iter().map(|p| p.s("name")).collect::<Vec<_>>(), ["Gi1", "Gi2", "Gi4"]);
        assert!((ports[0]["rx"].as_f64().unwrap() - 1000.0).abs() < 2.0 && ports[0]["tx"] == 0.0, "{ports:?}");
        assert!(ports[1].get("rx").is_none()); // sin dato inventado; Gi4 caído no guarda tráfico
        assert_eq!(out.iter().map(|x| x.0.as_str()).collect::<BTreeSet<_>>(), ["err:Gi1", "rx:Gi1", "tx:Gi1"].into());
        assert_eq!(probs, ["Gi1: al 100 % de su capacidad", "Gi4 (SRV): caído"]);
        lock(&IF_PREV).insert(98, [("1".into(), (t0 - 1.0, (1i128 << 32) - 1000, 0, 0))].into_iter().collect());
        let old: HashMap<String, IndexMap<String, SV>> = [
            (ifo("type"), col(&[("1", Int(6))])),
            (ifo("oper"), col(&[("1", Int(1))])),
            ("1.3.6.1.2.1.2.2.1.10".into(), col(&[("1", Int(1000))])),
            ("1.3.6.1.2.1.2.2.1.16".into(), col(&[("1", Int(0))])),
        ]
        .into_iter()
        .collect();
        let rx = interfaces(&mut FakeIf(old), Some(98), &mut vec![], &mut vec![]).unwrap()[0]["rx"].as_f64().unwrap();
        assert!((rx - 0.016).abs() < 0.002, "{rx}"); // 2000 bytes en ~1 s, pese a la vuelta
    }

    #[test]
    fn grabador_hikvision() {
        let hik = br#"<hddList xmlns="http://www.hikvision.com/ver20/XMLSchema"><hdd><id>1</id><hddName>hdd1</hddName><status>ok</status>
          <capacity>1000</capacity><freeSpace>250</freeSpace></hdd><hdd><id>2</id><hddName>hdd2</hddName><status>error</status>
          <capacity>1000</capacity><freeSpace>1000</freeSpace></hdd></hddList>"#;
        let (out, probs) = parse_hik(hik).unwrap();
        assert_eq!(out, vec![m("disk:hdd1", "hdd1", 75.0, "%"), m("disk:hdd2", "hdd2", 0.0, "%")]);
        assert_eq!(probs, ["hdd2: error"]);
        assert!(parse_hik(b"<hddList/>").is_err() && parse_hik(b"no es xml").is_err());
    }

    #[test]
    fn fabricante_y_tipo() {
        let gs = |d, o| guess(d, o);
        assert_eq!(gs("HP LaserJet Pro M404", "1.3.6.1.4.1.11.2.3.9.1"), ("HP".into(), "printer".into())); // HP: la descripción decide
        assert_eq!(gs("ProCurve J9773A Switch 2530", "1.3.6.1.4.1.11.2.3.7.11.160"), ("HP".into(), "switch".into()));
        assert_eq!(gs("Linux nas 4.4", "1.3.6.1.4.1.6574.1"), ("Synology".into(), "nas".into()));
        assert_eq!(gs("", ""), (String::new(), String::new()));
    }

    #[test]
    fn lecturas_y_umbrales() {
        let src: Row = json!({"temp_max": 65.0, "disk_max": 90}).as_object().unwrap().clone();
        let mut probs = vec![];
        let out = limits(&src, vec![m("temp:Disk 2", "Disk 2", 71.0, "°C"), m("disk:C:", "C:", 95.004, "%")], &mut probs);
        assert_eq!(out[1].2, 95.0);
        assert_eq!(probs, ["Disk 2: 71 °C (límite 65)", "C: 95 % lleno (límite 90 %)"]);
        assert!(natural("Gi1/0/2") < natural("Gi1/0/10"));
        assert_eq!(size_bytes("1.80 TB"), Some(1.8 * 1024f64.powi(4)));
    }
}
