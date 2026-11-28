//! Lo que entra por la API se valida aquí, con los mismos mensajes que la versión en Python.
use crate::db::q;
use crate::monitor::{CHECK_KINDS, NetErr, parse_net};
use crate::util::{J, Row, bad, is_int, truthy};
use crate::{p, re};
use anyhow::Result;
use serde_json::Value;

/// Sin espacios ni guion inicial: no se cuela como opción de ping.
pub fn host_ok(h: &str) -> bool {
    re!(r"^[A-Za-z0-9][A-Za-z0-9.:\-]{0,252}$").is_match(h)
}

pub fn check_pass(pw: &Value) -> Result<()> {
    match pw.as_str() {
        Some(s) if (8..=200).contains(&s.chars().count()) => Ok(()),
        _ => bad("la contraseña necesita al menos 8 caracteres"),
    }
}

fn int_in(v: &Value, lo: i64, hi: i64) -> bool {
    is_int(v) && v.as_i64().is_some_and(|n| (lo..=hi).contains(&n))
}

const RACK_TYPES: &[&str] = &["server", "switch", "patch", "router", "firewall", "nas", "ups", "pdu", "kvm", "tray", "blank", "other"];

/// El frontal pinta estos campos tal cual: solo se aceptan tipos conocidos y números enteros.
pub fn check_rack(d: &Row) -> Result<()> {
    let h = d.get("height").cloned().unwrap_or(42.into());
    let devs = d.get("devices").cloned().unwrap_or(Value::Array(vec![]));
    let ok = int_in(&h, 1, 60)
        && devs.as_array().is_some_and(|a| {
            a.iter().all(|x| {
                x.as_object().is_some_and(|x| {
                    x.get("t").and_then(Value::as_str).is_some_and(|t| RACK_TYPES.contains(&t))
                        && ["u", "h"].iter().all(|k| x.get(*k).is_some_and(is_int))
                        && ["ports", "sfp"].iter().all(|k| x.get(*k).is_none_or(is_int))
                })
            })
        });
    if ok { Ok(()) } else { bad("datos de rack no válidos") }
}

pub fn check_host(d: &Row, new: bool) -> Result<()> {
    if (new || d.contains_key("host")) && !d.get("host").and_then(Value::as_str).is_some_and(host_ok) {
        return bad("host no válido: usa una IP o un nombre (p. ej. 10.0.0.1 o sw-core.local)");
    }
    if d.get("every").is_some_and(|e| !int_in(e, 10, 3600)) {
        return bad("el intervalo va de 10 a 3600 segundos");
    }
    let k = match d.get("kind") {
        None => "ping",
        Some(v) => v.as_str().unwrap_or("\0"),
    };
    if !CHECK_KINDS.contains(&k) {
        return bad("tipo de comprobación desconocido");
    }
    if d.get("port").is_some_and(|p| !p.is_null() && !int_in(p, 1, 65535)) {
        return bad("puerto no válido");
    }
    if d.get("url").is_some_and(truthy) && !d.get("url").and_then(Value::as_str).is_some_and(|u| re!(r"^https?://[^\s/]+\S{0,500}$").is_match(u)) {
        return bad("la URL empieza por http:// o https://");
    }
    if d.get("expect").is_some_and(|e| !e.as_str().is_some_and(|s| s.chars().count() <= 200)) {
        return bad("texto esperado demasiado largo");
    }
    if d.get("warn_days").is_some_and(|w| !int_in(w, 1, 365)) {
        return bad("avisar de 1 a 365 días antes");
    }
    if d.contains_key("kind") && (k == "tcp" && !d.t("port") || k == "http" && !d.t("url")) {
        return bad(if k == "tcp" { "falta el puerto" } else { "falta la URL" });
    }
    // sonido al caer: "" = el general de cada navegador, "none" = ninguno, uno de los de catlan o uno subido (u:id)
    if d.get("sound").is_some_and(|s| !s.as_str().is_some_and(|s| re!(r"^(|none|bell|beep|siren|meow|u:\d{1,9})$").is_match(s))) {
        return bad("sonido no válido");
    }
    Ok(())
}

pub const AUTHS: &[&str] = &["none", "md5", "sha", "sha224", "sha256", "sha384", "sha512"];

pub fn check_source(d: &Row, new: bool) -> Result<()> {
    let mut h = Row::new();
    if new || d.contains_key("host") {
        h.insert("host".into(), d.get("host").cloned().unwrap_or(Value::Null));
    }
    check_host(&h, new)?; // el intervalo se valida aquí, con otro rango
    if (new || d.contains_key("kind")) && !crate::health::PROFILES.contains(&d.get("kind").map_or(Some("generic"), Value::as_str).unwrap_or("\0")) {
        return bad("tipo de equipo desconocido");
    }
    if d.get("port").is_some_and(|p| !int_in(p, 1, 65535)) {
        return bad("puerto no válido");
    }
    if d.get("every").is_some_and(|e| !int_in(e, 60, 86400)) {
        return bad("el intervalo va de 60 segundos a 1 día");
    }
    for k in ["temp_max", "disk_max"] {
        if d.get(k).is_some_and(|v| !v.as_f64().is_some_and(|f| f > 0.0 && f <= 200.0)) {
            return bad("los umbrales deben ser números entre 1 y 200");
        }
    }
    for k in ["community", "user", "pass", "label", "priv_pass"] {
        if d.get(k).is_some_and(|v| !v.as_str().is_some_and(|s| s.chars().count() <= 200)) {
            return bad(format!("{k} no válido"));
        }
    }
    // True/False también valen: son 1/0
    if d.get("v3").is_some_and(|v| !(v.is_boolean() || v.as_f64().is_some_and(|f| f == 0.0 || f == 1.0))) {
        return bad("v3 no válido");
    }
    if d.get("auth").is_some_and(|a| !a.as_str().is_some_and(|a| AUTHS.contains(&a))) || d.get("priv").is_some_and(|a| !a.as_str().is_some_and(|a| a == "none" || a == "aes")) {
        return bad("algoritmo SNMPv3 no admitido");
    }
    if d.t("v3") {
        if d.contains_key("user") && !d.t("user") {
            return bad("SNMPv3 necesita un usuario");
        }
        if d.s("auth") == "none" && d.get("priv").map_or("none", |p| p.as_str().unwrap_or("")) != "none" {
            return bad("para cifrar, SNMPv3 exige también autenticación");
        }
        if ["pass", "priv_pass"].iter().any(|k| d.t(k) && d.s(k).chars().count() < 8) {
            return bad("las contraseñas SNMPv3 tienen al menos 8 caracteres");
        }
    }
    Ok(())
}

fn date_ok(s: &str) -> bool {
    chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok()
}

/// Fin de garantía: vacío o una fecha AAAA-MM-DD de verdad (el aviso compara textos).
pub fn check_item(d: &Row) -> Result<()> {
    match d.get("warranty") {
        None => Ok(()),
        Some(Value::String(w)) if w.is_empty() || date_ok(w) => Ok(()),
        Some(Value::String(_)) => bad("fecha de garantía no válida: AAAA-MM-DD"),
        Some(_) => bad("fecha de garantía no válida"),
    }
}

pub const EXPIRY_KINDS: &[&str] = &["licencia", "dominio", "certificado", "contrato", "soporte", "otro"];

/// Licencias, dominios, contratos…: con nombre, tipo conocido y una fecha AAAA-MM-DD de verdad.
pub fn check_expiry(d: &Row, new: bool) -> Result<()> {
    if (new || d.contains_key("name")) && !d.get("name").and_then(Value::as_str).is_some_and(|n| (1..=200).contains(&n.trim().chars().count())) {
        return bad("ponle un nombre (hasta 200 caracteres)");
    }
    if d.get("kind").is_some_and(|k| !k.as_str().is_some_and(|k| EXPIRY_KINDS.contains(&k))) {
        return bad(format!("tipo no válido: {}", EXPIRY_KINDS.join(", ")));
    }
    if (new || d.contains_key("date")) && !d.get("date").and_then(Value::as_str).is_some_and(date_ok) {
        return bad("fecha no válida: AAAA-MM-DD");
    }
    if d.get("item").is_some_and(|i| !i.is_null() && !is_int(i)) {
        return bad("equipo no válido");
    }
    if d.get("notes").is_some_and(|n| !n.as_str().is_some_and(|s| s.chars().count() <= 5000)) {
        return bad("notas no válidas");
    }
    Ok(())
}

/// Un programa para los PCs: su id de winget (va como argumento de winget.exe, sin shell) y un nombre.
pub fn check_script(d: &Row, new: bool) -> Result<()> {
    if (new || d.contains_key("name")) && !d.get("name").and_then(Value::as_str).is_some_and(|n| (1..=100).contains(&n.trim().chars().count())) {
        return bad("el nombre va de 1 a 100 caracteres");
    }
    if (new || d.contains_key("body")) && !d.get("body").and_then(Value::as_str).is_some_and(|b| (1..=100_000).contains(&b.trim().len())) {
        return bad("el script va de 1 a 100.000 caracteres");
    }
    if d.get("notes").is_some_and(|n| !n.as_str().is_some_and(|s| s.chars().count() <= 2000)) {
        return bad("notas no válidas");
    }
    Ok(())
}

/// Un interruptor guardado como 0 o 1 (true/false también valen).
pub fn check_flag(d: &Row, k: &str) -> Result<()> {
    match d.get(k) {
        None | Some(Value::Bool(_)) => Ok(()),
        Some(v) if v.as_i64().is_some_and(|n| n == 0 || n == 1) => Ok(()),
        _ => bad(format!("{k}: true o false")),
    }
}

pub fn check_app(d: &Row, new: bool) -> Result<()> {
    if (new || d.contains_key("winget")) && !d.get("winget").and_then(Value::as_str).is_some_and(|w| re!(r"^[A-Za-z0-9][A-Za-z0-9.+_\-]{1,127}$").is_match(w)) {
        return bad("id de winget no válido: algo como Google.Chrome o 7zip.7zip");
    }
    if (new || d.contains_key("name")) && !d.get("name").and_then(Value::as_str).is_some_and(|n| (1..=100).contains(&n.trim().chars().count())) {
        return bad("el nombre va de 1 a 100 caracteres");
    }
    if d.get("notes").is_some_and(|n| !n.as_str().is_some_and(|s| s.chars().count() <= 2000)) {
        return bad("notas no válidas");
    }
    Ok(())
}

/// IPv4 de /16 a /30; se guarda normalizada (10.0.0.7/24 -> 10.0.0.0/24).
pub fn check_subnet(d: &mut Row, new: bool) -> Result<()> {
    if new || d.contains_key("cidr") {
        let s = match d.get("cidr") {
            Some(Value::String(s)) => s.trim().to_string(),
            Some(v) => crate::util::py_str(v),
            None => String::new(),
        };
        match parse_net(&s) {
            Ok(n) if (16..=30).contains(&n.prefix) => {
                d.insert("cidr".into(), n.to_string().into());
            }
            Ok(_) | Err(NetErr::V6) => return bad("solo redes IPv4 de /16 a /30"),
            Err(NetErr::Bad) => return bad("red no válida: escribe algo como 10.0.0.0/24"),
        }
    }
    for k in ["name", "vlan", "notes"] {
        if d.get(k).is_some_and(|v| !v.as_str().is_some_and(|s| s.chars().count() <= 2000)) {
            return bad(format!("{k} no válido"));
        }
    }
    Ok(())
}

pub const INC_STATUS: &[&str] = &["abierta", "en curso", "en espera", "resuelta", "cerrada"];
pub const INC_PRIO: &[&str] = &["baja", "media", "alta", "crítica"];

pub fn check_incident(d: &Row, rid: Option<i64>) -> Result<()> {
    if d.get("title").is_some_and(|t| !t.as_str().is_some_and(|t| (1..=200).contains(&t.trim().chars().count()))) {
        return bad("el título va de 1 a 200 caracteres");
    }
    if d.get("body").is_some_and(|b| !b.as_str().is_some_and(|b| b.chars().count() <= 20000)) {
        return bad("descripción demasiado larga");
    }
    if d.get("status").is_some_and(|s| !s.as_str().is_some_and(|s| INC_STATUS.contains(&s))) || d.get("priority").is_some_and(|s| !s.as_str().is_some_and(|s| INC_PRIO.contains(&s))) {
        return bad("estado o prioridad no válidos");
    }
    for (k, table, what) in [("assignee", "users", "la persona"), ("grp", "groups", "el grupo"), ("item", "items", "el equipo"), ("parent", "incidents", "la incidencia padre")] {
        if let Some(v) = d.get(k).filter(|v| !v.is_null())
            && (!is_int(v) || q(&format!("SELECT 1 FROM {table} WHERE id=?"), p![v])?.is_empty())
        {
            return bad(format!("{what} no existe"));
        }
    }
    // subiendo por los padres no se puede llegar a ella misma: sería un círculo
    let mut par = d.i("parent");
    while let (Some(rid), Some(pid)) = (rid, par) {
        if pid == rid {
            return bad("una incidencia no puede colgar de sí misma ni de una de sus hijas");
        }
        par = crate::db::val("SELECT parent FROM incidents WHERE id=?", p![pid])?.as_i64();
    }
    Ok(())
}

const DASH_KIND: &[&str] = &["stat", "inv", "mon", "lat", "health", "log", "map"];
const DASH_VIEW: &[&str] = &["line", "bar", "pie"];
const DASH_BY: &[&str] = &["kind", "status", "location"];
const DASH_GROUP: &[&str] = &["temp", "disk", "load", "fan", "net"];
const DASH_STAT: &[&str] = &["items", "pages", "maps", "racks", "down", "warn"];
const DASH_HOURS: &[i64] = &[6, 24, 168, 720, 2160];

/// El frontal pinta estos campos: solo tipos conocidos y posiciones enteras dentro de la rejilla de 12 columnas.
pub fn check_dash(d: &Value) -> Result<()> {
    let ws = d.as_object().filter(|o| o.keys().all(|k| k == "widgets")).and_then(|o| o.get("widgets")).and_then(Value::as_array);
    let Some(ws) = ws.filter(|w| w.len() <= 60) else { return bad("dashboard no válido") };
    let mut ids = std::collections::HashSet::new();
    for w in ws {
        let id = w.get("id").and_then(Value::as_str).unwrap_or("");
        let Some(w) = w.as_object().filter(|_| re!(r"^[a-z0-9]{1,20}$").is_match(id) && ids.insert(id.to_string())) else {
            return bad("widget sin id válido");
        };
        for (k, v) in w {
            let opt = |list: &[&str]| v.as_str().is_some_and(|s| list.contains(&s));
            let ok = match k.as_str() {
                "id" => true,
                "title" => v.as_str().is_some_and(|t| t.chars().count() <= 80),
                "x" => int_in(v, 0, 11),
                "y" => int_in(v, 0, 500),
                "w" => int_in(v, 1, 12),
                "h" => int_in(v, 1, 8),
                "source" | "map" => int_in(v, 1, 1 << 31),
                "kind" => opt(DASH_KIND),
                "view" => opt(DASH_VIEW),
                "by" => opt(DASH_BY),
                "group" => opt(DASH_GROUP),
                "stat" => opt(DASH_STAT),
                "hours" => is_int(v) && v.as_i64().is_some_and(|h| DASH_HOURS.contains(&h)),
                _ => false,
            };
            if !ok {
                return bad(format!("widget {id}: {k} no válido"));
            }
        }
        if !w.contains_key("kind") || ["x", "y", "w", "h"].iter().any(|k| !w.contains_key(*k)) || w.i("x").unwrap_or(0) + w.i("w").unwrap_or(0) > 12 {
            return bad(format!("widget {id}: fuera de la rejilla"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn o(v: Value) -> Row {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn hosts_que_no_se_cuelan_en_ping() {
        for bad in ["-c 9 x", "a;rm", "", "x'; calc #"] {
            assert!(!host_ok(bad), "{bad}");
        }
        assert!(host_ok("10.0.0.1") && host_ok("sw-core.local") && host_ok("127.0.0.1:18099"));
        assert!(check_host(&o(json!({"host": "10.0.0.1", "every": 1})), true).is_err());
        assert!(check_host(&o(json!({"kind": "tcp", "host": "x"})), true).is_err());
        assert!(check_host(&o(json!({"kind": "http", "host": "x", "url": "javascript:alert(1)"})), true).is_err());
        assert!(check_host(&o(json!({"host": "x", "sound": "u:12"})), true).is_ok());
    }

    #[test]
    fn dashboards() {
        let w0 = json!({"id": "a1", "kind": "inv", "by": "status", "view": "pie", "x": 0, "y": 0, "w": 4, "h": 3, "title": "Estado"});
        assert!(check_dash(&json!({"widgets": [w0]})).is_ok());
        for (k, v) in [("id", json!("<img src=x>")), ("x", json!(10)), ("kind", json!("iframe")), ("onclick", json!("x")), ("w", json!(true)), ("hours", json!(7))] {
            let mut w = w0.clone();
            w[k] = v;
            assert!(check_dash(&json!({"widgets": [w]})).is_err(), "{k}");
        }
        assert!(check_dash(&json!({"widgets": [w0, w0]})).is_err());
    }
}
