//! Control remoto con Kitty. catlan hace de relevo entre la web del técnico y la Kitty del PC, que solo sale hacia catlan
//! (en el PC no se abre ningún puerto). El usuario del PC acepta cada sesión y la puede cortar cuando quiera.
//! Las sesiones viven en memoria; en el historial del equipo (Actividad) queda quién se conectó, cuándo y cuánto.
use crate::db::q;
use crate::p;
use crate::util::J;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant};

pub struct Sess {
    pub agent: i64,
    pub item: Value,
    pub pc: String,
    pub tech: i64,
    pub who: String,
    pub state: &'static str, // pedida → aceptada → cerrada, o rechazada
    pub why: String,
    frame: Vec<u8>,
    seq: u64,
    input: Vec<Value>,
    asked: Instant,
    started: Option<Instant>,
    agent_seen: Instant,
    tech_seen: Instant,
    ended: Option<Instant>,
}

static SESS: LazyLock<Mutex<HashMap<String, Sess>>> = LazyLock::new(Default::default);
/// Cambia con cada novedad (una petición, un fotograma, ratón o teclado, el final): despierta a los WebSockets, que
/// miran entonces si va con su sesión.
pub static CHANGED: LazyLock<tokio::sync::watch::Sender<u64>> = LazyLock::new(|| tokio::sync::watch::channel(0).0);

fn changed() {
    CHANGED.send_modify(|v| *v = v.wrapping_add(1));
}

/// Sin respuesta del usuario del PC en este tiempo, se da por rechazada.
const ASK: Duration = Duration::from_secs(60);
/// Si Kitty o la web dejan de dar señales este tiempo, la sesión se corta.
const LOST: Duration = Duration::from_secs(20);

fn sessions() -> MutexGuard<'static, HashMap<String, Sess>> {
    SESS.lock().unwrap_or_else(|e| e.into_inner())
}

/// En el historial del equipo, como lo demás que le pasa.
fn log(who: &str, action: &str, s: &Sess, data: Value) {
    if cfg!(test) {
        return; // las pruebas unitarias no tienen base de datos
    }
    let _ = q("INSERT INTO log(who, action, kind, ref, name, data) VALUES(?, ?, 'item', ?, ?, ?)", p![who, action, &s.item, s.pc.as_str(), data.to_string()]);
}

fn end(s: &mut Sess, state: &'static str, why: &str, who: &str) {
    if s.ended.is_some() {
        return;
    }
    let mins = s.started.map(|t| t.elapsed().as_secs().div_ceil(60));
    s.state = state;
    s.why = why.into();
    s.ended = Some(Instant::now());
    s.input.clear();
    s.frame.clear();
    let action = if state == "rechazada" { "control remoto rechazado" } else { "control remoto terminado" };
    log(who, action, s, json!({"técnico": s.who, "motivo": why, "minutos": mins}));
    changed();
}

/// Cierra lo que se ha quedado sin respuesta y olvida lo terminado hace rato.
fn sweep(m: &mut HashMap<String, Sess>) {
    for s in m.values_mut() {
        match s.state {
            "pedida" if s.asked.elapsed() > ASK => end(s, "rechazada", "nadie respondió en el PC", "catlan"),
            "pedida" if s.tech_seen.elapsed() > LOST => end(s, "cerrada", "el técnico se fue antes de que respondieran", "catlan"),
            "aceptada" if s.agent_seen.elapsed() > LOST => end(s, "cerrada", "se perdió la conexión con el PC", "catlan"),
            "aceptada" if s.tech_seen.elapsed() > LOST => end(s, "cerrada", "se perdió la conexión con el técnico", "catlan"),
            _ => {}
        }
    }
    m.retain(|_, s| s.ended.is_none_or(|t| t.elapsed() < Duration::from_secs(300)));
}

fn status(s: &Sess) -> Value {
    json!({"state": s.state, "why": s.why, "pc": s.pc, "who": s.who, "seq": s.seq, "secs": s.started.map(|t| t.elapsed().as_secs())})
}

// ── Lo que pide la web del técnico ──

/// Pedir conectarse a un equipo: una sesión a la vez por PC.
pub fn ask(agent: &crate::util::Row, tech: i64, who: &str) -> Result<(String, Value), String> {
    let mut m = sessions();
    sweep(&mut m);
    let id_agent = agent.i("id").unwrap_or(0);
    if !online(id_agent) {
        return Err(format!("Kitty no está abierto en {} (o es una versión sin control remoto): el usuario tiene que tener el gato en la bandeja", agent.s("name")));
    }
    if let Some(o) = m.values().find(|s| s.agent == id_agent && s.ended.is_none()) {
        return Err(format!("{} ya tiene una sesión abierta con {}", o.pc, o.who));
    }
    let now = Instant::now();
    let s = Sess {
        agent: id_agent,
        item: agent.get("item").cloned().unwrap_or(Value::Null),
        pc: agent.s("name").to_string(),
        tech,
        who: who.into(),
        state: "pedida",
        why: String::new(),
        frame: vec![],
        seq: 0,
        input: vec![],
        asked: now,
        started: None,
        agent_seen: now,
        tech_seen: now,
        ended: None,
    };
    log(who, "pedir control remoto", &s, json!({}));
    let id = crate::crypto::token_urlsafe(18);
    let st = status(&s);
    m.insert(id.clone(), s);
    changed();
    Ok((id, st))
}

/// La sesión, solo para quien la pidió. None: no existe o no es suya.
fn mine<'a>(m: &'a mut HashMap<String, Sess>, id: &str, tech: i64) -> Option<&'a mut Sess> {
    m.get_mut(id).filter(|s| s.tech == tech)
}

pub fn get(id: &str, tech: i64) -> Option<Value> {
    let mut m = sessions();
    sweep(&mut m);
    let s = mine(&mut m, id, tech)?;
    s.tech_seen = Instant::now();
    Some(status(s))
}

/// (número y JPEG del fotograma, si hay uno nuevo; estado de la sesión)
pub type Frame = (Option<(u64, Vec<u8>)>, Value);

/// El fotograma si hay uno después de `after`, y el estado. No espera: el WebSocket vuelve a mirar con cada novedad.
pub fn frame(id: &str, tech: i64, after: u64) -> Option<Frame> {
    let mut m = sessions();
    sweep(&mut m);
    let s = mine(&mut m, id, tech)?;
    s.tech_seen = Instant::now();
    let f = (s.seq > after && !s.frame.is_empty()).then(|| (s.seq, s.frame.clone()));
    Some((f, status(s)))
}

/// Ya terminada (cerrada o rechazada).
pub fn ended(st: &Value) -> bool {
    matches!(st["state"].as_str(), Some("cerrada" | "rechazada"))
}

/// Ratón y teclado del técnico, para que Kitty los recoja con el siguiente fotograma.
pub fn input(id: &str, tech: i64, evs: Vec<Value>) -> Option<Value> {
    let mut m = sessions();
    sweep(&mut m);
    let s = mine(&mut m, id, tech)?;
    s.tech_seen = Instant::now();
    if s.state == "aceptada" && s.input.len() < 2000 {
        s.input.extend(evs);
        changed();
    }
    Some(status(s))
}

pub fn stop(id: &str, tech: i64, who: &str) -> Option<Value> {
    let mut m = sessions();
    let s = mine(&mut m, id, tech)?;
    let state = if s.state == "pedida" { "rechazada" } else { "cerrada" };
    end(s, state, &format!("la terminó {who}"), who);
    Some(status(s))
}

// ── Lo que pide Kitty ──

/// Las Kitty abiertas que saben de control remoto: cuándo preguntaron por última vez.
static ONLINE: LazyLock<Mutex<HashMap<i64, Instant>>> = LazyLock::new(Default::default);
/// Kitty pregunta cada pocos segundos; tras este tiempo sin preguntar, se da por cerrada.
const POLL: Duration = Duration::from_secs(30);

pub fn online(agent: i64) -> bool {
    crate::util::lock(&ONLINE).get(&agent).is_some_and(|t| t.elapsed() < POLL)
}

/// ¿Quiere IT conectarse a este PC? Responde al momento: Kitty pregunta cada pocos segundos, sin dejar una conexión
/// abierta por PC (con miles de PCs se llenaría el servidor).
pub fn pending(agent: i64) -> Value {
    crate::util::lock(&ONLINE).insert(agent, Instant::now());
    let mut m = sessions();
    sweep(&mut m);
    m.iter().find(|(_, s)| s.agent == agent && s.state == "pedida").map_or(json!({}), |(id, s)| json!({"id": id, "who": s.who}))
}

/// El usuario del PC acepta, rechaza o corta.
pub fn answer(agent: i64, id: &str, ok: bool) -> Option<Value> {
    let mut m = sessions();
    sweep(&mut m);
    let s = m.get_mut(id).filter(|s| s.agent == agent)?;
    let who = format!("Kitty · {}", s.pc);
    match (s.state, ok) {
        ("pedida", true) => {
            s.state = "aceptada";
            s.started = Some(Instant::now());
            s.agent_seen = Instant::now();
            log(&who, "control remoto aceptado", s, json!({"técnico": s.who}));
            changed();
        }
        ("pedida", false) => end(s, "rechazada", "el usuario del PC no lo permitió", &who),
        ("aceptada", false) => end(s, "cerrada", "la cortó el usuario del PC", &who),
        _ => {}
    }
    Some(status(s))
}

/// Un fotograma (vacío: la pantalla no ha cambiado) y, de vuelta, lo que ha hecho el técnico desde el anterior.
/// None en `jpeg`: Kitty no ha enviado nada, solo se recoge lo del técnico (no cuenta como señal de vida).
pub fn push(agent: i64, id: &str, jpeg: Option<Vec<u8>>) -> Option<Value> {
    let mut m = sessions();
    sweep(&mut m);
    let s = m.get_mut(id).filter(|s| s.agent == agent)?;
    if s.state != "aceptada" {
        return Some(json!({"state": s.state, "why": s.why}));
    }
    let Some(jpeg) = jpeg else { return Some(json!({"state": s.state, "input": std::mem::take(&mut s.input)})) };
    s.agent_seen = Instant::now();
    if !jpeg.is_empty() {
        s.frame = jpeg;
        s.seq += 1;
        changed();
    }
    Some(json!({"state": s.state, "input": std::mem::take(&mut s.input)}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: i64) -> crate::util::Row {
        let mut r = crate::util::Row::new();
        r.insert("id".into(), id.into());
        r.insert("name".into(), "PC-PRUEBA".into());
        r
    }

    #[test]
    fn flujo_completo() {
        assert!(ask(&row(990_001), 7, "ana").is_err()); // Kitty no ha preguntado nunca: no está abierto
        assert_eq!(pending(990_001), json!({}));
        let (id, st) = ask(&row(990_001), 7, "ana").unwrap();
        assert_eq!(st["state"], "pedida");
        assert!(ask(&row(990_001), 8, "luis").is_err()); // una a la vez por PC
        assert_eq!(pending(990_001)["id"], id.as_str());
        assert!(get(&id, 8).is_none()); // solo quien la pidió
        assert!(input(&id, 7, vec![json!({"t": "m"})]).is_some());
        assert_eq!(answer(990_001, &id, true).unwrap()["state"], "aceptada");
        input(&id, 7, vec![json!({"t": "m", "x": 0.5, "y": 0.5})]);
        let r = push(990_001, &id, Some(vec![0xFF, 0xD8, 1])).unwrap();
        assert_eq!(r["input"].as_array().unwrap().len(), 1); // lo de antes de aceptar no cuenta
        let (f, _) = frame(&id, 7, 0).unwrap();
        assert_eq!(f.unwrap().0, 1);
        assert!(frame(&id, 7, 1).unwrap().0.is_none()); // ya lo tiene: no se repite
        input(&id, 7, vec![json!({"t": "k"})]);
        assert_eq!(push(990_001, &id, None).unwrap()["input"].as_array().unwrap().len(), 1); // lo del técnico, sin esperar a un fotograma
        assert_eq!(answer(990_001, &id, false).unwrap()["state"], "cerrada");
        assert_eq!(push(990_001, &id, Some(vec![1])).unwrap()["state"], "cerrada");
        assert!(ask(&row(990_001), 8, "luis").is_ok()); // ya se puede otra
    }
}
