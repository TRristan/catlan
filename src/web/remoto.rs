//! Control remoto. El técnico pide la sesión por HTTP y la ve por un WebSocket (pantalla de ida, ratón y teclado de
//! vuelta). Kitty pregunta por HTTP si hay alguna pedida y, aceptada, abre su propio WebSocket para la pantalla.
//! Las Kitty de antes del WebSocket siguen enviando cada fotograma por HTTP (/api/agent/remote/frame).
use super::kitty::{agent_by_ukey, ukey};
use super::{Ctx, Future, H, Perm, Route, Ws, err, js, out, r};
use crate::db::q;
use crate::p;
use crate::remote;
use crate::server::Resp;
use crate::util::{J, bad};
use anyhow::Result;
use axum::extract::ws::{Message, WebSocket};
use serde_json::{Value, json};
use std::time::Duration;

pub fn routes() -> Vec<Route> {
    vec![
        r("POST", "/api/remote", Perm::User, Ctx::remote_ask),
        r("GET", "/api/remote/{id}", Perm::User, Ctx::remote_get),
        r("DELETE", "/api/remote/{id}", Perm::User, Ctx::remote_stop),
        Route { method: "GET", path: "/api/remote/{id}/ws", perm: Perm::User, h: H::Ws(tech_ws) },
        // lo de Kitty: con la clave de incidencias (la ventana de Kitty corre como el usuario del PC y no puede leer la del equipo)
        r("POST", "/api/agent/remote", Perm::Free, Ctx::agent_pending),
        r("POST", "/api/agent/remote/answer", Perm::Free, Ctx::agent_answer),
        r("POST", "/api/agent/remote/frame", Perm::Free, Ctx::agent_frame),
        Route { method: "GET", path: "/api/agent/remote/ws", perm: Perm::Free, h: H::Ws(kitty_ws) },
    ]
}

/// Un fotograma de Kitty: vacío (la pantalla no ha cambiado) o un JPEG de hasta 8 MB.
fn frame_ok(jpg: &[u8]) -> bool {
    jpg.is_empty() || jpg.starts_with(&[0xFF, 0xD8]) && jpg.len() <= 8 << 20
}

/// Ratón y teclado del técnico: hasta 500 eventos de golpe, cada uno con su tipo.
fn events(b: &[u8]) -> Result<Vec<Value>> {
    if b.len() > 64 * 1024 {
        return bad("demasiados eventos de golpe");
    }
    let v: Value = serde_json::from_slice(b)?;
    match v.as_array().filter(|a| a.len() <= 500 && a.iter().all(|e| e.get("t").is_some_and(Value::is_string))) {
        Some(a) => Ok(a.clone()),
        None => bad("eventos no válidos"),
    }
}

impl Ctx {
    /// Pedir el control remoto de un equipo. Cada sesión es solo de quien la pidió; el usuario del PC tiene que aceptarla.
    fn remote_ask(&mut self) -> Result<Resp> {
        let b = self.body()?;
        let Some(aid) = b.get("agent").and_then(Value::as_i64) else { return bad("¿a qué equipo?") };
        let Some(a) = q("SELECT * FROM agents WHERE id=?", p![aid])?.one() else { return Ok(err(404, "ese Kitty no existe")) };
        if a.s("state") != "adoptado" {
            return bad("este Kitty aún no está aceptado en catlan");
        }
        Ok(match remote::ask(&a, self.uid(), &self.user) {
            Ok((id, st)) => js(201, json!({"id": id, "status": st})),
            Err(e) => err(409, &e),
        })
    }

    fn remote_get(&mut self) -> Result<Resp> {
        Ok(remote::get(self.param("id").unwrap_or(""), self.uid()).map_or_else(gone, |v| js(200, v)))
    }

    fn remote_stop(&mut self) -> Result<Resp> {
        Ok(remote::stop(self.param("id").unwrap_or(""), self.uid(), &self.user).map_or_else(gone, |v| js(200, v)))
    }

    /// ¿Quiere IT conectarse a este PC?
    fn agent_pending(&mut self) -> Result<Resp> {
        let b = self.body()?;
        Ok(match agent_by_ukey(ukey(&b))? {
            Ok(a) => js(200, remote::pending(a.i("id").unwrap_or(0))),
            Err(r) => r,
        })
    }

    /// El usuario del PC acepta, rechaza o corta.
    fn agent_answer(&mut self) -> Result<Resp> {
        let b = self.body()?;
        let a = match agent_by_ukey(ukey(&b))? {
            Ok(a) => a,
            Err(r) => return Ok(r),
        };
        let id = b.get("id").and_then(Value::as_str).unwrap_or("");
        let ok = b.get("ok").and_then(Value::as_bool).unwrap_or(false);
        Ok(remote::answer(a.i("id").unwrap_or(0), id, ok).map_or_else(|| err(404, "no existe"), |v| js(200, v)))
    }

    /// Kitty de antes del WebSocket: un fotograma por petición. El cuerpo es el JPEG: la clave y la sesión van en cabeceras.
    fn agent_frame(&mut self) -> Result<Resp> {
        let a = match agent_by_ukey(self.req.header("x-kitty"))? {
            Ok(a) => a,
            Err(r) => return Ok(r),
        };
        let jpg = self.req.body.clone();
        if !frame_ok(&jpg) {
            return bad("fotograma no válido");
        }
        Ok(remote::push(a.i("id").unwrap_or(0), self.req.header("x-sesion"), Some(jpg)).map_or_else(|| err(404, "no existe"), |v| js(200, v)))
    }
}

fn gone() -> Resp {
    err(404, "esta sesión ya no existe")
}

/// Cada cuánto mira el WebSocket aunque no haya novedades: mantiene viva la sesión y nota lo que caduca.
const TICK: Duration = Duration::from_secs(2);

/// La pantalla para el técnico: fotogramas (binario) y estado (texto, JSON) en cuanto cambian. Recibe listas de
/// eventos de ratón y teclado (texto, JSON). Terminar es aparte (DELETE): si solo se corta la red, la sesión sigue
/// hasta que caduca y el técnico puede volver a entrar.
fn tech_ws(w: Ws) -> Future {
    Box::pin(async move {
        let id = w.params.iter().find(|(k, _)| k == "id").map(|(_, v)| v.clone()).unwrap_or_default();
        let uid = w.who.uid.unwrap_or(0);
        if remote::get(&id, uid).is_none() {
            return out(gone());
        }
        w.up.max_message_size(64 * 1024).on_upgrade(move |ws| tech_loop(ws, id, uid))
    })
}

async fn tech_loop(mut ws: WebSocket, id: String, uid: i64) {
    let mut rx = remote::CHANGED.subscribe();
    let mut tick = tokio::time::interval(TICK);
    let (mut seq, mut state) = (0u64, String::new());
    loop {
        let Some((f, st)) = remote::frame(&id, uid, seq) else {
            let _ = ws.send(Message::Text(json!({"state": "cerrada", "why": "La sesión ya no existe."}).to_string().into())).await;
            break;
        };
        if let Some((s, jpg)) = f {
            seq = s;
            if ws.send(Message::Binary(jpg.into())).await.is_err() {
                break;
            }
        }
        if st["state"].as_str() != Some(state.as_str()) {
            state = st["state"].as_str().unwrap_or("").to_string();
            if ws.send(Message::Text(st.to_string().into())).await.is_err() || remote::ended(&st) {
                break;
            }
        }
        tokio::select! {
            r = rx.changed() => if r.is_err() { break },
            _ = tick.tick() => {}
            m = ws.recv() => match m {
                Some(Ok(Message::Text(t))) => match events(t.as_bytes()) {
                    Ok(evs) => { remote::input(&id, uid, evs); }
                    Err(e) => { let _ = ws.send(Message::Text(json!({"error": e.to_string()}).to_string().into())).await; }
                },
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(_)) => {}
            },
        }
    }
}

/// La pantalla desde Kitty: recibe fotogramas (binario; vacío = sin cambios, para seguir vivo) y le manda, en cuanto
/// llegan, el ratón y el teclado del técnico y el final de la sesión (texto, JSON).
fn kitty_ws(w: Ws) -> Future {
    Box::pin(async move {
        let (key, id) = (w.req.header("x-kitty").to_string(), w.req.header("x-sesion").to_string());
        let a = tokio::task::spawn_blocking(move || agent_by_ukey(&key)).await;
        let aid = match a {
            Ok(Ok(Ok(a))) => a.i("id").unwrap_or(0),
            Ok(Ok(Err(r))) => return out(r),
            Ok(Err(e)) => return out(err(400, &e.to_string())),
            Err(_) => return out(err(500, "error interno")),
        };
        if remote::push(aid, &id, None).is_none() {
            return out(err(404, "no existe"));
        }
        w.up.max_message_size((8 << 20) + 1024).on_upgrade(move |ws| kitty_loop(ws, aid, id))
    })
}

async fn kitty_loop(mut ws: WebSocket, aid: i64, id: String) {
    let mut rx = remote::CHANGED.subscribe();
    loop {
        let jpg = tokio::select! {
            r = rx.changed() => if r.is_err() { break } else { None },
            m = ws.recv() => match m {
                Some(Ok(Message::Binary(b))) if frame_ok(&b) => Some(b.to_vec()),
                Some(Ok(Message::Binary(_))) => {
                    let _ = ws.send(Message::Text(json!({"error": "fotograma no válido"}).to_string().into())).await;
                    continue;
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(_)) => continue,
            },
        };
        let Some(v) = remote::push(aid, &id, jpg) else { break };
        let done = v["state"] != "aceptada";
        if (done || v["input"].as_array().is_some_and(|a| !a.is_empty())) && ws.send(Message::Text(v.to_string().into())).await.is_err() {
            break;
        }
        if done {
            break;
        }
    }
}
