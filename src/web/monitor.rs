//! El monitor (pings y comprobaciones), Salud (SNMP, Hikvision y Kitty), sonidos, el tablero, los avisos y lo que
//! se guarda. Salud se refresca sola con un WebSocket que avisa cuando cambia algo.
use super::inventario::{kind_of, table_cols};
use super::{Ctx, Future, H, Perm, Route, Ws, err, js, no_content, r};
use crate::db::{self, q, val};
use crate::health;
use crate::monitor::{self, SECRET};
use crate::p;
use crate::server::Resp;
use crate::util::{Bad, J, Row, bad, is_int, obj, py_str, trunc, truthy};
use crate::validate::*;
use anyhow::Result;
use axum::extract::ws::{Message, WebSocket};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::time::Duration;

const AUDIO_TYPES: &[&str] = &["audio/mpeg", "audio/wav", "audio/x-wav", "audio/wave", "audio/ogg", "audio/webm", "audio/mp4", "audio/aac", "audio/x-m4a"];

pub fn routes() -> Vec<Route> {
    vec![
        r("GET", "/api/checks", Perm::User, Ctx::crud_list),
        r("POST", "/api/checks", Perm::User, Ctx::crud_create),
        r("GET", "/api/checks/{id}", Perm::User, Ctx::crud_get),
        r("PUT", "/api/checks/{id}", Perm::User, Ctx::crud_put),
        r("DELETE", "/api/checks/{id}", Perm::User, Ctx::crud_delete),
        r("POST", "/api/checks/{id}/mute", Perm::User, Ctx::mute),
        r("GET", "/api/sources", Perm::User, Ctx::crud_list),
        r("POST", "/api/sources", Perm::User, Ctx::crud_create),
        r("GET", "/api/sources/{id}", Perm::User, Ctx::crud_get),
        r("PUT", "/api/sources/{id}", Perm::User, Ctx::crud_put),
        r("DELETE", "/api/sources/{id}", Perm::User, Ctx::crud_delete),
        r("POST", "/api/sources/{id}/mute", Perm::User, Ctx::mute),
        r("POST", "/api/sources/{id}/topology", Perm::User, Ctx::topology),
        r("POST", "/api/sources/test", Perm::User, Ctx::source_test),
        // copias de la configuración: la lista, todos; el texto y el diff, solo administradores (llevan contraseñas)
        r("GET", "/api/sources/{id}/configs", Perm::User, |c| Ok(js(200, crate::configs::versions(c.id())?))),
        r("POST", "/api/sources/{id}/configs", Perm::User, Ctx::config_now),
        r("DELETE", "/api/sources/{id}/hostkey", Perm::User, |c| {
            let n = q("UPDATE sources SET ssh_key=NULL, cfg_last=NULL WHERE id=?", p![c.id()])?.rowcount;
            if n == 0 {
                return Ok(err(404, "no existe"));
            }
            c.log("olvidar clave SSH", "source", c.id(), val("SELECT host FROM sources WHERE id=?", p![c.id()])?, &json!({}))?;
            Ok(no_content())
        }),
        r("GET", "/api/configs/{id}", Perm::Admin, |c| {
            Ok(match q("SELECT c.text, c.ts, s.host FROM configs c LEFT JOIN sources s ON s.id = c.source WHERE c.id=?", p![c.id()])?.one() {
                Some(r) => {
                    let file = format!("{}-{}.txt", r.s("host"), r.s("ts").replace([' ', ':'], "-"));
                    Resp::new(200, r.s("text").as_bytes().to_vec(), "text/plain; charset=utf-8").header("Content-Disposition", format!("attachment; filename*=UTF-8''{}", crate::util::quote(&file))).header("X-Content-Type-Options", "nosniff")
                }
                None => err(404, "no existe"),
            })
        }),
        r("GET", "/api/configs/{id}/diff", Perm::Admin, |c| Ok(crate::configs::diff_view(c.id())?.map_or_else(|| err(404, "no existe"), |v| js(200, v)))),
        r("GET", "/api/monitor", Perm::User, |_| Ok(js(200, monitor::monitor_state()?))),
        r("POST", "/api/monitor/test", Perm::User, |_| {
            if monitor::channels().is_empty() {
                return Ok(err(400, "ningún canal de aviso configurado: hazlo en Opciones → Avisos"));
            }
            Ok(js(200, monitor::notify("catlan: aviso de prueba", "Si lees esto, los avisos de catlan llegan por aquí.\n\n-- catlan")))
        }),
        r("POST", "/api/maintenance", Perm::User, Ctx::maintenance),
        r("GET", "/api/alerts", Perm::Admin, |_| Ok(js(200, monitor::alerts_view()?))),
        r("PUT", "/api/alerts", Perm::Admin, Ctx::alerts_put),
        // cuántos días se guarda cada cosa: verlo, todos; cambiarlo, los administradores
        r("GET", "/api/retention", Perm::User, |_| Ok(js(200, monitor::retention()))),
        r("PUT", "/api/retention", Perm::Admin, |c| {
            let v = monitor::set_retention(&c.body()?)?;
            c.log("editar", "retention", 0, "cuánto se guarda", &v)?;
            Ok(js(200, v))
        }),
        // la salud del propio catlan
        r("GET", "/api/system", Perm::Admin, |_| Ok(js(200, monitor::system_health()?))),
        r("POST", "/api/ping", Perm::User, |c| {
            let b = c.body()?;
            let mut d = Row::new();
            d.insert("host".into(), b.as_object().and_then(|o| o.get("host")).cloned().unwrap_or(Value::Null));
            check_host(&d, true)?;
            let (up, rtt) = monitor::ping(d.s("host"));
            Ok(js(200, json!({"up": up, "rtt": rtt})))
        }),
        r("GET", "/api/sounds", Perm::User, |_| Ok(js(200, q("SELECT id, name FROM sounds ORDER BY id", p![])?.rows))),
        r("POST", "/api/sounds", Perm::User, Ctx::sound_create),
        r("DELETE", "/api/sounds/{id}", Perm::User, Ctx::sound_delete),
        r("GET", "/api/sounds/{id}/audio", Perm::User, |c| {
            Ok(match db::blob("SELECT mime, data FROM sounds WHERE id=?", p![c.id()])? {
                Some((mime, data)) => Resp::new(200, data, &mime),
                None => err(404, "no existe"),
            })
        }),
        r("GET", "/api/dashboard", Perm::User, |_| {
            let d = val("SELECT data FROM dash WHERE id=1", p![])?;
            // null: el frontal pone uno por defecto
            Ok(js(200, d.as_str().and_then(|s| serde_json::from_str::<Value>(s).ok()).unwrap_or(Value::Null)))
        }),
        r("PUT", "/api/dashboard", Perm::User, |c| {
            let d = c.body()?;
            check_dash(&d)?;
            q("INSERT OR REPLACE INTO dash(id, data) VALUES(1, ?)", p![d.to_string()])?;
            Ok(no_content())
        }),
        r("POST", "/api/discover", Perm::User, Ctx::discover),
        r("GET", "/api/latency", Perm::User, |c| Ok(js(200, monitor::latency(hours(&c.qs)?)?))),
        r("GET", "/api/sla", Perm::User, |c| {
            let month = c.qs.get("month").map(|v| v[0].clone()).unwrap_or_else(|| crate::util::local("%Y-%m"));
            Ok(js(200, monitor::sla(&month)?))
        }),
        r("GET", "/api/health", Perm::User, |_| Ok(js(200, monitor::health()?))),
        Route { method: "GET", path: "/api/health/ws", perm: Perm::User, h: H::Ws(health_ws) },
        r("GET", "/api/metrics", Perm::User, |c| {
            let source = c.qs.get("source").map(|v| v[0].as_str()).unwrap_or("0").parse::<i64>().map_err(|_| Bad("fuente no válida".into()))?;
            Ok(js(200, monitor::series(source, hours(&c.qs)?)?))
        }),
    ]
}

fn hours(qs: &HashMap<String, Vec<String>>) -> Result<i64> {
    let h: i64 = qs.get("hours").map_or("24", |v| v[0].as_str()).parse().map_err(|_| Bad("horas no válidas".into()))?;
    Ok(h.clamp(1, monitor::MAX_HOURS))
}

/// Como mucho un aviso cada tanto: con miles de Kitty, Salud cambia varias veces por segundo.
const HEALTH_EVERY: Duration = Duration::from_secs(5);

/// Avisa a la web («salud», texto) cuando hay lecturas nuevas en Salud; la web vuelve a pedir lo que enseña.
fn health_ws(w: Ws) -> Future {
    Box::pin(async move { w.up.max_message_size(1024).on_upgrade(health_loop) })
}

async fn health_loop(mut ws: WebSocket) {
    let mut rx = monitor::HEALTH.subscribe();
    rx.mark_unchanged();
    loop {
        tokio::select! {
            r = rx.changed() => {
                if r.is_err() || ws.send(Message::Text("salud".into())).await.is_err() {
                    break;
                }
                tokio::time::sleep(HEALTH_EVERY).await;
            }
            m = ws.recv() => if matches!(m, Some(Ok(Message::Close(_))) | None | Some(Err(_))) { break },
        }
    }
}

impl Ctx {
    /// Silenciar los avisos de una comprobación o un equipo de Salud.
    fn mute(&mut self) -> Result<Resp> {
        let (res, rid) = (self.res(), self.id());
        let b = self.body()?;
        let mins = if truthy(&b) { obj(&b)?.get("minutes").cloned().unwrap_or(Value::Null) } else { Value::Null };
        if !(is_int(&mins) && mins.as_i64().is_some_and(|x| (0..=10080).contains(&x))) {
            return bad("silenciar de 0 minutos a 7 días");
        }
        let mins = mins.as_i64().unwrap_or(0);
        let cur = q(&format!("UPDATE {res} SET mute_from=NULL, mute_until = CASE WHEN ? > 0 THEN datetime('now', '+' || ? || ' minutes') END WHERE id=?"), p![mins, mins, rid])?;
        if cur.rowcount == 0 {
            return Ok(err(404, "no existe"));
        }
        let row = q(&format!("SELECT id, label, host, mute_until FROM {res} WHERE id=?"), p![rid])?.one().unwrap_or_default();
        let name = if row.s("label").is_empty() { row.s("host") } else { row.s("label") }.to_string();
        self.log(if mins > 0 { "silenciar" } else { "quitar silencio" }, kind_of(res), &row["id"], name, &json!({"minutes": mins}))?;
        Ok(js(200, row))
    }

    /// Dibujar el esquema de red de un switch con lo que cuenta por LLDP/CDP.
    fn topology(&mut self) -> Result<Resp> {
        let rid = self.id();
        let src = q("SELECT * FROM sources WHERE id=?", p![rid])?.one();
        let Some(src) = src.filter(|s| !["kitty", "hikvision"].contains(&s.s("kind"))) else {
            return Ok(if q("SELECT 1 FROM sources WHERE id=?", p![rid])?.is_empty() { err(404, "no existe") } else { err(400, "solo los equipos que se leen por SNMP") });
        };
        let (mid, name, nbrs, new) = match health::auto_map(&src) {
            Ok(x) => x,
            Err(e) => return Ok(err(400, &e.to_string())),
        };
        if nbrs.is_empty() {
            return Ok(err(400, "el equipo no ha contado ningún vecino: activa LLDP o CDP en el switch y comprueba que SNMP deja leer las tablas BRIDGE/LLDP"));
        }
        self.log(if new { "crear" } else { "editar" }, "map", mid, &name, &json!({"auto": true, "vecinos": nbrs.len()}))?;
        Ok(js(200, json!({"map": mid, "name": name, "neighbors": nbrs})))
    }

    /// Copiar ya la configuración de un equipo (lo mismo que hace el monitor una vez al día).
    fn config_now(&mut self) -> Result<Resp> {
        let Some(src) = q(&format!("{} WHERE s.id=?", monitor::SOURCES), p![self.id()])?.one() else { return Ok(err(404, "no existe")) };
        if !crate::configs::KINDS.contains(&src.s("kind")) || src.s("ssh_user").is_empty() {
            return Ok(err(400, "pon un usuario SSH en el equipo (solo Cisco, HP/Aruba y MikroTik)"));
        }
        Ok(match crate::configs::backup(&src) {
            Ok(new) => {
                if let Some(v) = new {
                    self.log("copiar configuración", "source", &src["id"], &src["host"], &json!({"version": v}))?;
                }
                js(200, json!({"new": new}))
            }
            Err(e) => err(400, &e.to_string()),
        })
    }

    /// Probar un equipo de Salud sin guardarlo.
    fn source_test(&mut self) -> Result<Resp> {
        let b = self.body()?;
        let Some(b) = b.as_object() else { return bad("envía un objeto") };
        let cols = table_cols("sources").unwrap_or(&[]);
        let mut d: Row = b.iter().filter(|(k, _)| cols.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect();
        if let Some(id) = b.get("id").filter(|v| is_int(v)) {
            // editando: las credenciales vacías son las guardadas
            if let Some(old) = q(&format!("SELECT {} FROM sources WHERE id=?", SECRET.join(", ")), p![id])?.one() {
                for k in SECRET {
                    if !d.t(k) {
                        d.insert(k.into(), old[k].clone());
                    }
                }
            }
        }
        check_source(&d, true)?;
        let mut src: Row = Row::new();
        src.insert("kind".into(), "generic".into());
        src.extend(d);
        Ok(match health::collect(&src) {
            Ok((out, probs, info)) => js(200, json!({"metrics": health::metrics_json(&out), "problems": probs, "info": info})),
            Err(e) => err(400, &e.to_string()),
        })
    }

    /// Mantenimiento programado de equipos o de todo un rack.
    fn maintenance(&mut self) -> Result<Resp> {
        let b = self.body()?;
        let b = obj(&b)?;
        let rack = b.get("rack").filter(|v| !v.is_null());
        let mut items = b.get("items").filter(|v| truthy(v)).cloned().unwrap_or(json!([]));
        if let Some(rack) = rack {
            let Some(rk) = q("SELECT data FROM maps WHERE id=?", p![rack])?.one() else { return Ok(err(404, "no existe")) };
            let data: Value = serde_json::from_str(rk.s("data")).unwrap_or_default();
            items = data["devices"].as_array().into_iter().flatten().filter_map(|d| d.get("item").filter(|i| is_int(i)).cloned()).collect();
        }
        let items: Vec<i64> = match items.as_array() {
            Some(a) if !a.is_empty() && a.iter().all(is_int) => a.iter().filter_map(Value::as_i64).collect(),
            _ => return bad("elige equipos del inventario (o un rack con equipos enlazados)"),
        };
        let t = |k: &str| health::parse_iso(&b.get(k).map(py_str).unwrap_or_default(), true);
        let (Some(t0), Some(t1)) = (t("from"), t("to")) else { return bad("fechas no válidas") };
        if !(t0 < t1 && t1 > chrono::Utc::now() && t1 - t0 <= chrono::TimeDelta::days(31)) {
            return bad("el mantenimiento acaba después de empezar, en el futuro y dura como mucho 31 días");
        }
        let (f0, f1) = (t0.format("%Y-%m-%d %H:%M:%S").to_string(), t1.format("%Y-%m-%d %H:%M:%S").to_string());
        let marks = vec!["?"; items.len()].join(",");
        let ips: Vec<Value> =
            q(&format!("SELECT ip FROM items WHERE id IN ({marks}) AND ip != ''"), items.iter().map(|i| db::SqlV::Integer(*i)).collect())?.into_iter().map(|r| r["ip"].clone()).collect();
        let mut n = 0;
        for t in ["checks", "sources"] {
            let mut args = p![&f0, &f1];
            args.extend(items.iter().map(|i| db::SqlV::Integer(*i)));
            args.extend(ips.iter().map(db::jv));
            let or = if ips.is_empty() { String::new() } else { format!(" OR host IN ({})", vec!["?"; ips.len()].join(",")) };
            n += q(&format!("UPDATE {t} SET mute_from=?, mute_until=? WHERE item IN ({marks}){or}"), args)?.rowcount;
        }
        let (kind, r) = match rack {
            Some(r) => ("rack", db::jv(r)),
            None => ("item", db::SqlV::Integer(items[0])),
        };
        self.log("programar mantenimiento", kind, r, format!("{} equipos", items.len()), &json!({"desde": f0, "hasta": f1, "items": items}))?;
        Ok(js(200, json!({"muted": n, "from": f0, "to": f1})))
    }

    /// Canales de aviso: los secretos ni salen ni se pisan con un campo vacío.
    fn alerts_put(&mut self) -> Result<Resp> {
        let b = self.body()?;
        let Some(b) = b.as_object() else { return bad("envía un objeto") };
        let mut saved = monitor::saved_alerts()?;
        for k in monitor::ALERT_KEYS {
            let Some(v) = b.get(k) else { continue };
            if v.is_null() {
                saved.shift_remove(k); // quitar lo guardado (vuelve la variable de entorno, si la hay)
                continue;
            }
            let Some(v) = v.as_str().filter(|s| s.chars().count() <= 600) else { return bad(format!("{k} no válido")) };
            let v = v.trim();
            if v.is_empty() {
                if !monitor::ALERT_SECRET.contains(&k) {
                    saved.shift_remove(k);
                }
                continue; // secreto vacío = conservar el guardado
            }
            monitor::check_alert(k, v)?;
            saved.insert(k.into(), v.into());
        }
        q("INSERT OR REPLACE INTO meta(k, v) VALUES('alerts', ?)", p![Value::Object(saved).to_string()])?;
        monitor::apply_alerts()?;
        let mut campos: Vec<&str> = b.keys().map(String::as_str).filter(|k| monitor::ALERT_KEYS.contains(k)).collect();
        campos.sort();
        self.log("editar", "alerts", 0, "los avisos", &json!({"campos": campos}))?;
        Ok(js(200, monitor::alerts_view()?))
    }

    fn sound_create(&mut self) -> Result<Resp> {
        let mime = self.req.header("content-type").split(';').next().unwrap_or("").trim().to_string();
        let data = self.req.body.clone();
        if !AUDIO_TYPES.contains(&mime.as_str()) || data.is_empty() || data.len() > 3 * 1024 * 1024 {
            return Ok(err(400, "sube un audio (mp3, wav, ogg, m4a) de hasta 3 MB"));
        }
        let name = trunc(self.qs.get("name").map_or("Alerta", |v| v[0].as_str()), 100);
        let id = q("INSERT INTO sounds(name, mime, data) VALUES(?,?,?)", p![&name, &mime, data])?.lastrowid;
        Ok(js(201, json!({"id": id, "name": name})))
    }

    fn sound_delete(&mut self) -> Result<Resp> {
        q("DELETE FROM sounds WHERE id=?", p![self.id()])?;
        q("UPDATE checks SET sound='' WHERE sound=?", p![format!("u:{}", self.param("id").unwrap_or(""))])?; // quien lo usaba vuelve al sonido general
        Ok(no_content())
    }

    /// Descubrir red: ping, DNS y SNMP en una red IPv4 pequeña.
    fn discover(&mut self) -> Result<Resp> {
        let b = self.body()?;
        let b = obj(&b)?;
        let s = b.get("net").map(py_str).unwrap_or_default();
        let net = match monitor::parse_net(s.trim()) {
            Ok(n) if n.num_addresses() <= 1024 => n,
            Ok(_) | Err(monitor::NetErr::V6) => return bad("solo redes IPv4 de hasta 1024 direcciones (/22)"),
            Err(monitor::NetErr::Bad) => return bad("red no válida: escribe algo como 10.0.0.0/24"),
        };
        let community = match b.get("community").filter(|v| truthy(v)) {
            None => "public".to_string(),
            Some(Value::String(s)) if s.chars().count() <= 100 => s.clone(),
            Some(_) => return bad("comunidad no válida"),
        };
        let hosts: Vec<String> = net.hosts().map(|h| std::net::Ipv4Addr::from(h).to_string()).collect();
        Ok(js(200, health::discover(&hosts, &community)?))
    }
}
