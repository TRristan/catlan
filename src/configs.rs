//! Copia de la configuración de switches y routers por SSH (Cisco, HP/Aruba, MikroTik), estilo Oxidized: una al día,
//! una versión nueva solo si cambia, con el diff entre versiones y un aviso. La clave del equipo se fija la primera vez.
use crate::db::{q, val};
use crate::monitor::{SOURCES, channels, muted, notify};
use crate::p;
use crate::util::{J, Row, trunc};
use anyhow::{Result, anyhow, bail};
use russh::client::{self, KeyboardInteractiveAuthResponse as Ki};
use russh::keys::{HashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Preferred, cipher, kex, mac};
use serde_json::{Value, json};
use std::borrow::Cow;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Los que se copian. El resto de tipos de Salud no tiene una configuración que guardar.
pub const KINDS: [&str; 3] = ["cisco", "hp", "mikrotik"];

// Los equipos de red viejos solo hablan algoritmos antiguos: se aceptan detrás de los buenos (el equipo elige el mejor que tenga)
const KEX: &[kex::Name] = &[
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
    kex::ECDH_SHA2_NISTP256,
    kex::ECDH_SHA2_NISTP384,
    kex::ECDH_SHA2_NISTP521,
    kex::DH_GEX_SHA256,
    kex::DH_G16_SHA512,
    kex::DH_G14_SHA256,
    kex::DH_G14_SHA1,
    kex::DH_GEX_SHA1,
    kex::DH_G1_SHA1,
    kex::EXTENSION_SUPPORT_AS_CLIENT,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
];
const CIPHERS: &[cipher::Name] = &[
    cipher::CHACHA20_POLY1305,
    cipher::AES_256_GCM,
    cipher::AES_128_GCM,
    cipher::AES_256_CTR,
    cipher::AES_192_CTR,
    cipher::AES_128_CTR,
    cipher::AES_256_CBC,
    cipher::AES_192_CBC,
    cipher::AES_128_CBC,
    cipher::TRIPLE_DES_CBC,
];
const MACS: &[mac::Name] = &[mac::HMAC_SHA256_ETM, mac::HMAC_SHA512_ETM, mac::HMAC_SHA256, mac::HMAC_SHA512, mac::HMAC_SHA1_ETM, mac::HMAC_SHA1];

/// Fija la clave: sin huella guardada vale cualquiera (y se guarda); con huella, solo esa.
struct Keys {
    known: String,
    seen: Arc<Mutex<String>>,
}
impl client::Handler for Keys {
    type Error = russh::Error;
    async fn check_server_key(&mut self, k: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = k else { return Ok(false) };
        let fp = key.fingerprint(HashAlg::Sha256).to_string();
        let ok = self.known.is_empty() || self.known == fp;
        *crate::util::lock(&self.seen) = fp;
        Ok(ok)
    }
}

/// Lo que se manda a cada tipo. HP (ProCurve/Aruba) no acepta órdenes sueltas: hay que abrir una consola.
fn command(kind: &str) -> &'static str {
    match kind {
        "mikrotik" => "/export",
        _ => "show running-config",
    }
}

async fn read_all(ch: &mut russh::Channel<client::Msg>, idle: Option<Duration>) -> Result<Vec<u8>> {
    let mut out = vec![];
    loop {
        let msg = match idle {
            // en una consola nadie cierra: se acaba cuando el equipo deja de escribir
            Some(t) => match tokio::time::timeout(t, ch.wait()).await {
                Ok(m) => m,
                Err(_) => break,
            },
            None => ch.wait().await,
        };
        match msg {
            Some(ChannelMsg::Data { data }) => out.extend_from_slice(&data),
            Some(ChannelMsg::ExtendedData { data, .. }) => out.extend_from_slice(&data),
            Some(ChannelMsg::Eof | ChannelMsg::Close) | None => break,
            _ => {}
        }
        if out.len() > 20 << 20 {
            bail!("la configuración pasa de 20 MB");
        }
    }
    Ok(out)
}

async fn fetch_async(host: &str, port: u16, user: &str, pass: &str, kind: &str, known: &str) -> Result<(String, String)> {
    let config = client::Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
        preferred: Preferred { kex: Cow::Borrowed(KEX), cipher: Cow::Borrowed(CIPHERS), mac: Cow::Borrowed(MACS), ..Preferred::DEFAULT },
        ..Default::default()
    };
    let seen = Arc::new(Mutex::new(String::new()));
    let handler = Keys { known: known.into(), seen: seen.clone() };
    let conn = tokio::time::timeout(Duration::from_secs(15), client::connect(Arc::new(config), (host, port), handler)).await;
    let fp = crate::util::lock(&seen).clone();
    let mut s = match conn {
        Err(_) => bail!("el equipo no responde por SSH (puerto {port})"),
        Ok(Err(_)) if !known.is_empty() && !fp.is_empty() && fp != known => {
            bail!("la clave SSH del equipo ha cambiado (antes {known}, ahora {fp}). Si has cambiado el equipo, olvida la clave guardada; si no, alguien podría estar suplantándolo")
        }
        Ok(Err(e)) => bail!("SSH: {e}"),
        Ok(Ok(s)) => s,
    };
    let mut ok = s.authenticate_password(user, pass).await?.success();
    if !ok {
        // muchos switches piden la contraseña por «keyboard-interactive»
        let mut r = s.authenticate_keyboard_interactive_start(user, None).await?;
        for _ in 0..3 {
            match r {
                Ki::InfoRequest { prompts, .. } => r = s.authenticate_keyboard_interactive_respond(prompts.iter().map(|_| pass.to_string()).collect()).await?,
                Ki::Success => {
                    ok = true;
                    break;
                }
                Ki::Failure { .. } => break,
            }
        }
    }
    if !ok {
        bail!("usuario o contraseña SSH incorrectos");
    }
    let mut ch = s.channel_open_session().await?;
    let raw = if kind == "hp" {
        ch.request_pty(false, "vt100", 200, 1000, 0, 0, &[]).await?;
        ch.request_shell(false).await?;
        // la primera tecla salta el «Press any key to continue»
        ch.data_bytes(format!("\r\nno page\r\n{}\r\n", command(kind)).into_bytes()).await?;
        read_all(&mut ch, Some(Duration::from_secs(8))).await?
    } else {
        ch.exec(true, command(kind)).await?;
        tokio::time::timeout(Duration::from_secs(120), read_all(&mut ch, None)).await.map_err(|_| anyhow!("el equipo tardó más de 2 minutos en dar la configuración"))??
    };
    let _ = s.disconnect(russh::Disconnect::ByApplication, "", "").await;
    let text = String::from_utf8_lossy(&raw);
    Ok((clean(kind, &text)?, fp))
}

/// Pide la configuración por SSH: (texto limpio, huella de la clave del equipo).
pub fn fetch(src: &Row) -> Result<(String, String)> {
    let (host, port) = (src.s("host").to_string(), src.i("ssh_port").filter(|p| (1..=65535).contains(p)).unwrap_or(22) as u16);
    let (user, pass, kind, known) = (src.s("ssh_user").to_string(), src.s("ssh_pass").to_string(), src.s("kind").to_string(), src.s("ssh_key").to_string());
    // un runtime propio en su hilo: se llama desde el monitor y desde la web (que ya está dentro de uno)
    std::thread::spawn(move || tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(fetch_async(&host, port, &user, &pass, &kind, &known)))
        .join()
        .map_err(|_| anyhow!("la copia por SSH se rompió"))?
}

/// Quita lo que cambia en cada copia sin que cambie la configuración (fechas, tamaños, ecos de la consola).
pub fn clean(kind: &str, raw: &str) -> Result<String> {
    let text = crate::re!(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[A-Za-z=>]").replace_all(raw, "").replace('\r', "");
    let mut lines: Vec<&str> = text.lines().collect();
    if kind == "hp" {
        // de la consola, solo lo que hay entre el eco de la orden y el siguiente indicador
        let cmd = command(kind);
        let Some(at) = lines.iter().position(|l| l.trim_end().ends_with(cmd)) else { bail!("la consola del switch no respondió a «{cmd}»") };
        let prompt = lines[at].trim_end().strip_suffix(cmd).unwrap_or("").trim().to_string();
        lines = lines[at + 1..].to_vec();
        if !prompt.is_empty()
            && let Some(end) = lines.iter().rposition(|l| l.trim().starts_with(&prompt))
        {
            lines.truncate(end);
        }
    }
    let skip = |l: &str| match kind {
        "cisco" => ["Building configuration", "Current configuration :", "! Last configuration change", "! NVRAM config last updated", "! No configuration change since", "ntp clock-period"]
            .iter()
            .any(|p| l.starts_with(p)),
        "mikrotik" => l.starts_with("# ") && l.contains(" by RouterOS"),
        _ => false,
    };
    let lines: Vec<&str> = lines.into_iter().map(str::trim_end).filter(|l| !skip(l)).collect();
    let (a, b) = (lines.iter().position(|l| !l.is_empty()).unwrap_or(lines.len()), lines.iter().rposition(|l| !l.is_empty()).map_or(0, |i| i + 1));
    let lines = if a < b { &lines[a..b] } else { &[][..] };
    if let Some(e) = lines.first().filter(|l| l.starts_with('%') || l.contains("nvalid input") || l.starts_with("bad command")) {
        bail!("el equipo contestó: {}", trunc(e, 200));
    }
    if lines.len() < 3 {
        bail!("el equipo no devolvió ninguna configuración: ¿tiene el usuario permiso para verla?");
    }
    Ok(lines.join("\n") + "\n")
}

/// Diff por líneas: ('=' | '-' | '+', línea). Lo común del principio y del final se quita antes, y con lo que queda,
/// la subsecuencia común más larga. shortcut: si lo distinto pasa de 2000×2000 líneas, sale como «todo fuera, todo dentro».
pub fn diff<'a>(a: &'a str, b: &'a str) -> Vec<(char, &'a str)> {
    let (a, b): (Vec<&str>, Vec<&str>) = (a.lines().collect(), b.lines().collect());
    let pre = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let suf = a[pre..].iter().rev().zip(b[pre..].iter().rev()).take_while(|(x, y)| x == y).count();
    let (ma, mb) = (&a[pre..a.len() - suf], &b[pre..b.len() - suf]);
    let mut out: Vec<(char, &str)> = a[..pre].iter().map(|l| ('=', *l)).collect();
    if ma.len() * mb.len() > 4_000_000 {
        out.extend(ma.iter().map(|l| ('-', *l)));
        out.extend(mb.iter().map(|l| ('+', *l)));
    } else {
        let (n, m) = (ma.len(), mb.len());
        let mut t = vec![0u32; (n + 1) * (m + 1)]; // t[i][j]: LCS de ma[i..] y mb[j..]
        for i in (0..n).rev() {
            for j in (0..m).rev() {
                t[i * (m + 1) + j] = if ma[i] == mb[j] { t[(i + 1) * (m + 1) + j + 1] + 1 } else { t[(i + 1) * (m + 1) + j].max(t[i * (m + 1) + j + 1]) };
            }
        }
        let (mut i, mut j) = (0, 0);
        while i < n || j < m {
            if i < n && j < m && ma[i] == mb[j] {
                out.push(('=', ma[i]));
                (i, j) = (i + 1, j + 1);
            } else if i < n && (j == m || t[(i + 1) * (m + 1) + j] >= t[i * (m + 1) + j + 1]) {
                out.push(('-', ma[i])); // ante la duda, lo quitado antes que lo nuevo
                i += 1;
            } else {
                out.push(('+', mb[j]));
                j += 1;
            }
        }
    }
    out.extend(a[a.len() - suf..].iter().map(|l| ('=', *l)));
    out
}

/// El diff para la web: los cambios con 3 líneas alrededor; lo que no cambia, resumido como ["…", n líneas].
pub fn hunks(d: &[(char, &str)]) -> Value {
    let near = |i: usize| d[i.saturating_sub(3)..(i + 4).min(d.len())].iter().any(|(op, _)| *op != '=');
    let mut out: Vec<Value> = vec![];
    let mut gap = 0;
    for (i, (op, l)) in d.iter().enumerate() {
        if *op == '=' && !near(i) {
            gap += 1;
            continue;
        }
        if gap > 0 {
            out.push(json!(["…", gap]));
            gap = 0;
        }
        out.push(json!([op.to_string(), l]));
    }
    if gap > 0 {
        out.push(json!(["…", gap]));
    }
    out.into()
}

fn name(src: &Row) -> String {
    [src.s("label"), src.s("item_name"), src.s("host")].into_iter().find(|s| !s.is_empty()).unwrap_or("").to_string()
}

/// Copia la configuración de un equipo. Devuelve el id de la versión nueva, o None si no ha cambiado.
pub fn backup(src: &Row) -> Result<Option<i64>> {
    let id = src.i("id").unwrap_or(0);
    let (text, fp) = match fetch(src) {
        Ok(x) => x,
        Err(e) => {
            let msg = trunc(&e.to_string(), 300);
            q("UPDATE sources SET cfg_error=?, cfg_last=CURRENT_TIMESTAMP WHERE id=?", p![&msg, id])?;
            if src.s("cfg_error").is_empty() && !muted(src) && !channels().is_empty() {
                notify(&format!("catlan: no se pudo copiar la configuración de {}", name(src)), &format!("{} ({}): {msg}\n\n-- catlan", name(src), src.s("host")));
            }
            return Err(e);
        }
    };
    q("UPDATE sources SET cfg_error=NULL, cfg_last=CURRENT_TIMESTAMP, ssh_key=COALESCE(NULLIF(ssh_key, ''), ?) WHERE id=?", p![&fp, id])?;
    let last = val("SELECT text FROM configs WHERE source=? ORDER BY id DESC LIMIT 1", p![id])?;
    if last.as_str() == Some(text.as_str()) {
        return Ok(None);
    }
    let new = q("INSERT INTO configs(source, text) VALUES(?, ?)", p![id, &text])?.lastrowid;
    if let Some(old) = last.as_str()
        && !muted(src)
        && !channels().is_empty()
    {
        // solo cuánto: las líneas pueden llevar contraseñas y no deben salir por correo ni Telegram
        let d = diff(old, &text);
        let (add, del) = (d.iter().filter(|x| x.0 == '+').count(), d.iter().filter(|x| x.0 == '-').count());
        notify(
            &format!("catlan: cambió la configuración de {}", name(src)),
            &format!("{} ({}): {add} líneas nuevas y {del} quitadas.\nEl detalle, en catlan: Salud → {} → Configuración.\n\n-- catlan", name(src), src.s("host"), name(src)),
        );
    }
    Ok(Some(new))
}

/// Una vez al día cada equipo con usuario SSH; si falló, se reintenta cada hora.
pub fn due() -> Result<Vec<Row>> {
    let kinds = KINDS.iter().map(|k| format!("'{k}'")).collect::<Vec<_>>().join(",");
    Ok(q(
        &format!(
            "{SOURCES} WHERE s.ssh_user != '' AND s.kind IN ({kinds}) AND (s.cfg_last IS NULL OR date(s.cfg_last, 'localtime') < date('now', 'localtime') \
             OR (s.cfg_error IS NOT NULL AND s.cfg_last <= datetime('now', '-1 hour')))"
        ),
        p![],
    )?
    .rows)
}

/// Lo que ve la web de un equipo: sus versiones (sin el texto) y cómo fue la última copia.
pub fn versions(src: i64) -> Result<Value> {
    let s = q("SELECT ssh_user, ssh_key, cfg_error, cfg_last FROM sources WHERE id=?", p![src])?.one().unwrap_or_default();
    let v = q("SELECT id, ts, length(text) AS size, length(text) - length(replace(text, char(10), '')) AS lines FROM configs WHERE source=? ORDER BY id DESC", p![src])?;
    Ok(json!({"on": !s.s("ssh_user").is_empty(), "key": s["ssh_key"], "error": s["cfg_error"], "last": s["cfg_last"], "versions": v.rows}))
}

/// Una versión frente a la anterior del mismo equipo (o frente a nada, si es la primera).
pub fn diff_view(id: i64) -> Result<Option<Value>> {
    let Some(cur) = q("SELECT id, source, ts, text FROM configs WHERE id=?", p![id])?.one() else { return Ok(None) };
    let prev = q("SELECT id, ts, text FROM configs WHERE source=? AND id<? ORDER BY id DESC LIMIT 1", p![&cur["source"], id])?.one();
    let old = prev.as_ref().map_or("", |p| p.s("text"));
    Ok(Some(json!({"id": id, "ts": cur["ts"], "prev": prev.as_ref().map(|p| json!({"id": p["id"], "ts": p["ts"]})), "hunks": hunks(&diff(old, cur.s("text")))})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limpia_lo_que_cambia_en_cada_copia() {
        let cisco = "Building configuration...\r\n\r\nCurrent configuration : 1234 bytes\r\n!\r\n! Last configuration change at 10:00:00 UTC\r\nversion 15.2\r\nhostname sw1\r\n!\r\nend\r\n";
        assert_eq!(clean("cisco", cisco).unwrap(), "!\nversion 15.2\nhostname sw1\n!\nend\n");
        let mk = "# nov/28/2026 10:00:00 by RouterOS 6.49\n# software id = AB12\n/ip address\nadd address=10.0.0.1/24\n";
        assert_eq!(clean("mikrotik", mk).unwrap(), "# software id = AB12\n/ip address\nadd address=10.0.0.1/24\n");
        let hp = "\x1b[1;24rPress any key\r\nSW-1# no page\r\nSW-1# show running-config\r\n\r\nRunning configuration:\r\n\r\nhostname \"SW-1\"\r\nvlan 1\r\n   untagged 1-24\r\n\x1b[24;1HSW-1# ";
        assert_eq!(clean("hp", hp).unwrap(), "Running configuration:\n\nhostname \"SW-1\"\nvlan 1\n   untagged 1-24\n");
        assert!(clean("cisco", "% Invalid input detected at '^' marker.\n").is_err());
        assert!(clean("hp", "SW-1# ").is_err());
    }

    #[test]
    fn diff_por_lineas() {
        let ops = |a, b| diff(a, b).iter().map(|(o, l)| format!("{o}{l}")).collect::<Vec<_>>().join(" ");
        assert_eq!(ops("a\nb\nc\n", "a\nb\nc\n"), "=a =b =c");
        assert_eq!(ops("a\nb\nc\n", "a\nx\nc\n"), "=a -b +x =c");
        assert_eq!(ops("a\nc\n", "a\nb\nc\nd\n"), "=a +b =c +d");
        assert_eq!(ops("", "a\n"), "+a");
        let big: String = (0..20).map(|i| format!("{i}\n")).collect();
        let h = hunks(&diff(&big, &big.replace("10\n", "diez\n")));
        assert_eq!(h, json!([["…", 7], ["=", "7"], ["=", "8"], ["=", "9"], ["-", "10"], ["+", "diez"], ["=", "11"], ["=", "12"], ["=", "13"], ["…", 6]]));
    }

    // Claves de prueba, solo para este switch de mentira
    const KEY_A: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDekM0tO94EAYSPoSVroq/efZLhB841Gibbm6J9cOanwgAAAIjKgHnFyoB5
xQAAAAtzc2gtZWQyNTUxOQAAACDekM0tO94EAYSPoSVroq/efZLhB841Gibbm6J9cOanwg
AAAEBaHp8abRsj0tDFxfnIlTugqzmVBYOyn0p8BZHz07N1Pt6QzS073gQBhI+hJWuir959
kuEHzjUaJtubon1w5qfCAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
";
    const KEY_B: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCWFHrk/cfivvXKrVaL83p373Z4In7BBUOhN4AfygwQoAAAAIgvuiCqL7og
qgAAAAtzc2gtZWQyNTUxOQAAACCWFHrk/cfivvXKrVaL83p373Z4In7BBUOhN4AfygwQoA
AAAECSbrVy8Ety/X1keOmxNVkirk8y3SCDzBdOrDglmXO0VZYUeuT9x+K+9cqtVovzenfv
dngifsEFQ6E3gB/KDBCgAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
";

    /// Un Cisco de mentira: contraseña «secreto», y a «show running-config» contesta con lo que haya en `conf`.
    #[derive(Clone)]
    struct FakeCisco(Arc<Mutex<String>>);
    impl russh::server::Handler for FakeCisco {
        type Error = russh::Error;
        async fn auth_password(&mut self, user: &str, pass: &str) -> Result<russh::server::Auth, Self::Error> {
            Ok(if user == "admin" && pass == "secreto" { russh::server::Auth::Accept } else { russh::server::Auth::reject() })
        }
        async fn channel_open_session(&mut self, _: russh::Channel<russh::server::Msg>, reply: russh::server::ChannelOpenHandle, _: &mut russh::server::Session) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }
        async fn exec_request(&mut self, ch: russh::ChannelId, cmd: &[u8], s: &mut russh::server::Session) -> Result<(), Self::Error> {
            s.channel_success(ch)?;
            let out = if cmd == b"show running-config" { format!("Building configuration...\r\n\r\n{}", crate::util::lock(&self.0)) } else { "% Invalid input\r\n".into() };
            s.data(ch, out.into_bytes())?;
            s.exit_status_request(ch, 0)?;
            s.eof(ch)?;
            s.close(ch)?;
            Ok(())
        }
    }

    fn serve(key: &str, conf: Arc<Mutex<String>>) -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let cfg = Arc::new(russh::server::Config {
            keys: vec![russh::keys::PrivateKey::from_openssh(key).unwrap()],
            auth_rejection_time: Duration::from_millis(10),
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..Default::default()
        });
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async move {
                l.set_nonblocking(true).unwrap();
                let l = tokio::net::TcpListener::from_std(l).unwrap();
                loop {
                    let (s, _) = l.accept().await.unwrap();
                    let (cfg, h) = (cfg.clone(), FakeCisco(conf.clone()));
                    tokio::spawn(async move {
                        if let Ok(r) = russh::server::run_stream(cfg, s, h).await {
                            let _ = r.await;
                        }
                    });
                }
            })
        });
        port
    }

    #[test]
    fn copia_por_ssh_con_versiones_y_clave_fijada() {
        crate::db::test_init();
        let conf = Arc::new(Mutex::new("hostname sw1\r\ninterface Gi0/1\r\n description uplink\r\nend\r\n".to_string()));
        let port = serve(KEY_A, conf.clone());
        let id = q("INSERT INTO sources(host, kind, ssh_user, ssh_pass, ssh_port) VALUES('127.0.0.1', 'cisco', 'admin', 'secreto', ?)", p![port as i64]).unwrap().lastrowid;
        let src = || q(&format!("{SOURCES} WHERE s.id=?"), p![id]).unwrap().one().unwrap();
        let v1 = backup(&src()).unwrap().expect("primera copia");
        assert!(src().s("ssh_key").starts_with("SHA256:"));
        assert_eq!(val("SELECT text FROM configs WHERE id=?", p![v1]).unwrap(), json!("hostname sw1\ninterface Gi0/1\n description uplink\nend\n"));
        assert_eq!(backup(&src()).unwrap(), None, "sin cambios no hay versión nueva");
        *crate::util::lock(&conf) = "hostname sw1\r\ninterface Gi0/1\r\n description core\r\nend\r\n".into();
        let v2 = backup(&src()).unwrap().expect("cambió");
        let d = diff_view(v2).unwrap().unwrap();
        assert_eq!(d["prev"]["id"], json!(v1));
        assert!(d["hunks"].as_array().unwrap().contains(&json!(["-", " description uplink"])) && d["hunks"].as_array().unwrap().contains(&json!(["+", " description core"])));
        assert_eq!(versions(id).unwrap()["versions"].as_array().unwrap().len(), 2);
        // contraseña mala: error guardado en el equipo
        q("UPDATE sources SET ssh_pass='otra' WHERE id=?", p![id]).unwrap();
        assert!(backup(&src()).unwrap_err().to_string().contains("contraseña"));
        assert!(src().s("cfg_error").contains("contraseña"));
        // otro equipo en la misma IP y puerto, con otra clave: no se le manda la contraseña
        let other = serve(KEY_B, conf);
        q("UPDATE sources SET ssh_pass='secreto', ssh_port=? WHERE id=?", p![other as i64, id]).unwrap();
        assert!(backup(&src()).unwrap_err().to_string().contains("ha cambiado"));
        q("UPDATE sources SET ssh_key=NULL WHERE id=?", p![id]).unwrap(); // «olvidar la clave»
        assert_eq!(backup(&src()).unwrap(), None);
        assert!(src().s("cfg_error").is_empty());
    }
}
