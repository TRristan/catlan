//! Contraseñas (PBKDF2), copias cifradas, TOTP y las primitivas de SNMPv3. Todo con crates de RustCrypto revisados.
use crate::util::Bad;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha2::Digest;

pub fn rand_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).expect("sin generador de números aleatorios del sistema");
    b
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

pub fn token_hex(n: usize) -> String {
    hex(&rand_bytes(n))
}

/// `secrets.token_urlsafe(n)`: n bytes en base64 para URL, sin relleno.
pub fn token_urlsafe(n: usize) -> String {
    data_encoding::BASE64URL_NOPAD.encode(&rand_bytes(n))
}

pub fn sha256_hex(s: &str) -> String {
    hex(&sha2::Sha256::digest(s.as_bytes()))
}

/// Comparación en tiempo constante.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn pbkdf2(pw: &[u8], salt: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pw, salt, 600_000, &mut out);
    out
}

/// `pbkdf2$<sal hex>$<hash hex>`, el mismo formato que la versión en Python: las contraseñas siguen valiendo.
pub fn pw_hash(pw: &str, salt: Option<&[u8]>) -> String {
    let salt = salt.map(|s| s.to_vec()).unwrap_or_else(|| rand_bytes(16));
    format!("pbkdf2${}${}", hex(&salt), hex(&pbkdf2(pw.as_bytes(), &salt, 32)))
}

pub fn pw_ok(pw: &str, stored: &str) -> bool {
    match stored.split('$').nth(1).and_then(unhex) {
        Some(salt) => ct_eq(pw_hash(pw, Some(&salt)).as_bytes(), stored.as_bytes()),
        None => false,
    }
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key).expect("HMAC admite cualquier clave");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

fn shake256(seed: &[u8], n: usize) -> Vec<u8> {
    use shake::{ExtendableOutput, Update, XofReader};
    let mut h = shake::Shake256::default();
    h.update(seed);
    let mut out = vec![0u8; n];
    h.finalize_xof().read(&mut out);
    out
}

pub const SEAL: &[u8] = b"CATLAN-CIFRADO-1";

/// Cifra con contraseña: PBKDF2-SHA256 → flujo SHAKE-256 y HMAC-SHA256 (cifrar y luego autenticar).
/// Mismo formato que la versión en Python: las copias de antes se siguen abriendo.
pub fn seal(data: &[u8], pw: &str) -> Vec<u8> {
    let (salt, nonce) = (rand_bytes(16), rand_bytes(16));
    let k = pbkdf2(pw.as_bytes(), &salt, 64);
    let mut out = [SEAL, &salt, &nonce].concat();
    let stream = shake256(&[&k[..32], &nonce].concat(), data.len());
    out.extend(data.iter().zip(&stream).map(|(a, b)| a ^ b));
    let tag = hmac_sha256(&k[32..], &out);
    out.extend(tag);
    out
}

pub fn unseal(blob: &[u8], pw: &str) -> Result<Vec<u8>, Bad> {
    if !blob.starts_with(SEAL) || blob.len() < SEAL.len() + 64 {
        return Err(Bad("no es una copia cifrada de catlan".into()));
    }
    let (salt, nonce, ct, tag) = (&blob[16..32], &blob[32..48], &blob[48..blob.len() - 32], &blob[blob.len() - 32..]);
    let k = pbkdf2(pw.as_bytes(), salt, 64);
    if !ct_eq(tag, &hmac_sha256(&k[32..], &blob[..blob.len() - 32])) {
        return Err(Bad("contraseña incorrecta o copia dañada".into()));
    }
    let stream = shake256(&[&k[..32], nonce].concat(), ct.len());
    Ok(ct.iter().zip(&stream).map(|(a, b)| a ^ b).collect())
}

/// Código de 6 cifras de la app de autenticación (RFC 6238: HMAC-SHA1, 30 s) para un secreto en base32.
pub fn totp(secret: &str, t: f64) -> Option<String> {
    let key = data_encoding::BASE32.decode(secret.as_bytes()).ok()?;
    let mut m = <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(&key).ok()?;
    m.update(&((t / 30.0).floor() as u64).to_be_bytes());
    let mac = m.finalize().into_bytes();
    let o = (mac[mac.len() - 1] & 15) as usize;
    let n = u32::from_be_bytes([mac[o], mac[o + 1], mac[o + 2], mac[o + 3]]) & 0x7FFF_FFFF;
    Some(format!("{:06}", n % 1_000_000))
}

/// Vale el código de ahora y el de 30 s antes o después (relojes un poco desfasados).
pub fn totp_ok(secret: &str, code: &str) -> bool {
    let code: String = code.trim().replace(' ', "");
    let now = crate::util::now();
    !secret.is_empty() && [-30.0, 0.0, 30.0].iter().any(|d| totp(secret, now + d).is_some_and(|c| ct_eq(c.as_bytes(), code.as_bytes())))
}

// ── SNMPv3 (USM: RFC 3414, 3826 y 7860) ──

/// Algoritmo de autenticación de SNMPv3 -> bytes de la firma.
pub fn auth_len(proto: &str) -> Option<usize> {
    Some(match proto {
        "md5" | "sha" => 12,
        "sha224" => 16,
        "sha256" => 24,
        "sha384" => 32,
        "sha512" => 48,
        _ => return None,
    })
}

pub fn hash(proto: &str, data: &[u8]) -> Vec<u8> {
    match proto {
        "md5" => md5::Md5::digest(data).to_vec(),
        "sha" => sha1::Sha1::digest(data).to_vec(),
        "sha224" => sha2::Sha224::digest(data).to_vec(),
        "sha384" => sha2::Sha384::digest(data).to_vec(),
        "sha512" => sha2::Sha512::digest(data).to_vec(),
        _ => sha2::Sha256::digest(data).to_vec(),
    }
}

pub fn hmac(proto: &str, key: &[u8], msg: &[u8]) -> Vec<u8> {
    fn run<M: Mac + KeyInit>(key: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut m = <M as KeyInit>::new_from_slice(key).expect("HMAC admite cualquier clave");
        m.update(msg);
        m.finalize().into_bytes().to_vec()
    }
    match proto {
        "md5" => run::<Hmac<md5::Md5>>(key, msg),
        "sha" => run::<Hmac<sha1::Sha1>>(key, msg),
        "sha224" => run::<Hmac<sha2::Sha224>>(key, msg),
        "sha384" => run::<Hmac<sha2::Sha384>>(key, msg),
        "sha512" => run::<Hmac<sha2::Sha512>>(key, msg),
        _ => run::<Hmac<sha2::Sha256>>(key, msg),
    }
}

/// Clave localizada: la contraseña repetida hasta 1 MB, resumida, y mezclada con el engineID del equipo.
pub fn usm_key(proto: &str, password: &str, engine: &[u8]) -> Vec<u8> {
    let p = password.as_bytes();
    let long: Vec<u8> = p.iter().copied().cycle().take(if p.is_empty() { 0 } else { 1 << 20 }).collect();
    let ku = hash(proto, &long);
    hash(proto, &[&ku[..], engine, &ku[..]].concat())
}

pub fn aes_block(key: &[u8], block: &[u8; 16]) -> [u8; 16] {
    let c = aes::Aes128::new_from_slice(key).expect("clave AES de 16 bytes");
    let mut b = aes::Block::from(*block);
    c.encrypt_block(&mut b);
    b.into()
}

/// AES-128 en modo CFB de 128 bits (RFC 3826).
pub fn aes_cfb(key: &[u8], iv: &[u8], data: &[u8], encrypt: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut prev: [u8; 16] = iv.try_into().expect("IV de 16 bytes");
    for chunk in data.chunks(16) {
        let ks = aes_block(key, &prev);
        let o: Vec<u8> = chunk.iter().zip(ks).map(|(a, b)| a ^ b).collect();
        let fb = if encrypt { &o[..] } else { chunk };
        prev[..fb.len()].copy_from_slice(fb);
        out.extend(o);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_vectores_oficiales() {
        // FIPS-197 y NIST SP 800-38A
        let k: Vec<u8> = (0..16).collect();
        assert_eq!(hex(&aes_block(&k, &unhex("00112233445566778899aabbccddeeff").unwrap().try_into().unwrap())), "69c4e0d86a7b0430d8cdb78070b4c55a");
        let (k, iv): (Vec<u8>, Vec<u8>) = (unhex("2b7e151628aed2a6abf7158809cf4f3c").unwrap(), (0..16).collect());
        let pt = unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51").unwrap();
        assert_eq!(hex(&aes_cfb(&k, &iv, &pt, true)), "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b");
        assert_eq!(aes_cfb(&k, &iv, &aes_cfb(&k, &iv, &pt[..20], true), false), pt[..20]); // bloque final incompleto
    }

    #[test]
    fn claves_usm_rfc3414() {
        let e = unhex("000000000000000000000002").unwrap();
        assert_eq!(hex(&usm_key("md5", "maplesyrup", &e)), "526f5eed9fcce26f8964c2930787d82b");
        assert_eq!(hex(&usm_key("sha", "maplesyrup", &e)), "6695febc9288e36282235fc7151f128497b38f3f");
    }

    #[test]
    fn totp_rfc6238() {
        let s = data_encoding::BASE32.encode(b"12345678901234567890");
        assert_eq!(totp(&s, 59.0).unwrap(), "287082");
        assert!(totp_ok(&s, &totp(&s, crate::util::now()).unwrap()) && !totp_ok("", "123456"));
    }

    #[test]
    fn copias_cifradas() {
        let blob = seal(b"SQLite format 3\0datos", "copia-segura");
        assert!(blob.starts_with(SEAL) && unseal(&blob, "copia-segura").unwrap() == b"SQLite format 3\0datos");
        assert!(unseal(&blob, "otra-clave").is_err());
        let mut roto = blob.clone();
        let n = roto.len() - 40;
        roto[n] ^= 1;
        assert!(unseal(&roto, "copia-segura").is_err() && unseal(b"SQLite", "x").is_err());
        assert_eq!(unseal(&seal(b"", "xxxxxxxx"), "xxxxxxxx").unwrap(), b"");
    }

    #[test]
    fn contrasenas() {
        let h = pw_hash("miau-miau", None);
        assert!(h.starts_with("pbkdf2$") && pw_ok("miau-miau", &h) && !pw_ok("otra", &h) && !pw_ok("x", "roto"));
    }
}
