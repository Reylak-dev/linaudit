//! category: ssh — port de checks.d/20-ssh.sh.
//! Configuración efectiva de OpenSSH (`sshd -T`). Si `sshd -T` no funciona (típicamente sin root),
//! cae a un parseo estático de los archivos, sin defaults y sin bloques Match.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf};

use super::Context;
use super::util::{check_file_perm, command_output, file_mode, find_command, glob, mode_within};
use crate::model::{Emitter, ResultExt, Severity::{self, *}};
use crate::tr;

/// Anidamiento máximo de `Include` (sshd aborta a partir de 16).
const MAX_INCLUDE_DEPTH: u32 = 16;
/// Archivos distintos que se procesan como mucho en el parseo estático.
const MAX_CONFIG_FILES: usize = 256;
/// Tamaño máximo de un archivo de config; uno mayor se omite (y el parseo queda incompleto).
const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// Configuración de sshd: clave en minúsculas -> valor.
#[derive(Debug, Default, Clone)]
pub struct SshdConfig {
    values: HashMap<String, String>,
    /// true si salió del parseo estático (sin defaults de sshd ni Match).
    pub is_static: bool,
    /// Archivos presentes que el parseo estático no pudo leer (ruta del sistema auditado y motivo).
    /// Si no está vacío, el parseo es incompleto: ver `indeterminate`.
    skipped: Vec<String>,
    /// Claves cuya primera aparición se leyó DESPUÉS de omitir un archivo: el omitido se lee antes
    /// en sshd y pudo fijarlas primero, así que su valor no es de fiar.
    uncertain: HashSet<String>,
}

impl SshdConfig {
    /// Salida de `sshd -T`: una línea `clave valor` por opción, claves ya en minúsculas.
    pub fn from_sshd_t(out: &str) -> Self {
        let mut values = HashMap::new();
        for line in out.lines() {
            let mut it = line.splitn(2, ' ');
            if let (Some(k), Some(v)) = (it.next(), it.next()) {
                values.entry(k.to_ascii_lowercase()).or_insert_with(|| v.trim().to_string());
            }
        }
        SshdConfig { values, is_static: false, ..Default::default() }
    }

    /// Parseo estático desde /etc/ssh/sshd_config, como lo lee sshd: gana el primer valor obtenido
    /// de cada clave y cada `Include` se expande EN SU POSICIÓN, así que un drop-in sólo gana si el
    /// `Include` aparece antes que el ajuste. Un `Match` corta el resto del archivo en que aparece;
    /// en un drop-in, al volver del `Include` se sigue con el archivo que lo incluyó (sshd restaura
    /// el estado de Match al terminar cada include).
    pub fn from_static(ctx: &Context) -> Self {
        let mut p = StaticParse {
            root: std::fs::canonicalize(&ctx.fs_root).unwrap_or_else(|_| ctx.fs_root.clone()),
            cfg: SshdConfig { is_static: true, ..Default::default() },
            visited: HashSet::new(),
        };
        p.include_file(Path::new("/etc/ssh/sshd_config"), 0);
        p.cfg
    }

    fn lookup(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str).filter(|v| !v.is_empty())
    }

    pub fn get<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.lookup(key).unwrap_or(default)
    }

    /// true si el parseo quedó incompleto y el valor de `key` no es fiable: o falta (caería a un
    /// default que un archivo omitido pudo cambiar) o se fijó después de la omisión.
    fn indeterminate(&self, key: &str) -> bool {
        !self.skipped.is_empty() && (self.lookup(key).is_none() || self.uncertain.contains(key))
    }

    /// Los primeros archivos omitidos, para el detalle (una lista hostil podría ser enorme).
    fn skipped_summary(&self) -> String {
        let mut s = self.skipped.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
        if self.skipped.len() > 3 {
            s.push_str(&format!(" (+{})", self.skipped.len() - 3));
        }
        s
    }

    fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// Estado del parseo estático. Las rutas se interpretan dentro de `root` como en un chroot
/// (symlinks absolutos y `..` incluidos), así que una config hostil en una imagen offline no puede
/// hacer leer archivos fuera del árbol auditado.
struct StaticParse {
    root: PathBuf,
    cfg: SshdConfig,
    /// Archivos ya procesados: re-incluir uno no cambia nada (gana el primer valor) y así se cortan
    /// ciclos y fan-outs.
    visited: HashSet<PathBuf>,
}

impl StaticParse {
    fn skip(&mut self, path: &Path, why: &str) {
        self.cfg.skipped.push(format!("{} ({why})", path.display()));
    }

    /// Procesa el texto de un archivo. Termina en el primer `Match`: lo que sigue es condicional.
    fn ingest(&mut self, text: &str, depth: u32) {
        for line in text.lines() {
            let mut words = line.split_whitespace();
            let Some(k) = words.next() else { continue };
            if k.starts_with('#') {
                continue;
            }
            let k = k.to_ascii_lowercase();
            match k.as_str() {
                "match" => return,
                "include" => {
                    for pattern in words {
                        self.include(pattern, depth);
                    }
                }
                _ => {
                    if !self.cfg.values.contains_key(&k) {
                        if !self.cfg.skipped.is_empty() {
                            self.cfg.uncertain.insert(k.clone());
                        }
                        self.cfg.values.insert(k, words.collect::<Vec<_>>().join(" "));
                    }
                }
            }
        }
    }

    /// Expande un patrón `Include` (relativo a /etc/ssh, como en sshd) en orden léxico.
    fn include(&mut self, pattern: &str, depth: u32) {
        let abs = if pattern.starts_with('/') { PathBuf::from(pattern) } else { Path::new("/etc/ssh").join(pattern) };
        let is_glob = |s: &str| s.contains(['*', '?', '[']);
        let (Some(dir), Some(name)) = (abs.parent(), abs.file_name().map(|n| n.to_string_lossy().into_owned())) else {
            return;
        };
        if is_glob(&dir.to_string_lossy()) || name.contains('[') {
            // Forma de glob que no sabemos expandir: no se puede saber qué archivos leería sshd.
            self.skip(&abs, "unsupported glob");
            return;
        }
        if !is_glob(&name) {
            // Un objetivo literal inexistente no es un error en sshd; uno que existe pero no se
            // puede alcanzar (permisos, bucle de symlinks) sí deja el parseo incompleto.
            match resolve_in_root(&self.root, &abs) {
                Ok(_) => self.include_file(&abs, depth + 1),
                Err(e) if is_missing(&e) => {}
                Err(e) => self.skip(&abs, unreadable_reason(&e)),
            }
            return;
        }
        // Un directorio de drop-ins inexistente equivale a un glob sin coincidencias; uno que no se
        // puede listar NO: sshd sí lo lee, y tratarlo como vacío daría PASS por defaults.
        let host_dir = match resolve_in_root(&self.root, dir) {
            Ok(d) => d,
            Err(e) if is_missing(&e) => return,
            Err(e) => return self.skip(dir, unreadable_reason(&e)),
        };
        let entries = match std::fs::read_dir(&host_dir) {
            Ok(d) => d,
            Err(e) if is_missing(&e) => return,
            Err(e) => return self.skip(dir, unreadable_reason(&e)),
        };
        let mut names = Vec::new();
        for entry in entries {
            match entry {
                Ok(e) => {
                    let n = e.file_name().to_string_lossy().into_owned();
                    if glob_match(&name, &n) {
                        names.push(n);
                    }
                }
                // Listado cortado a la mitad: no se sabe qué archivos faltan.
                Err(e) => return self.skip(dir, unreadable_reason(&e)),
            }
        }
        names.sort();
        for n in names {
            self.include_file(&dir.join(n), depth + 1);
        }
    }

    /// Lee y procesa un archivo (ruta del sistema auditado). Todo archivo presente que no se pueda
    /// procesar queda registrado en `skipped`: nunca se ignora en silencio.
    fn include_file(&mut self, abs: &Path, depth: u32) {
        if depth > MAX_INCLUDE_DEPTH {
            return self.skip(abs, "include nesting too deep");
        }
        let host = match resolve_in_root(&self.root, abs) {
            Ok(h) => h,
            // sshd_config ausente o ilegible: config vacía (lo reporta `run` como SSH-000).
            Err(_) if depth == 0 => return,
            // Un glob que casa un symlink roto sí es un archivo que sshd intentaría leer.
            Err(e) => return self.skip(abs, unreadable_reason(&e)),
        };
        if !self.visited.insert(host.clone()) {
            return;
        }
        if self.visited.len() > MAX_CONFIG_FILES {
            return self.skip(abs, "too many files");
        }
        match std::fs::metadata(&host) {
            Ok(m) if m.is_file() && m.len() <= MAX_FILE_BYTES => match std::fs::read_to_string(&host) {
                Ok(text) => self.ingest(&text, depth),
                Err(e) => self.skip(abs, unreadable_reason(&e)),
            },
            Ok(m) if m.is_file() => self.skip(abs, "too large"),
            _ => self.skip(abs, "not a regular file"),
        }
    }
}

/// Resuelve `abs` (ruta del sistema auditado) a una ruta real bajo `root`, siguiendo symlinks como
/// en un chroot: un destino absoluto se toma relativo a `root` y `..` no sube de `root`. Devuelve
/// error si algún componente no existe (ver `is_missing`), no se puede examinar (permisos) o hay
/// demasiados saltos de symlink.
fn resolve_in_root(root: &Path, abs: &Path) -> io::Result<PathBuf> {
    fn push_components(stack: &mut Vec<OsString>, p: &Path) {
        for c in p.components().rev() {
            match c {
                Component::Normal(s) => stack.push(s.to_os_string()),
                Component::ParentDir => stack.push("..".into()),
                _ => {}
            }
        }
    }
    let mut pending = Vec::new();
    push_components(&mut pending, abs);
    let mut cur = PathBuf::new();
    let mut hops = 0;
    while let Some(c) = pending.pop() {
        if c == ".." {
            cur.pop();
            continue;
        }
        let next = cur.join(&c);
        let meta = std::fs::symlink_metadata(root.join(&next))?;
        if meta.file_type().is_symlink() {
            hops += 1;
            if hops > 40 {
                return Err(io::Error::other("too many levels of symbolic links"));
            }
            let target = std::fs::read_link(root.join(&next))?;
            if target.is_absolute() {
                cur = PathBuf::new();
            }
            push_components(&mut pending, &target);
        } else {
            cur = next;
        }
    }
    Ok(root.join(cur))
}

/// La ruta no existe (o un componente intermedio no es un directorio): para sshd es lo mismo que
/// un glob sin coincidencias, no un archivo omitido.
fn is_missing(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory)
}

/// Motivo corto para `skipped`.
fn unreadable_reason(e: &io::Error) -> &'static str {
    match e.kind() {
        io::ErrorKind::PermissionDenied => "permission denied",
        _ => "unreadable",
    }
}

/// Glob de un componente con `*` y `?`. Como glob(3), un comodín no casa un `.` inicial.
fn glob_match(pattern: &str, name: &str) -> bool {
    if name.starts_with('.') && !pattern.starts_with('.') {
        return false;
    }
    // Backtracking al último `*`: lineal en la práctica, sin explosión con patrones hostiles.
    let (p, n) = (pattern.as_bytes(), name.as_bytes());
    let (mut i, mut j, mut star, mut mark) = (0, 0, None, 0);
    while j < n.len() {
        if i < p.len() && (p[i] == b'?' || p[i] == n[j]) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == b'*' {
            star = Some(i);
            mark = j;
            i += 1;
        } else if let Some(s) = star {
            i = s + 1;
            mark += 1;
            j = mark;
        } else {
            return false;
        }
    }
    p[i..].iter().all(|&c| c == b'*')
}

pub fn run(ctx: &Context, em: &mut Emitter) {
    let sshd = if ctx.is_live() {
        find_command("sshd")
    } else {
        Some(ctx.path("/usr/sbin/sshd")).filter(|p| p.exists())
    };
    let Some(sshd) = sshd else {
        em.na("SSH-000", Info, tr!("OpenSSH server")).with_detail(tr!("sshd is not installed"));
        return;
    };

    let from_t = if ctx.is_live() { command_output(&sshd, &["-T"]).map(|o| SshdConfig::from_sshd_t(&o)) } else { None };
    let cfg = match from_t {
        Some(c) if !c.is_empty() => c,
        _ => {
            let c = SshdConfig::from_static(ctx);
            if c.is_empty() {
                em.error("SSH-000", High, tr!("sshd configuration"))
                    .with_detail(tr!("could not read or evaluate the configuration (not root?)"));
                return;
            }
            c
        }
    };

    evaluate_config(em, &cfg);
    check_match_blocks(ctx, em);
    check_files(ctx, em);
}

/// Valor de `key` para un control. Si el parseo estático quedó incompleto y el valor no es fiable,
/// emite el control como WARN indeterminado y devuelve `None`: un default nunca da un PASS falso.
fn value<'a>(em: &mut Emitter, cfg: &'a SshdConfig, id: &str, sev: Severity, key: &str, default: &'a str) -> Option<&'a str> {
    if cfg.indeterminate(key) {
        em.warn(id, sev, tr!("Setting could not be determined"))
            .with_detail(tr!("{key}: skipped config files: {files}", key = key, files = cfg.skipped_summary()))
            .with_fix(tr!("Review the skipped files; the static parse cannot tell which value sshd uses"));
        return None;
    }
    Some(cfg.get(key, default))
}

/// SSH-001..009, 011..013: opciones de la configuración efectiva.
pub fn evaluate_config(em: &mut Emitter, cfg: &SshdConfig) {
    let note = if cfg.is_static { tr!(" (static config, no defaults: sshd -T unavailable)") } else { "" };

    if let Some(v) = value(em, cfg, "SSH-001", High, "permitrootlogin", "prohibit-password") {
        match v {
            "no" => {
                em.pass("SSH-001", High, tr!("Direct root login disabled"));
            }
            "prohibit-password" | "without-password" | "forced-commands-only" => {
                em.warn("SSH-001", High, tr!("Root can log in over SSH with a key only"))
                    .with_detail(format!("PermitRootLogin {v}{note}"))
                    .with_fix(tr!("PermitRootLogin no and use sudo"));
            }
            _ => {
                em.fail("SSH-001", High, tr!("Root can log in over SSH with a password"))
                    .with_detail(format!("PermitRootLogin {v}{note}"))
                    .with_fix("PermitRootLogin no");
            }
        }
    }

    if let Some(v) = value(em, cfg, "SSH-002", Medium, "passwordauthentication", "yes") {
        if v == "no" {
            em.pass("SSH-002", Medium, tr!("Password authentication disabled"));
        } else {
            em.fail("SSH-002", Medium, tr!("SSH accepts password authentication"))
                .with_detail(format!("PasswordAuthentication {v}{note}"))
                .with_fix(tr!("Use keys (or a waiver if there is SSO/IPA)"));
        }
    }

    if let Some(v) = value(em, cfg, "SSH-003", Critical, "permitemptypasswords", "no") {
        if v == "no" {
            em.pass("SSH-003", Critical, tr!("PermitEmptyPasswords disabled"));
        } else {
            em.fail("SSH-003", Critical, tr!("SSH allows empty passwords"))
                .with_detail(format!("PermitEmptyPasswords {v}"))
                .with_fix("PermitEmptyPasswords no");
        }
    }

    if let Some(v) = value(em, cfg, "SSH-004", Low, "maxauthtries", "6") {
        if v.parse::<i64>().is_ok_and(|n| n <= 6) {
            em.pass("SSH-004", Low, tr!("MaxAuthTries is reasonable")).with_detail(format!("MaxAuthTries {v}"));
        } else {
            em.warn("SSH-004", Low, tr!("MaxAuthTries is high")).with_detail(format!("MaxAuthTries {v}")).with_fix("MaxAuthTries 4");
        }
    }

    if let Some(v) = value(em, cfg, "SSH-005", Low, "x11forwarding", "no") {
        if v == "no" {
            em.pass("SSH-005", Low, tr!("X11Forwarding disabled"));
        } else {
            em.warn("SSH-005", Low, tr!("X11Forwarding enabled"))
                .with_detail(format!("X11Forwarding {v}{note}"))
                .with_fix("X11Forwarding no");
        }
    }

    if cfg.is_static {
        em.na("SSH-006", Medium, tr!("Weak cryptographic algorithms")).with_detail(tr!("requires sshd -T"));
    } else {
        let weak = |key: &str, is_weak: fn(&str) -> bool| {
            cfg.get(key, "").split(',').filter(|a| is_weak(a)).collect::<Vec<_>>().join(",")
        };
        let c = weak("ciphers", |a| {
            ["3des", "arcfour", "blowfish", "cast128"].iter().any(|w| a.contains(w)) || a.ends_with("-cbc")
        });
        let m = weak("macs", |a| a.starts_with("hmac-md5") || a.starts_with("umac-64") || a.contains("hmac-sha1-96"));
        let k = weak("kexalgorithms", |a| {
            ["group1-sha1", "group14-sha1", "group-exchange-sha1"].iter().any(|w| a.contains(w))
        });
        if c.is_empty() && m.is_empty() && k.is_empty() {
            em.pass("SSH-006", Medium, tr!("No weak cryptographic algorithms"));
        } else {
            let mut d = Vec::new();
            if !c.is_empty() {
                d.push(format!("ciphers: {c}"));
            }
            if !m.is_empty() {
                d.push(format!("macs: {m}"));
            }
            if !k.is_empty() {
                d.push(format!("kex: {k}"));
            }
            em.fail("SSH-006", Medium, tr!("Weak SSH algorithms enabled"))
                .with_detail(d.join(" "))
                .with_fix(tr!("Set explicit Ciphers/MACs/KexAlgorithms (e.g. crypto-policies on RHEL)"));
        }
    }

    if let Some(v) = value(em, cfg, "SSH-007", Low, "logingracetime", "120") {
        let v = v.strip_suffix('s').unwrap_or(v);
        if v.parse::<i64>().is_ok_and(|n| n <= 60) {
            em.pass("SSH-007", Low, "LoginGraceTime <= 60s").with_detail(format!("{v} s"));
        } else {
            em.warn("SSH-007", Low, tr!("LoginGraceTime is high")).with_detail(format!("{v}s")).with_fix("LoginGraceTime 30");
        }
    }

    if let Some(v) = value(em, cfg, "SSH-008", Low, "clientaliveinterval", "0") {
        if v.parse::<i64>().is_ok_and(|n| n > 0) {
            em.pass("SSH-008", Low, tr!("Idle session timeout")).with_detail(format!("ClientAliveInterval {v}"));
        } else {
            em.warn("SSH-008", Low, tr!("No timeout for idle SSH sessions"))
                .with_detail(format!("ClientAliveInterval {v}"))
                .with_fix(tr!("ClientAliveInterval 300 / ClientAliveCountMax 0 (or TMOUT)"));
        }
    }

    if let Some(v) = value(em, cfg, "SSH-009", Medium, "gatewayports", "no") {
        if v == "no" {
            em.pass("SSH-009", Medium, tr!("GatewayPorts disabled"));
        } else {
            em.warn("SSH-009", Medium, tr!("GatewayPorts enabled")).with_detail(format!("GatewayPorts {v}")).with_fix("GatewayPorts no");
        }
    }

    if let Some(v) = value(em, cfg, "SSH-011", Low, "banner", "none") {
        if v != "none" {
            em.pass("SSH-011", Low, tr!("Legal banner configured")).with_detail(v);
        } else {
            em.warn("SSH-011", Low, tr!("No legal banner on SSH"))
                .with_detail("Banner none")
                .with_fix(tr!("Set Banner /etc/issue.net"));
        }
    }

    if let Some(v) = value(em, cfg, "SSH-012", High, "hostbasedauthentication", "no") {
        if v == "no" {
            em.pass("SSH-012", High, tr!("HostbasedAuthentication disabled"));
        } else {
            em.fail("SSH-012", High, tr!("HostbasedAuthentication enabled")).with_detail(v).with_fix("HostbasedAuthentication no");
        }
    }

    if let Some(v) = value(em, cfg, "SSH-013", Medium, "permituserenvironment", "no") {
        if v == "no" {
            em.pass("SSH-013", Medium, tr!("PermitUserEnvironment disabled"));
        } else {
            em.fail("SSH-013", Medium, tr!("PermitUserEnvironment enabled")).with_detail(v).with_fix("PermitUserEnvironment no");
        }
    }
}

/// Líneas dentro de bloques Match que reabren root o passwords vacíos.
pub fn weakening_match_lines(file: &str, text: &str) -> Vec<String> {
    let mut in_match = false;
    let mut out = Vec::new();
    for line in text.lines() {
        let mut w = line.split_whitespace();
        let Some(k) = w.next().map(str::to_ascii_lowercase) else { continue };
        if k == "match" {
            in_match = true;
            continue;
        }
        let v = w.next().unwrap_or("").to_ascii_lowercase();
        if in_match && (k == "permitrootlogin" || k == "permitemptypasswords") && v == "yes" {
            out.push(format!("{file}: {line}"));
        }
    }
    out
}

/// SSH-010
fn check_match_blocks(ctx: &Context, em: &mut Emitter) {
    let mut files = vec!["/etc/ssh/sshd_config".to_string()];
    files.extend(
        glob(&ctx.path("/etc/ssh/sshd_config.d"), "", ".conf")
            .iter()
            .filter_map(|p| p.file_name().map(|n| format!("/etc/ssh/sshd_config.d/{}", n.to_string_lossy()))),
    );
    let found: Vec<String> = files
        .iter()
        .filter_map(|f| std::fs::read_to_string(ctx.path(f)).ok().map(|t| weakening_match_lines(f, &t)))
        .flatten()
        .collect();
    if found.is_empty() {
        em.pass("SSH-010", Medium, tr!("No Match block re-enables root/empty passwords"));
    } else {
        em.fail("SSH-010", Medium, tr!("Match block weakens security"))
            .with_detail(found.join(" "))
            .with_fix(tr!("Review the Match blocks"));
    }
}

/// SSH-014..016: permisos y claves de host.
fn check_files(ctx: &Context, em: &mut Emitter) {
    check_file_perm(em, ctx, "SSH-014", Medium, tr!("sshd_config permissions"), "/etc/ssh/sshd_config", 0o644, Some(0));

    let bad: Vec<String> = glob(&ctx.path("/etc/ssh"), "ssh_host_", "_key")
        .iter()
        .filter_map(|p| {
            let m = file_mode(p)?;
            (!mode_within(m, 0o640)).then(|| {
                let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                format!("/etc/ssh/{name}({m:o})")
            })
        })
        .collect();
    if bad.is_empty() {
        em.pass("SSH-015", High, tr!("Host private keys have correct permissions"));
    } else {
        em.fail("SSH-015", High, tr!("Host private keys readable by others"))
            .with_detail(bad.join(" "))
            .with_fix("chmod 600 /etc/ssh/ssh_host_*_key");
    }

    if ctx.path("/etc/ssh/ssh_host_dsa_key").exists() {
        em.warn("SSH-016", Medium, tr!("DSA host key present (obsolete)"))
            .with_detail("/etc/ssh/ssh_host_dsa_key")
            .with_fix(tr!("Remove it and drop the DSA HostKey"));
    } else {
        em.pass("SSH-016", Medium, tr!("No DSA host key"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::fixture::Fixture;
    use crate::model::{CheckResult, Status};

    fn eval(cfg: &SshdConfig) -> HashMap<String, CheckResult> {
        let mut em = Emitter::new("ssh");
        evaluate_config(&mut em, cfg);
        em.into_results().into_iter().map(|r| (r.id.clone(), r)).collect()
    }

    #[test]
    fn defaults_de_sshd_t_endurecido() {
        let out = "permitrootlogin no\npasswordauthentication no\npermitemptypasswords no\nmaxauthtries 3\n\
                   x11forwarding no\nciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n\
                   macs hmac-sha2-256-etm@openssh.com\nkexalgorithms curve25519-sha256\nlogingracetime 30\n\
                   clientaliveinterval 300\ngatewayports no\nbanner /etc/issue.net\nhostbasedauthentication no\n\
                   permituserenvironment no\n";
        let r = eval(&SshdConfig::from_sshd_t(out));
        for (id, res) in &r {
            assert_eq!(res.status, Status::Pass, "{id}: {res:?}");
        }
        assert_eq!(r.len(), 12); // 001..009 y 011..013 (010 y 014..016 leen archivos)
    }

    #[test]
    fn detecta_algoritmos_debiles_y_root_con_password() {
        let out = "permitrootlogin yes\nciphers aes128-ctr,aes256-cbc,3des-cbc\nmacs hmac-md5,hmac-sha2-256\n\
                   kexalgorithms diffie-hellman-group14-sha1\n";
        let r = eval(&SshdConfig::from_sshd_t(out));
        assert_eq!(r["SSH-001"].status, Status::Fail);
        assert_eq!(r["SSH-006"].status, Status::Fail);
        assert_eq!(r["SSH-006"].detail, "ciphers: aes256-cbc,3des-cbc macs: hmac-md5 kex: diffie-hellman-group14-sha1");
    }

    fn static_cfg(files: &[(&str, &str)]) -> SshdConfig {
        let fx = Fixture::new();
        for (path, text) in files {
            fx.file(path, text);
        }
        SshdConfig::from_static(&fx.ctx())
    }

    #[test]
    fn parseo_estatico_respeta_primera_aparicion_y_corta_en_match() {
        let cfg = static_cfg(&[
            (
                "/etc/ssh/sshd_config",
                "Include /etc/ssh/sshd_config.d/*.conf\n# comentario\nPasswordAuthentication yes\n\
                 PermitRootLogin no\nMatch User x\nPermitRootLogin yes\n",
            ),
            ("/etc/ssh/sshd_config.d/10-x.conf", "PasswordAuthentication no\n"),
        ]);
        assert!(cfg.is_static);
        assert_eq!(cfg.get("passwordauthentication", "?"), "no");
        assert_eq!(cfg.get("permitrootlogin", "?"), "no");
        let r = eval(&cfg);
        assert_eq!(r["SSH-006"].status, Status::Na);
        // sin defaults: X11Forwarding usa el default asumido y no lleva nota
        assert_eq!(r["SSH-005"].status, Status::Pass);
    }

    #[test]
    fn ajuste_antes_del_include_gana_sobre_el_dropin() {
        let cfg = static_cfg(&[
            ("/etc/ssh/sshd_config", "PasswordAuthentication no\nInclude sshd_config.d/*.conf\nPermitRootLogin no\n"),
            ("/etc/ssh/sshd_config.d/10-a.conf", "PasswordAuthentication yes\nPermitRootLogin yes\n"),
        ]);
        // El principal fijó PasswordAuthentication antes del Include; PermitRootLogin, después.
        assert_eq!(cfg.get("passwordauthentication", "?"), "no");
        assert_eq!(cfg.get("permitrootlogin", "?"), "yes");
    }

    #[test]
    fn dropins_en_orden_lexico_y_match_en_dropin_no_corta_el_principal() {
        let cfg = static_cfg(&[
            ("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nX11Forwarding no\n"),
            ("/etc/ssh/sshd_config.d/20-b.conf", "MaxAuthTries 9\n"),
            ("/etc/ssh/sshd_config.d/10-a.conf", "MaxAuthTries 3\nMatch User x\nBanner /x\n"),
            ("/etc/ssh/sshd_config.d/.oculto.conf", "MaxAuthTries 1\n"),
            ("/etc/ssh/sshd_config.d/30-c.disabled", "GatewayPorts yes\n"),
        ]);
        assert_eq!(cfg.get("maxauthtries", "?"), "3");
        assert_eq!(cfg.get("banner", "none"), "none");
        assert_eq!(cfg.get("x11forwarding", "?"), "no");
        assert_eq!(cfg.get("gatewayports", "no"), "no");
        assert!(cfg.skipped.is_empty());
    }

    #[test]
    fn include_ciclico_termina() {
        let cfg = static_cfg(&[
            ("/etc/ssh/sshd_config", "Include /etc/ssh/a.conf\nPermitRootLogin no\n"),
            ("/etc/ssh/a.conf", "Include /etc/ssh/a.conf /etc/ssh/sshd_config\nX11Forwarding no\n"),
        ]);
        assert_eq!(cfg.get("permitrootlogin", "?"), "no");
        assert_eq!(cfg.get("x11forwarding", "?"), "no");
        assert!(cfg.skipped.is_empty());
    }

    #[test]
    fn symlinks_absolutos_se_resuelven_dentro_del_arbol_auditado() {
        use std::os::unix::fs::symlink;
        let fx = Fixture::new();
        fx.file("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n");
        fx.file("/opt/ssh/real.conf", "PermitRootLogin no\n");
        fx.dir("/etc/ssh/sshd_config.d");
        let ctx = fx.ctx();
        symlink("/opt/ssh/real.conf", ctx.path("/etc/ssh/sshd_config.d/10-link.conf")).unwrap();
        // Apunta a /etc/passwd "del árbol" (que no existe en el fixture), nunca al del host.
        symlink("../../../../../../etc/passwd", ctx.path("/etc/ssh/sshd_config.d/20-escape.conf")).unwrap();
        let cfg = SshdConfig::from_static(&ctx);
        assert_eq!(cfg.get("permitrootlogin", "?"), "no");
        assert_eq!(cfg.skipped.len(), 1, "{:?}", cfg.skipped);
    }

    #[test]
    fn dropin_omitido_no_da_pass_falso() {
        let big = format!("PermitEmptyPasswords yes\n{}", "#\n".repeat(MAX_FILE_BYTES as usize));
        let cfg = static_cfg(&[
            ("/etc/ssh/sshd_config", "PasswordAuthentication no\nInclude /etc/ssh/sshd_config.d/*.conf\nX11Forwarding no\n"),
            ("/etc/ssh/sshd_config.d/10-big.conf", &big),
        ]);
        assert_eq!(cfg.skipped.len(), 1);
        let r = eval(&cfg);
        // Ausente: caería al default "no" -> indeterminado.
        assert_eq!(r["SSH-003"].status, Status::Warn);
        // Fijado después del archivo omitido, que sshd lee antes -> indeterminado.
        assert_eq!(r["SSH-005"].status, Status::Warn);
        // Fijado antes de la omisión: sigue siendo autoritativo.
        assert_eq!(r["SSH-002"].status, Status::Pass);
    }

    /// Corre el parseo estático con `dir` sin permisos (0o000) y lo restaura antes de volver, para
    /// que el fixture se pueda borrar. `None` si se corre como root (los permisos no aplican).
    fn static_cfg_with_locked_dir(files: &[(&str, &str)], dir: &str) -> Option<SshdConfig> {
        let fx = Fixture::new();
        for (path, text) in files {
            fx.file(path, text);
        }
        fx.mode(dir, 0o000);
        let ctx = fx.ctx();
        let cfg = if std::fs::read_dir(ctx.path(dir)).is_ok() { None } else { Some(SshdConfig::from_static(&ctx)) };
        fx.mode(dir, 0o755);
        cfg
    }

    #[test]
    fn directorio_de_dropins_ilegible_no_da_pass_falso() {
        let Some(cfg) = static_cfg_with_locked_dir(
            &[
                ("/etc/ssh/sshd_config", "PasswordAuthentication no\nInclude /etc/ssh/sshd_config.d/*.conf\nX11Forwarding no\n"),
                ("/etc/ssh/sshd_config.d/10-a.conf", "PermitEmptyPasswords yes\nX11Forwarding yes\n"),
            ],
            "/etc/ssh/sshd_config.d",
        ) else {
            return eprintln!("omitido: corriendo como root");
        };
        assert_eq!(cfg.skipped, ["/etc/ssh/sshd_config.d (permission denied)"]);
        let r = eval(&cfg);
        // Ausente: caería al default "no" aunque el drop-in ilegible diga "yes".
        assert_eq!(r["SSH-003"].status, Status::Warn);
        // Fijado después del Include, que el drop-in pudo ganar.
        assert_eq!(r["SSH-005"].status, Status::Warn);
        // Fijado antes del Include: sigue siendo autoritativo.
        assert_eq!(r["SSH-002"].status, Status::Pass);
    }

    #[test]
    fn include_literal_en_directorio_ilegible_no_da_pass_falso() {
        let Some(cfg) = static_cfg_with_locked_dir(
            &[
                ("/etc/ssh/sshd_config", "Include /etc/ssh/private/extra.conf\n"),
                ("/etc/ssh/private/extra.conf", "PermitEmptyPasswords yes\n"),
            ],
            "/etc/ssh/private",
        ) else {
            return eprintln!("omitido: corriendo como root");
        };
        assert_eq!(cfg.skipped, ["/etc/ssh/private/extra.conf (permission denied)"]);
        assert_eq!(eval(&cfg)["SSH-003"].status, Status::Warn);
    }

    #[test]
    fn directorio_de_dropins_inexistente_no_es_omision() {
        let cfg = static_cfg(&[("/etc/ssh/sshd_config", "PasswordAuthentication no\nInclude /etc/ssh/sshd_config.d/*.conf\n")]);
        assert!(cfg.skipped.is_empty(), "{:?}", cfg.skipped);
        assert_eq!(eval(&cfg)["SSH-003"].status, Status::Pass);
    }

    #[test]
    fn glob_no_soportado_marca_incompleto() {
        let cfg = static_cfg(&[("/etc/ssh/sshd_config", "PasswordAuthentication no\nInclude /etc/ssh/*/x.conf\n")]);
        assert_eq!(cfg.skipped.len(), 1);
        assert_eq!(eval(&cfg)["SSH-003"].status, Status::Warn);
        // Un objetivo literal inexistente no es un error en sshd.
        let cfg = static_cfg(&[("/etc/ssh/sshd_config", "PasswordAuthentication no\nInclude /etc/ssh/no-existe.conf\n")]);
        assert!(cfg.skipped.is_empty());
        assert_eq!(eval(&cfg)["SSH-003"].status, Status::Pass);
    }

    #[test]
    fn glob_match_como_glob3() {
        assert!(glob_match("*.conf", "10-a.conf"));
        assert!(!glob_match("*.conf", "10-a.conf.bak"));
        assert!(!glob_match("*.conf", ".a.conf"));
        assert!(glob_match("1?-*.conf", "10-a.conf"));
        assert!(glob_match("*", "x"));
        assert!(!glob_match("a*b*c", "aXbY"));
    }

    #[test]
    fn match_que_reabre_root() {
        let t = "PermitRootLogin no\nMatch Address 10.0.0.0/8\n  PermitRootLogin yes\n";
        assert_eq!(weakening_match_lines("/etc/ssh/sshd_config", t), vec![
            "/etc/ssh/sshd_config:   PermitRootLogin yes".to_string()
        ]);
        assert!(weakening_match_lines("f", "PermitRootLogin yes\n").is_empty());
    }

    #[test]
    fn logingracetime_con_sufijo() {
        let r = eval(&SshdConfig::from_sshd_t("logingracetime 30s\n"));
        assert_eq!(r["SSH-007"].status, Status::Pass);
        let r = eval(&SshdConfig::from_sshd_t("logingracetime 2m\n"));
        assert_eq!(r["SSH-007"].status, Status::Warn);
    }
}
