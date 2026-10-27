//! 普通实例 → 提权实例的请求编解码。
//!
//! 载荷里所有字符串都是 UTF-16 的十六进制，用 `|` 分隔，
//! 所以塞进注册表默认值（shell 会把它当命令行解析）时不会有任何引号问题。

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

/// 提权实例的命令行标记
pub const FLAG: &str = "--sudo-elevated";

/// 后台运行（-b）
pub const FLAG_DETACHED: u32 = 1 << 0;
/// 给子进程设置 HOME（-H）
pub const FLAG_SET_HOME: u32 = 1 << 1;

pub struct Request {
    pub parent_pid: u32,
    pub flags: u32,
    pub timeout: u64,
    pub cwd: PathBuf,
    pub rc_path: PathBuf,
    /// -g：要设置的主组（空表示不改）
    pub group: Option<OsString>,
    pub env: Vec<(OsString, OsString)>,
    pub command: Vec<OsString>,
}

impl Request {
    pub fn encode(&self) -> String {
        let mut parts: Vec<String> = vec![
            "v1".to_string(),
            self.parent_pid.to_string(),
            self.flags.to_string(),
            self.timeout.to_string(),
            encode_wide(self.cwd.as_os_str()),
            encode_wide(self.rc_path.as_os_str()),
            match &self.group {
                Some(group) => encode_wide(group),
                None => String::new(),
            },
            self.env.len().to_string(),
        ];
        for (key, value) in &self.env {
            parts.push(encode_wide(key));
            parts.push(encode_wide(value));
        }
        parts.push(self.command.len().to_string());
        for arg in &self.command {
            parts.push(encode_wide(arg));
        }
        parts.join("|")
    }

    pub fn decode(text: &str) -> Option<Request> {
        let mut fields = text.split('|');
        if fields.next()? != "v1" {
            return None;
        }
        let parent_pid = fields.next()?.parse().ok()?;
        let flags = fields.next()?.parse().ok()?;
        let timeout = fields.next()?.parse().ok()?;
        let cwd = PathBuf::from(decode_wide(fields.next()?)?);
        let rc_path = PathBuf::from(decode_wide(fields.next()?)?);
        let group_hex = fields.next()?;
        let group = if group_hex.is_empty() {
            None
        } else {
            Some(decode_wide(group_hex)?)
        };

        let env_count: usize = fields.next()?.parse().ok()?;
        let mut env = Vec::with_capacity(env_count);
        for _ in 0..env_count {
            let key = decode_wide(fields.next()?)?;
            let value = decode_wide(fields.next()?)?;
            env.push((key, value));
        }

        let arg_count: usize = fields.next()?.parse().ok()?;
        let mut command = Vec::with_capacity(arg_count);
        for _ in 0..arg_count {
            command.push(decode_wide(fields.next()?)?);
        }

        Some(Request {
            parent_pid,
            flags,
            timeout,
            cwd,
            rc_path,
            group,
            env,
            command,
        })
    }
}

fn encode_wide(value: &OsStr) -> String {
    let mut out = String::with_capacity(value.len() * 4);
    for unit in value.encode_wide() {
        out.push(char::from_digit((unit >> 12) as u32 & 0xF, 16).unwrap());
        out.push(char::from_digit((unit >> 8) as u32 & 0xF, 16).unwrap());
        out.push(char::from_digit((unit >> 4) as u32 & 0xF, 16).unwrap());
        out.push(char::from_digit(unit as u32 & 0xF, 16).unwrap());
    }
    out
}

fn decode_wide(hex: &str) -> Option<OsString> {
    if hex.len() % 4 != 0 {
        return None;
    }
    let bytes = hex.as_bytes();
    let mut units = Vec::with_capacity(hex.len() / 4);
    for chunk in bytes.chunks(4) {
        let text = std::str::from_utf8(chunk).ok()?;
        units.push(u16::from_str_radix(text, 16).ok()?);
    }
    Some(OsString::from_wide(&units))
}
