//! 密码提示 + “时间戳”缓存。
//!
//! 语义照抄 Linux 版 sudo：同一个终端会话里第一次用要输密码，之后
//! TIMEOUT 之内免密；换一个终端（新的 cmd 窗口 / 新的 Windows Terminal
//! 标签页）就要重新输入。缓存按“终端宿主进程 + 用户”分开存放，
//! 只记录过期时间，**不保存密码本身**。

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::console;
use crate::token::{self, LogonError};
use crate::win;

/// 免密有效期（秒），与 sudo 默认的 15 分钟一致
const TIMEOUT: u64 = 15 * 60;

pub struct AuthRequest<'a> {
    pub user: &'a str,
    pub prompt: Option<&'a str>,
    pub non_interactive: bool,
    pub from_stdin: bool,
    pub askpass: bool,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn cache_dir() -> PathBuf {
    match std::env::var_os("LOCALAPPDATA") {
        Some(dir) => PathBuf::from(dir).join("sudo").join("stamps"),
        None => std::env::temp_dir().join("sudo-stamps"),
    }
}

fn fingerprint(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn stamp_path(user: &str) -> PathBuf {
    let key = format!("{}\n{}", win::session_key(), user.to_lowercase());
    cache_dir().join(format!("{:016x}.txt", fingerprint(&key)))
}

/// 当前终端会话对这个账户是否还在免密期内
pub fn is_valid(user: &str) -> bool {
    let Ok(text) = fs::read_to_string(stamp_path(user)) else {
        return false;
    };
    match text.lines().next().map(|line| line.trim()) {
        Some("v1") => text
            .lines()
            .nth(1)
            .and_then(|expiry| expiry.trim().parse::<u64>().ok())
            .map(|expiry| expiry > now())
            .unwrap_or(false),
        _ => false,
    }
}

fn touch(user: &str) {
    let _ = fs::create_dir_all(cache_dir());
    let body = format!(
        "v1\n{}\n{}\n{}\n",
        now() + TIMEOUT,
        user,
        win::session_key()
    );
    let _ = fs::write(stamp_path(user), body);
}

/// -k：只清掉本终端会话的记录
pub fn clear_current(user: &str) {
    let _ = fs::remove_file(stamp_path(user));
}

/// -K：全部清掉
pub fn clear_all() {
    let _ = fs::remove_dir_all(cache_dir());
}

fn read_password(request: &AuthRequest, prompt: &str) -> Option<String> {
    if request.askpass {
        let helper = std::env::var("SUDO_ASKPASS").ok()?;
        let output = std::process::Command::new(helper)
            .arg(prompt)
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Some(text);
    }
    if request.from_stdin {
        return console::read_line(prompt);
    }
    console::read_secret(prompt)
}

/// 需要时提示密码；成功（或本来就在免密期内 / 已经是管理员）返回 Ok。
pub fn require(request: &AuthRequest) -> Result<(), String> {
    // 已经是提升过的令牌，和 sudo 一样不再询问
    if token::is_elevated() || is_valid(request.user) {
        return Ok(());
    }
    if request.non_interactive {
        return Err("需要输入密码，但指定了 -n（非交互）".into());
    }

    let prompt = match request.prompt {
        Some(text) => text.to_string(),
        None => format!("[sudo] password for {}: ", request.user),
    };

    for attempt in 0..3 {
        let password = match read_password(request, &prompt) {
            Some(value) => value,
            None => return Err("没有可用的终端读取密码".into()),
        };
        if password.is_empty() && attempt > 0 {
            break;
        }

        match token::verify_password(request.user, &password) {
            Ok(()) => {
                touch(request.user);
                return Ok(());
            }
            Err(LogonError::Credentials) => {
                console::err("Sorry, try again.\r\n");
            }
            Err(LogonError::Other(code, text)) => {
                // 微软账户 / 策略禁止密码登录这类情况，校验不了也不能把工具卡死
                console::err(&format!(
                    "sudo: 警告：无法在本机校验密码（{text}，错误码 {code}），直接放行\r\n"
                ));
                touch(request.user);
                return Ok(());
            }
        }
    }

    Err("3 次密码错误（若你平时用微软账户 / PIN / 指纹登录，本机的密码校验可能不适用，可以改用无终端的原生 UAC 方式）".into())
}
