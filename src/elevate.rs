//! 提权主流程。
//!
//! 两条路，由调用方按"手里有没有可交互的终端"来选：
//!
//! * [`Strategy::Hijack`]：劫持 `ms-settings` 注册表项，让会自动提权的
//!   `fodhelper.exe` 把 `sudo-elevated.exe` 拉起来。全程无 UAC 弹窗，
//!   于是前面用密码提示充当 sudo 的认证关口。
//! * [`Strategy::Uac`]：没有终端（从 GUI、计划任务之类启动）时，
//!   直接用 ShellExecute 的 `runas` 动词，走 Windows 原生 UAC 弹窗。
//!
//! 两条路最终都由 `sudo-elevated.exe` 干活，用 rc 文件回报 `exit <code>`。

use std::ffi::{OsStr, OsString};
use std::fs;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Threading::WaitForSingleObject;
use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

use crate::launch::{self, Job};
use crate::payload::{self, Request};
use crate::registry;
use crate::win::{
    current_pid, error_text, last_error, process_alive, wide, wide_str,
};

/// 干提权活的那个 GUI 子系统 exe，必须和 sudo.exe 放在一起
pub const HELPER_NAME: &str = "sudo-elevated.exe";

pub enum Strategy {
    /// 无 UAC 弹窗：劫持 ms-settings + fodhelper
    Hijack,
    /// 原生 UAC 弹窗：ShellExecute 的 runas
    Uac,
}

/// 每次提权用一个独立的 rc 文件做双向通信
pub fn new_rc_path() -> PathBuf {
    let base = match std::env::var_os("LOCALAPPDATA") {
        Some(dir) => PathBuf::from(dir).join("sudo").join("run"),
        None => std::env::temp_dir().join("sudo-run"),
    };
    let _ = fs::create_dir_all(&base);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    base.join(format!("{}-{stamp}.rc", current_pid()))
}

fn write_rc(path: &Path, text: &str) {
    let _ = fs::write(path, text);
}

fn helper_exe() -> Result<PathBuf, String> {
    let current = std::env::current_exe().map_err(|e| format!("无法获取自身路径: {e}"))?;
    if let Some(dir) = current.parent() {
        let candidate = dir.join(HELPER_NAME);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(HELPER_NAME);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(format!(
        "找不到 {HELPER_NAME}，请把它和 sudo.exe 放在同一个目录里"
    ))
}

fn encoded_args(request: &Request) -> OsString {
    let mut args = OsString::from(payload::FLAG);
    args.push(" ");
    args.push(request.encode());
    args
}

pub fn request(request: &Request, strategy: Strategy) -> Result<i32, String> {
    match strategy {
        Strategy::Hijack => via_hijack(request),
        Strategy::Uac => via_uac(request),
    }
}

/// 静默提权：注册表劫持 + fodhelper
fn via_hijack(request: &Request) -> Result<i32, String> {
    let helper = helper_exe()?;
    let line = registry::build_command_line(
        helper.as_os_str(),
        payload::FLAG,
        OsStr::new(request.encode().as_str()),
    );

    registry::setup(&line)?;

    let target = wide_str("fodhelper.exe");
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpFile = target.as_ptr();
    info.nShow = SW_SHOWNORMAL;

    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        let code = last_error();
        registry::cleanup();
        return Err(format!("无法启动 fodhelper: {}", error_text(code)));
    }

    if !info.hProcess.is_null() {
        unsafe {
            // 用户在 UAC 上磨蹭时 fodhelper 会一直活着，多等一会
            WaitForSingleObject(info.hProcess, 120_000);
            CloseHandle(info.hProcess);
        }
    }
    // 提权实例自己也会清一次，这里是幂等的
    registry::cleanup();

    handshake(&request.rc_path)
}

/// 原生 UAC：没有终端可用时走这条
fn via_uac(request: &Request) -> Result<i32, String> {
    let helper = helper_exe()?;
    let verb = wide_str("runas");
    let file = wide(helper.as_os_str());
    let params = wide(&encoded_args(request));

    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    info.nShow = SW_SHOWNORMAL;

    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        let code = last_error();
        return if code == 1223 {
            Err("用户取消了 UAC 提权".into())
        } else {
            Err(format!("无法发起 UAC 提权: {}", error_text(code)))
        };
    }

    if !info.hProcess.is_null() {
        unsafe {
            WaitForSingleObject(info.hProcess, 120_000);
            CloseHandle(info.hProcess);
        }
    }

    handshake(&request.rc_path)
}

/// 等提权实例把结果写回来
fn handshake(path: &Path) -> Result<i32, String> {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        match fs::read_to_string(path) {
            Ok(text) => {
                if text.starts_with("started") {
                    break;
                }
                if let Some(message) = text.strip_prefix("error ") {
                    let _ = fs::remove_file(path);
                    return Err(message.trim().to_string());
                }
            }
            Err(_) => {}
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    if unstarted(path) {
        let _ = fs::remove_file(path);
        return Err("提权实例没有响应（被取消，或提权进程启动失败）".into());
    }

    loop {
        match fs::read_to_string(path) {
            Ok(text) => {
                if let Some(rest) = text.strip_prefix("exit ") {
                    let code = rest.trim().parse().unwrap_or(1);
                    let _ = fs::remove_file(path);
                    return Ok(code);
                }
                if let Some(message) = text.strip_prefix("error ") {
                    let _ = fs::remove_file(path);
                    return Err(message.trim().to_string());
                }
                // 还停在 started：提权实例是不是被杀了？别永远等下去
                if let Some(pid) = text
                    .split_whitespace()
                    .nth(1)
                    .and_then(|value| value.parse::<u32>().ok())
                {
                    if !process_alive(pid) {
                        std::thread::sleep(Duration::from_millis(100));
                        if let Ok(late) = fs::read_to_string(path) {
                            if let Some(rest) = late.strip_prefix("exit ") {
                                let _ = fs::remove_file(path);
                                return Ok(rest.trim().parse().unwrap_or(1));
                            }
                        }
                        let _ = fs::remove_file(path);
                        return Err("提权实例意外退出".into());
                    }
                }
            }
            Err(_) => {}
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn unstarted(path: &Path) -> bool {
    match fs::read_to_string(path) {
        Ok(text) => !text.starts_with("started"),
        Err(_) => true,
    }
}

/// 提权实例入口：挂到发起者的终端、清注册表、跑命令、回报退出码。
pub fn elevated_entry(raw_payload: Option<&OsStr>) -> i32 {
    let Some(request) = raw_payload
        .map(|value| value.to_string_lossy().into_owned())
        .and_then(|text| Request::decode(&text))
    else {
        return 1;
    };

    registry::cleanup();

    // 挂到用户那个终端上：输出直接出现在他敲 sudo 的窗口里，且不会新开窗口
    let attached = crate::console::attach_to_console_of(request.parent_pid);

    write_rc(&request.rc_path, &format!("started {}", current_pid()));

    // 把"用户真实控制台是谁"传下去：被 sudo 拉起的工具（比如 su.exe）
    // 靠它把输出放回同一个终端，而不是自己新开一个窗口
    let mut env = request.env;
    env.push((
        OsString::from(crate::su::CONSOLE_PID_ENV),
        OsString::from(request.parent_pid.to_string()),
    ));

    let job = Job {
        command: request.command,
        cwd: Some(request.cwd),
        env,
        set_home: request.flags & payload::FLAG_SET_HOME != 0,
        detached: request.flags & payload::FLAG_DETACHED != 0,
        timeout: if request.timeout == 0 {
            None
        } else {
            Some(Duration::from_secs(request.timeout))
        },
        new_console: !attached,
        credentials: None,
        group: request.group,
    };

    match launch::run(&job) {
        Ok(code) => {
            write_rc(&request.rc_path, &format!("exit {code}"));
            code
        }
        Err(message) => {
            write_rc(&request.rc_path, &format!("error {message}"));
            1
        }
    }
}

