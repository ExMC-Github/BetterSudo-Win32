//! 真正把目标进程拉起来：解析命令、环境、目录、身份、后台/超时。

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::mem::size_of;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, LookupAccountNameW, SecurityImpersonation, SetTokenInformation, TokenPrimary,
    TokenPrimaryGroup, PSID, TOKEN_ALL_ACCESS, TOKEN_ADJUST_DEFAULT, TOKEN_DUPLICATE,
    TOKEN_PRIMARY_GROUP, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessWithLogonW, CreateProcessWithTokenW, GetCurrentProcess, OpenProcessToken,
    PROCESS_INFORMATION, STARTUPINFOW, CREATE_NEW_CONSOLE, LOGON_WITH_PROFILE,
};

use crate::win::{error_text, last_error, wide, wide_str};

/// 目标进程的一份“施工图”
pub struct Job {
    /// 命令 + 参数（至少一个元素）
    pub command: Vec<OsString>,
    pub cwd: Option<PathBuf>,
    pub env: Vec<(OsString, OsString)>,
    /// -H：给子进程设置 HOME
    pub set_home: bool,
    /// -b：后台，不等待
    pub detached: bool,
    /// -T：超时（毫秒）
    pub timeout: Option<Duration>,
    /// 挂不上父控制台时兜底开新窗口
    pub new_console: bool,
    /// -u：以另一个身份运行（账户, 密码）
    pub credentials: Option<(String, String)>,
    /// -g：主组名
    pub group: Option<OsString>,
}

struct Plan {
    program: PathBuf,
    args: Vec<OsString>,
}

pub fn run(job: &Job) -> Result<i32, String> {
    if job.command.is_empty() {
        return Err("没有要执行的命令".into());
    }
    let plan = plan(job);

    if let Some((account, password)) = &job.credentials {
        return run_as_user(job, &plan, account, password);
    }
    if let Some(group) = &job.group {
        return run_as_group(job, &plan, group);
    }
    run_here(job, &plan)
}

fn run_here(job: &Job, plan: &Plan) -> Result<i32, String> {
    let mut cmd = Command::new(&plan.program);
    cmd.args(&plan.args);
    apply_common(&mut cmd, job);

    // 只在需要新窗口的场合加 CREATE_NEW_CONSOLE；GUI 程序不需要
    if (job.new_console || job.detached) && pe_subsystem(&plan.program) != Some(2) {
        cmd.creation_flags(CREATE_NEW_CONSOLE);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("无法运行 {}: {e}", plan.program.display()))?;

    if job.detached {
        return Ok(0);
    }
    wait(&mut child, job.timeout)
}

fn apply_common(cmd: &mut Command, job: &Job) {
    if let Some(dir) = &job.cwd {
        if dir.is_dir() {
            cmd.current_dir(dir);
        }
    }
    for (key, value) in &job.env {
        cmd.env(key, value);
    }
    if job.set_home {
        if let Some(profile) = std::env::var_os("USERPROFILE") {
            cmd.env("HOME", profile);
        }
    }
}

fn wait(child: &mut std::process::Child, timeout: Option<Duration>) -> Result<i32, String> {
    let Some(limit) = timeout else {
        return child
            .wait()
            .map(|status| status.code().unwrap_or(0))
            .map_err(|e| format!("等待进程结束失败: {e}"));
    };

    let deadline = Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.code().unwrap_or(0)),
            Ok(None) => {}
            Err(e) => return Err(format!("等待进程结束失败: {e}")),
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("命令超时（{} 秒），已终止", limit.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ---------------------------------------------------------------------------
// -u：换成另一个账户（需要该账户的密码）
// ---------------------------------------------------------------------------

fn run_as_user(job: &Job, plan: &Plan, account: &str, password: &str) -> Result<i32, String> {
    let (user, domain) = crate::token::split_account(account);
    let user_w = wide_str(&user);
    let domain_w = domain.as_ref().map(|value| wide_str(value));
    let pass_w = wide_str(password);
    let app_w = wide(plan.program.as_os_str());
    let mut cmdline = command_line(plan);
    let cwd_w = job
        .cwd
        .as_ref()
        .filter(|dir| dir.is_dir())
        .map(|dir| wide(dir.as_os_str()));

    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = size_of::<STARTUPINFOW>() as u32;
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let ok = unsafe {
        CreateProcessWithLogonW(
            user_w.as_ptr(),
            domain_w
                .as_ref()
                .map(|value| value.as_ptr())
                .unwrap_or(ptr::null()),
            pass_w.as_ptr(),
            LOGON_WITH_PROFILE,
            app_w.as_ptr(),
            cmdline.as_mut_ptr(),
            CREATE_NEW_CONSOLE,
            ptr::null(),
            cwd_w.as_ref().map(|value| value.as_ptr()).unwrap_or(ptr::null()),
            &startup,
            &mut process,
        )
    };

    if ok == 0 {
        let code = last_error();
        return Err(format!("无法以 {account} 身份运行: {}", error_text(code)));
    }
    // 密码用完就从内存里抹掉
    zero(&pass_w);

    finish(process, job.timeout)
}

// ---------------------------------------------------------------------------
// -g：改主组
// ---------------------------------------------------------------------------

fn run_as_group(job: &Job, plan: &Plan, group: &OsStr) -> Result<i32, String> {
    let group = group.to_string_lossy().into_owned();
    let sid = lookup_sid(&group)?;

    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
            &mut token,
        ) == 0
        {
            let code = last_error();
            return Err(format!("无法打开当前进程令牌: {}", error_text(code)));
        }

        let mut primary: HANDLE = ptr::null_mut();
        if DuplicateTokenEx(
            token,
            TOKEN_ALL_ACCESS,
            ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut primary,
        ) == 0
        {
            let code = last_error();
            CloseHandle(token);
            return Err(format!("无法复制令牌: {}", error_text(code)));
        }
        CloseHandle(token);

        let info = TOKEN_PRIMARY_GROUP {
            PrimaryGroup: sid.as_ptr() as PSID,
        };
        if SetTokenInformation(
            primary,
            TokenPrimaryGroup,
            &info as *const _ as *const core::ffi::c_void,
            size_of::<TOKEN_PRIMARY_GROUP>() as u32,
        ) == 0
        {
            let code = last_error();
            CloseHandle(primary);
            return Err(format!("无法设置主组 {group}: {}", error_text(code)));
        }

        let app_w = wide(plan.program.as_os_str());
        let mut cmdline = command_line(plan);
        let cwd_w = job
            .cwd
            .as_ref()
            .filter(|dir| dir.is_dir())
            .map(|dir| wide(dir.as_os_str()));

        let mut startup: STARTUPINFOW = std::mem::zeroed();
        startup.cb = size_of::<STARTUPINFOW>() as u32;
        let mut process: PROCESS_INFORMATION = std::mem::zeroed();

        let ok = CreateProcessWithTokenW(
            primary,
            0,
            app_w.as_ptr(),
            cmdline.as_mut_ptr(),
            CREATE_NEW_CONSOLE,
            ptr::null(),
            cwd_w
                .as_ref()
                .map(|value| value.as_ptr())
                .unwrap_or(ptr::null()),
            &startup,
            &mut process,
        );
        if ok == 0 {
            let code = last_error();
            CloseHandle(primary);
            return Err(format!(
                "无法以主组 {group} 运行（需要提升后的令牌）: {}",
                error_text(code)
            ));
        }
        CloseHandle(primary);

        finish(process, job.timeout)
    }
}

/// 组名 → SID 字节（所有权留在调用方，避免手工释放）
fn lookup_sid(name: &str) -> Result<Vec<u8>, String> {
    let name_w = wide_str(name);
    let mut sid_len = 0u32;
    let mut domain_len = 0u32;
    let mut sid_type = 0i32;

    unsafe {
        LookupAccountNameW(
            ptr::null(),
            name_w.as_ptr(),
            ptr::null_mut(),
            &mut sid_len,
            ptr::null_mut(),
            &mut domain_len,
            &mut sid_type,
        );
        if sid_len == 0 {
            return Err(format!("找不到组 {name}: {}", error_text(last_error())));
        }

        let mut sid = vec![0u8; sid_len as usize];
        let mut domain = vec![0u16; domain_len as usize];
        let ok = LookupAccountNameW(
            ptr::null(),
            name_w.as_ptr(),
            sid.as_mut_ptr() as PSID,
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut sid_type,
        );
        if ok == 0 {
            return Err(format!("找不到组 {name}: {}", error_text(last_error())));
        }
        Ok(sid)
    }
}

fn finish(process: PROCESS_INFORMATION, timeout: Option<Duration>) -> Result<i32, String> {
    unsafe {
        CloseHandle(process.hThread);
        if process.hProcess.is_null() {
            return Err("进程句柄无效".into());
        }
    }

    // 用 std 拿不到 raw 句柄的退出码，这里自己等
    let handle = process.hProcess;
    let deadline = timeout.map(|limit| Instant::now() + limit);
    let mut code = 0u32;
    loop {
        let state = unsafe { windows_sys::Win32::System::Threading::WaitForSingleObject(handle, 50) };
        if state == 0 {
            unsafe {
                windows_sys::Win32::System::Threading::GetExitCodeProcess(handle, &mut code);
                CloseHandle(handle);
            }
            return Ok(code as i32);
        }
        if let Some(deadline) = deadline {
            if Instant::now() >= deadline {
                unsafe {
                    windows_sys::Win32::System::Threading::TerminateProcess(handle, 1);
                    CloseHandle(handle);
                }
                return Err("命令超时，已终止".into());
            }
        }
    }
}

fn zero(buffer: &[u16]) {
    let pointer = buffer.as_ptr() as *mut u16;
    unsafe {
        for index in 0..buffer.len() {
            ptr::write_volatile(pointer.add(index), 0);
        }
    }
}

// ---------------------------------------------------------------------------
// 命令解析
// ---------------------------------------------------------------------------

fn plan(job: &Job) -> Plan {
    let name = &job.command[0];
    match find_executable(name) {
        Some(exe) => {
            let extension = exe
                .extension()
                .map(|value| value.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            if extension == "bat" || extension == "cmd" {
                let mut args = vec![OsString::from("/c"), exe.clone().into_os_string()];
                args.extend_from_slice(&job.command[1..]);
                return Plan {
                    program: cmd_exe(),
                    args,
                };
            }
            Plan {
                program: exe,
                args: job.command[1..].to_vec(),
            }
        }
        None => {
            let mut args = vec![OsString::from("/c")];
            args.extend_from_slice(&job.command);
            Plan {
                program: cmd_exe(),
                args,
            }
        }
    }
}

fn cmd_exe() -> PathBuf {
    if let Some(comspec) = std::env::var_os("COMSPEC") {
        let path = PathBuf::from(&comspec);
        if path.is_file() {
            return path;
        }
    }
    if let Some(root) = std::env::var_os("SystemRoot") {
        return PathBuf::from(root).join("System32").join("cmd.exe");
    }
    PathBuf::from(r"C:\Windows\System32\cmd.exe")
}

fn find_executable(name: &OsStr) -> Option<PathBuf> {
    let raw = name.to_string_lossy();
    let explicit = raw.contains('/') || raw.contains('\\');
    let extensions: Vec<&str> = if Path::new(name).extension().is_some() {
        vec![""]
    } else {
        vec![".exe", ".com", ".bat", ".cmd"]
    };

    let bases: Vec<PathBuf> = if explicit {
        vec![PathBuf::new()]
    } else {
        let mut dirs = Vec::new();
        if let Ok(cwd) = std::env::current_dir() {
            dirs.push(cwd);
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                dirs.push(parent.to_path_buf());
            }
        }
        if let Some(path) = std::env::var_os("PATH") {
            dirs.extend(std::env::split_paths(&path));
        }
        if let Some(root) = std::env::var_os("SystemRoot") {
            dirs.push(PathBuf::from(root).join("System32"));
        }
        dirs
    };

    for base in bases {
        let stem = if explicit {
            PathBuf::from(name)
        } else {
            base.join(name)
        };
        for extension in &extensions {
            let mut candidate = stem.clone().into_os_string();
            candidate.push(extension);
            let candidate = PathBuf::from(candidate);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// 读 PE 头的 Subsystem：2 = GUI（不要给它开控制台窗口）
fn pe_subsystem(path: &Path) -> Option<u16> {
    let mut file = File::open(path).ok()?;
    let mut dos = [0u8; 0x40];
    file.read_exact(&mut dos).ok()?;
    if &dos[..2] != b"MZ" {
        return None;
    }
    let offset = u32::from_le_bytes([dos[0x3c], dos[0x3d], dos[0x3e], dos[0x3f]]) as u64;
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut nt = [0u8; 0x60];
    file.read_exact(&mut nt).ok()?;
    if &nt[..4] != b"PE\0\0" {
        return None;
    }
    Some(u16::from_le_bytes([nt[24 + 68], nt[24 + 69]]))
}

/// 按 CommandLineToArgvW 的规则拼命令行（给 raw CreateProcess 用）
fn command_line(plan: &Plan) -> Vec<u16> {
    let mut line: Vec<u16> = Vec::new();
    let parts = std::iter::once(plan.program.as_os_str())
        .chain(plan.args.iter().map(|value| value.as_os_str()));
    for (index, part) in parts.enumerate() {
        if index > 0 {
            line.push(b' ' as u16);
        }
        line.extend(quote(part));
    }
    line.push(0);
    line
}

/// 按 CommandLineToArgvW 的规则给单个参数加引号（返回 UTF-16，不带结尾 NUL）
pub fn quote(value: &OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    let units: Vec<u16> = value.encode_wide().collect();
    let needs_quotes = units.is_empty()
        || units
            .iter()
            .any(|unit| *unit == b' ' as u16 || *unit == b'\t' as u16 || *unit == b'"' as u16);
    if !needs_quotes {
        return units;
    }

    let mut out = vec![b'"' as u16];
    let mut backslashes = 0;
    for unit in units {
        if unit == b'\\' as u16 {
            backslashes += 1;
            continue;
        }
        if unit == b'"' as u16 {
            out.extend(std::iter::repeat(b'\\' as u16).take(backslashes * 2 + 1));
            out.push(unit);
        } else {
            out.extend(std::iter::repeat(b'\\' as u16).take(backslashes));
            out.push(unit);
        }
        backslashes = 0;
    }
    out.extend(std::iter::repeat(b'\\' as u16).take(backslashes * 2));
    out.push(b'"' as u16);
    out
}
