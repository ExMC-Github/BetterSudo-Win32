//! `su` —— 以 SYSTEM 身份在当前终端里运行命令。
//!
//! 移植自 `C_or_Cpp_Project/syscmd/main.cpp`：启用 SeDebugPrivilege 打开
//! **当前会话**的 `winlogon.exe`，复制它的令牌，再用它起一个 SYSTEM 的 shell。
//!
//! 为什么不能一步到位、直接 `CreateProcessWithTokenW(..., 0, "cmd.exe")`？
//! 微软文档写得很清楚（winbase.h / CreateProcessWithTokenW）：
//!   > If the dwCreationFlags parameter has a value of 0: The process gets the
//!   > default error mode, **creates a new console** and creates a new process group.
//! 也就是说这个 API 默认就会新建控制台，指定 0 反而一定弹新窗口。
//! 唯一能避开新窗口的办法是先 `CREATE_NO_WINDOW` 起一个**无控制台**的中间进程，
//! 让它自己 `AttachConsole` 挂到目标终端，再由它 `CreateProcess` 拉起 shell —— 
//! 控制台继承只在同一份进程上下文里才生效。
//!
//! 所以流程是三段：
//!   su.exe（管理员）→ su.exe --system-run <控制台 pid>（SYSTEM，无窗口）
//!                   → cmd.exe（SYSTEM，附着在同一控制台里）

use std::ffi::{OsStr, OsString};
use std::mem::size_of;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, SetLastError, HANDLE, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, DuplicateTokenEx, LookupPrivilegeValueW, SecurityImpersonation,
    TokenPrimary, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_ALL_ACCESS, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::{
    CreateProcessWithTokenW, GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess,
    OpenProcess, OpenProcessToken, WaitForSingleObject, CREATE_NO_WINDOW, PROCESS_INFORMATION,
    PROCESS_QUERY_INFORMATION, STARTUPINFOW,
};
use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

use crate::console;
use crate::token;
use crate::win::{current_pid, error_text, last_error, wide, wide_str};

/// UAC 之后被重新拉起时带上的标记
const ELEVATED_MARK: &str = "--su-elevated";
/// 要求新开一个自己的控制台（UAC 后的实例不能挂在父进程那个已隐藏的窗口上）
const NEW_CONSOLE_MARK: &str = "--new-console";
/// SYSTEM 侧的中间进程：挂到指定控制台后跑 shell
const SYSTEM_RUN_MARK: &str = "--system-run";
/// sudo 会把它最终目标控制台的宿主 pid 放进环境变量，su 用它校正自己的控制台
pub const CONSOLE_PID_ENV: &str = "SUDO_CONSOLE_PID";

const HELP: &str = "\
用法: su [-h] [-V] [命令 [参数...]]

  以 SYSTEM 身份在当前终端里运行命令；不带命令则进入 SYSTEM 的交互式 cmd，
  输入 exit 返回。子进程不会弹新窗口，输出就留在你现在这个终端里。

  需要管理员权限：
    * 双击运行  -> 弹 Windows 原生 UAC
    * 命令行里  -> 推荐 `sudo su`（密码认证、无 UAC 弹窗、同终端输出）

  例:
    su                 进入 SYSTEM 的 cmd
    su whoami          以 SYSTEM 执行 whoami
    su -c \"dir /w\"     交给 cmd /c 执行一整条命令";

fn help() {
    console::out(&format!("{HELP}\r\n"));
}

pub fn main_console() -> i32 {
    let mut args: Vec<OsString> = Vec::new();
    let mut want_new_console = false;
    let mut system_console: Option<u32> = None;

    let mut rest = std::env::args_os().skip(1);
    while let Some(arg) = rest.next() {
        match arg.to_string_lossy().as_ref() {
            NEW_CONSOLE_MARK => want_new_console = true,
            ELEVATED_MARK => {}
            SYSTEM_RUN_MARK => {
                system_console = Some(
                    rest.next()
                        .and_then(|value| value.to_string_lossy().parse::<u32>().ok())
                        .unwrap_or(0),
                );
            }
            "-h" | "--help" | "/?" => {
                help();
                return 0;
            }
            "-V" | "--version" => {
                console::out(&format!(
                    "su (sudo-on-windows) {}\r\n",
                    env!("CARGO_PKG_VERSION")
                ));
                return 0;
            }
            _ => args.push(arg),
        }
    }

    // `su -c "..."`：把 -c 去掉，后面整串交给 cmd /c
    if args
        .first()
        .map(|arg| arg == OsStr::new("-c"))
        .unwrap_or(false)
    {
        args.remove(0);
    }

    if want_new_console {
        console::recreate();
    }

    // 第二阶段：SYSTEM 侧的中间进程。先挂到目标控制台，再就地跑 shell。
    if let Some(pid) = system_console {
        if pid != 0 && !console::console_contains(pid) {
            if !console::attach_to_console_of(pid) {
                // 挂不上就自己开一个，至少别变成一个看不见输出的进程
                console::recreate();
            }
        }
        return run_shell(&args);
    }

    // 由 sudo 拉起时，环境变量里带着用户真实控制台的宿主 pid。
    // 只有当"那个进程不在我当前的控制台里"时才切换，避免无谓地
    // FreeConsole 之后又挂不回去、反而新开一个窗口。
    if let Some(pid) = console_pid_from_env() {
        if !console::console_contains(pid) {
            if !console::attach_to_console_of(pid) {
                console::recreate();
            }
        }
    }

    if !token::is_elevated() {
        return relaunch_with_uac(&args);
    }

    run_as_system(&args)
}

fn console_pid_from_env() -> Option<u32> {
    std::env::var(CONSOLE_PID_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|pid| *pid != 0)
}

fn fail(message: &str) -> i32 {
    if console::has_console() {
        console::err(&format!("su: {message}\r\n"));
    } else {
        console::message_box(message);
    }
    1
}

/// 没有管理员权限：用 runas 弹原生 UAC，把自己重新拉起来再干活。
fn relaunch_with_uac(args: &[OsString]) -> i32 {
    if !token::in_admin_group() {
        return fail("当前用户不在 Administrators 组中，无法取得管理员权限");
    }

    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(error) => return fail(&format!("无法获取自身路径: {error}")),
    };

    let mut parameters = OsString::from(ELEVATED_MARK);
    parameters.push(" ");
    parameters.push(NEW_CONSOLE_MARK);
    for arg in args {
        parameters.push(" ");
        parameters.push(arg.as_os_str());
    }

    // 双击启动时窗口是我们独享的，先藏掉，UAC 背后就不会留一个空窗口；
    // 从 cmd 里启动时窗口是 cmd 的，console::hide 里会拒绝隐藏。
    console::hide();

    let verb = wide_str("runas");
    let file = wide(exe.as_os_str());
    let params = wide(&parameters);

    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    info.nShow = SW_SHOWNORMAL;

    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        let code = last_error();
        if code == 1223 {
            return 1; // 用户点了"否"，安静退出
        }
        return fail(&format!("无法发起 UAC 提权: {}", error_text(code)));
    }

    let mut code = 0u32;
    unsafe {
        WaitForSingleObject(info.hProcess, u32::MAX);
        GetExitCodeProcess(info.hProcess, &mut code);
        CloseHandle(info.hProcess);
    }
    code as i32
}

/// 已经是管理员：偷 SYSTEM 令牌，起一个无窗口的中间进程去挂控制台。
fn run_as_system(args: &[OsString]) -> i32 {
    if let Err(message) = enable_privilege("SeDebugPrivilege") {
        return fail(&format!("{message}（需要管理员权限）"));
    }
    // CreateProcessWithTokenW 需要它，失败也先继续试
    let _ = enable_privilege("SeImpersonatePrivilege");

    let session = current_session();
    let Some(winlogon) = find_process_in_session("winlogon.exe", session) else {
        return fail(&format!("当前会话（{session}）里找不到 winlogon.exe"));
    };

    let token = match system_token(winlogon) {
        Ok(token) => token,
        Err(message) => return fail(&message),
    };

    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(error) => {
            unsafe { CloseHandle(token) };
            return fail(&format!("无法获取自身路径: {error}"));
        }
    };

    // 我们自己就挂在这个控制台上，把 pid 交给中间进程让它 AttachConsole 即可
    let mut command_line = system_worker_command_line(exe.as_os_str(), current_pid(), args);

    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = size_of::<STARTUPINFOW>() as u32;
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // CREATE_NO_WINDOW：中间进程不要任何控制台窗口，它自己会挂到目标终端上
    let created = unsafe {
        CreateProcessWithTokenW(
            token,
            0,
            ptr::null(),
            command_line.as_mut_ptr(),
            CREATE_NO_WINDOW,
            ptr::null(),
            ptr::null(),
            &startup,
            &mut process,
        )
    };
    let code = last_error();
    unsafe { CloseHandle(token) };

    if created == 0 {
        return fail(&format!("无法创建 SYSTEM 进程: {}", error_text(code)));
    }

    let mut exit_code = 0u32;
    unsafe {
        CloseHandle(process.hThread);
        WaitForSingleObject(process.hProcess, u32::MAX);
        GetExitCodeProcess(process.hProcess, &mut exit_code);
        CloseHandle(process.hProcess);
    }
    exit_code as i32
}

/// `"<su.exe>" --system-run <控制台 pid> <命令...>`
fn system_worker_command_line(exe: &OsStr, console_pid: u32, args: &[OsString]) -> Vec<u16> {
    let mut line = crate::launch::quote(exe);
    line.extend(" ".encode_utf16());
    line.extend(SYSTEM_RUN_MARK.encode_utf16());
    line.extend(" ".encode_utf16());
    line.extend(console_pid.to_string().encode_utf16());
    for arg in args {
        line.push(b' ' as u16);
        line.extend(crate::launch::quote(arg.as_os_str()));
    }
    line.push(0);
    line
}

/// SYSTEM 侧执行体：控制台已经挂好了，直接起 shell（继承句柄 → 同终端）
fn run_shell(args: &[OsString]) -> i32 {
    let mut command = std::process::Command::new(shell_exe());
    if !args.is_empty() {
        command.arg("/c");
        command.args(args);
    }
    match command.status() {
        Ok(status) => status.code().unwrap_or(0),
        Err(error) => fail(&format!("无法启动 shell: {error}")),
    }
}

fn enable_privilege(name: &str) -> Result<(), String> {
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return Err(format!("无法打开进程令牌: {}", error_text(last_error())));
        }

        let name_w = wide_str(name);
        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        if LookupPrivilegeValueW(ptr::null(), name_w.as_ptr(), &mut luid) == 0 {
            let code = last_error();
            CloseHandle(token);
            return Err(format!("无法解析特权 {name}: {}", error_text(code)));
        }

        let state = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        // 官方要求：先清零 last error，再看它是不是 ERROR_NOT_ALL_ASSIGNED
        SetLastError(0);
        let ok = AdjustTokenPrivileges(
            token,
            0,
            &state,
            size_of::<TOKEN_PRIVILEGES>() as u32,
            ptr::null_mut(),
            ptr::null_mut(),
        );
        let code = last_error();
        CloseHandle(token);

        if ok == 0 || code != 0 {
            return Err(format!("无法启用 {name}: {}", error_text(code)));
        }
        Ok(())
    }
}

fn current_session() -> u32 {
    let mut session = 0u32;
    unsafe {
        ProcessIdToSessionId(GetCurrentProcessId(), &mut session);
    }
    session
}

fn find_process_in_session(name: &str, session: u32) -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot.is_null() || snapshot as isize == -1 {
            return None;
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut found = None;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                if wide_equals(&entry.szExeFile, name) {
                    let mut owner = 0u32;
                    if ProcessIdToSessionId(entry.th32ProcessID, &mut owner) != 0 && owner == session
                    {
                        found = Some(entry.th32ProcessID);
                        break;
                    }
                }
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
        found
    }
}

fn wide_equals(buffer: &[u16], text: &str) -> bool {
    let end = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end]).eq_ignore_ascii_case(text)
}

fn system_token(pid: u32) -> Result<HANDLE, String> {
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
        if process.is_null() {
            return Err(format!(
                "无法打开 winlogon 进程（PID {pid}）: {}",
                error_text(last_error())
            ));
        }

        let mut token: HANDLE = ptr::null_mut();
        let opened = OpenProcessToken(
            process,
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
            &mut token,
        );
        let code = last_error();
        CloseHandle(process);
        if opened == 0 {
            return Err(format!("无法读取 winlogon 令牌: {}", error_text(code)));
        }

        let mut primary: HANDLE = ptr::null_mut();
        let duplicated = DuplicateTokenEx(
            token,
            TOKEN_ALL_ACCESS,
            ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut primary,
        );
        let code = last_error();
        CloseHandle(token);
        if duplicated == 0 {
            return Err(format!("无法复制 SYSTEM 令牌: {}", error_text(code)));
        }
        Ok(primary)
    }
}

fn shell_exe() -> OsString {
    if let Some(comspec) = std::env::var_os("COMSPEC") {
        return comspec;
    }
    match std::env::var_os("SystemRoot") {
        Some(root) => {
            let mut path = std::path::PathBuf::from(root);
            path.push("System32");
            path.push("cmd.exe");
            path.into_os_string()
        }
        None => OsString::from(r"C:\Windows\System32\cmd.exe"),
    }
}
