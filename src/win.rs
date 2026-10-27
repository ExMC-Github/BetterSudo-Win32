//! 零散的 Win32 封装：宽字符串、错误文本、进程信息、终端会话标识。

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LocalFree, WAIT_TIMEOUT};
use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows_sys::Win32::System::Console::GetConsoleWindow;
use windows_sys::Win32::System::Diagnostics::Debug::{
    FormatMessageW, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM,
    FORMAT_MESSAGE_IGNORE_INSERTS,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    WaitForSingleObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId;

/// Rust 字符串 → NUL 结尾的 UTF-16
pub fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

pub fn wide_str(value: &str) -> Vec<u16> {
    wide(OsStr::new(value))
}

pub fn last_error() -> u32 {
    unsafe { GetLastError() }
}

/// 把 Win32 错误码翻成可读文本
pub fn error_text(code: u32) -> String {
    unsafe {
        let mut buffer: *mut u16 = std::ptr::null_mut();
        let len = FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER,
            std::ptr::null(),
            code,
            0,
            &mut buffer as *mut *mut u16 as *mut u16,
            0,
            std::ptr::null(),
        );
        if len == 0 || buffer.is_null() {
            return format!("错误码 {code}");
        }
        let slice = std::slice::from_raw_parts(buffer, len as usize);
        let text = String::from_utf16_lossy(slice)
            .trim_matches(|c: char| c == '\r' || c == '\n' || c == ' ')
            .to_string();
        LocalFree(buffer as *mut core::ffi::c_void);
        if text.is_empty() {
            format!("错误码 {code}")
        } else {
            format!("{text} (错误码 {code})")
        }
    }
}

pub fn current_pid() -> u32 {
    unsafe { GetCurrentProcessId() }
}

/// 进程创建时间（100ns），取不到就返回 0。用来给 PID 加个稳定指纹。
pub fn process_start_time(pid: u32) -> u64 {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return 0;
        }
        let mut created = Default::default();
        let mut exited = Default::default();
        let mut kernel = Default::default();
        let mut user = Default::default();
        let ok = GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user);
        CloseHandle(handle);
        if ok == 0 {
            return 0;
        }
        ((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64
    }
}

pub fn process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    unsafe {
        let handle = OpenProcess(SYNCHRONIZE, 0, pid);
        if handle.is_null() {
            return false;
        }
        let state = WaitForSingleObject(handle, 0);
        CloseHandle(handle);
        state == WAIT_TIMEOUT
    }
}

/// 父进程 PID（通过 Toolhelp 快照找自己）
pub fn parent_pid() -> u32 {
    let me = current_pid();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot.is_null() || snapshot as isize == -1 {
            return 0;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        let mut found = 0;
        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                if entry.th32ProcessID == me {
                    found = entry.th32ParentProcessID;
                    break;
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

/// “终端会话”的标识：同一个终端窗口里的所有 sudo 共享，
/// 换窗口 / 换标签页就变。用控制台宿主进程（conhost / WindowsTerminal）
/// 的 PID + 启动时间做指纹，避免 PID 复用。
pub fn session_key() -> String {
    unsafe {
        let hwnd = GetConsoleWindow();
        if !hwnd.is_null() {
            let mut owner = 0u32;
            GetWindowThreadProcessId(hwnd, &mut owner);
            if owner != 0 {
                return format!("console-{owner}-{}", process_start_time(owner));
            }
        }
    }
    let parent = parent_pid();
    format!("parent-{parent}-{}", process_start_time(parent))
}
