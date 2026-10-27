//! 控制台交互。
//!
//! 本程序是 GUI 子系统（这样 shell 拉起它时不会闪一个控制台窗口），
//! 所以需要输出时得先挂到父终端 / 目标终端上，再自己打开 CONOUT$ / CONIN$。

use std::ffi::c_void;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Console::{
    AllocConsole, AttachConsole, FreeConsole, GetConsoleMode, GetConsoleProcessList,
    GetConsoleWindow, GetStdHandle, ReadConsoleW, SetConsoleMode, SetStdHandle, WriteConsoleW,
    ATTACH_PARENT_PROCESS, ENABLE_ECHO_INPUT,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, WriteFile};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, ShowWindow, MB_ICONERROR, MB_OK, SW_HIDE,
};

use crate::win::wide_str;

const STD_INPUT: u32 = -10i32 as u32;
const STD_OUTPUT: u32 = -11i32 as u32;
const STD_ERROR: u32 = -12i32 as u32;

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const OPEN_EXISTING: u32 = 3;

fn invalid(handle: HANDLE) -> bool {
    handle.is_null() || handle as isize == -1
}

fn is_console(handle: HANDLE) -> bool {
    if invalid(handle) {
        return false;
    }
    let mut mode = 0u32;
    unsafe { GetConsoleMode(handle, &mut mode) != 0 }
}

fn std_handle(which: u32) -> HANDLE {
    unsafe { GetStdHandle(which) }
}

/// 接管当前进程的标准句柄，指向刚挂上的那个控制台。
fn bind_std_handles() {
    unsafe {
        let out = CreateFileW(
            wide_str("CONOUT$").as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );
        if !invalid(out) {
            SetStdHandle(STD_OUTPUT, out);
            SetStdHandle(STD_ERROR, out);
        }
        let input = CreateFileW(
            wide_str("CONIN$").as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );
        if !invalid(input) {
            SetStdHandle(STD_INPUT, input);
        }
    }
}

/// 当前进程是否已经挂在一个终端上。
/// console 子系统的 sudo.exe 从 cmd 里启动时本来就是 true。
pub fn has_console() -> bool {
    unsafe { !GetConsoleWindow().is_null() }
}

/// 没有终端可打印时，用系统弹窗把错误说清楚。
pub fn message_box(text: &str) {
    let caption = wide_str("sudo");
    let body = wide_str(text);
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            body.as_ptr(),
            caption.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

/// 指定进程是否也挂在我们这个控制台上 —— 用来判断"我现在这个终端是不是我要的那个"。
pub fn console_contains(pid: u32) -> bool {
    unsafe {
        let mut list = [0u32; 64];
        let count = GetConsoleProcessList(list.as_mut_ptr(), list.len() as u32);
        if count == 0 || count > list.len() as u32 {
            return false;
        }
        list[..count as usize].contains(&pid)
    }
}

/// 当前进程是否独占这个控制台窗口。
/// 只有"双击启动/自己新建"的情况才独占；从 cmd 里运行时，窗口是 cmd 的，
/// 这时候绝不能去隐藏它，否则会把用户自己的终端藏掉。
pub fn owns_console() -> bool {
    unsafe {
        let mut list = [0u32; 8];
        let count = GetConsoleProcessList(list.as_mut_ptr(), list.len() as u32);
        if count == 0 || count > list.len() as u32 {
            return false;
        }
        let me = crate::win::current_pid();
        list[..count as usize].iter().all(|pid| *pid == me)
    }
}

/// 把当前进程的控制台窗口藏起来（准备弹 UAC 时用，免得背后留个空窗口）。
pub fn hide() {
    if !owns_console() {
        return;
    }
    unsafe {
        let window = GetConsoleWindow();
        if !window.is_null() {
            ShowWindow(window, SW_HIDE);
        }
    }
}

/// 丢掉当前控制台、自己新建一个（UAC 之后要保证有一个自己能看见的窗口）。
pub fn recreate() -> bool {
    unsafe {
        FreeConsole();
        if AllocConsole() == 0 {
            return false;
        }
    }
    bind_std_handles();
    true
}

/// 挂到自己父进程所在的控制台（GUI 子系统的进程用）。
pub fn attach_to_parent() -> bool {
    if has_console() {
        return true;
    }
    unsafe {
        FreeConsole();
        if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
            return false;
        }
    }
    bind_std_handles();
    true
}

/// 挂到指定进程所在的控制台（提权实例用：父进程是 shell，不是本程序）。
pub fn attach_to_console_of(pid: u32) -> bool {
    unsafe {
        FreeConsole();
        if pid != 0 && AttachConsole(pid) != 0 {
            bind_std_handles();
            return true;
        }
        if AttachConsole(ATTACH_PARENT_PROCESS) != 0 {
            bind_std_handles();
            return true;
        }
    }
    false
}

fn write(which: u32, text: &str) {
    let handle = std_handle(which);
    if invalid(handle) {
        return;
    }
    unsafe {
        let mut written = 0u32;
        if is_console(handle) {
            let units: Vec<u16> = text.encode_utf16().collect();
            WriteConsoleW(
                handle,
                units.as_ptr(),
                units.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            );
        } else {
            WriteFile(
                handle,
                text.as_ptr() as *const u8,
                text.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            );
        }
    }
}

pub fn out(text: &str) {
    write(STD_OUTPUT, text);
}

pub fn err(text: &str) {
    write(STD_ERROR, text);
}

fn trim_end(value: &str) -> String {
    value
        .trim_end_matches(|c| c == '\r' || c == '\n')
        .to_string()
}

/// 从终端读一行（回显正常）。没有控制台就退回读 stdin。
pub fn read_line(prompt: &str) -> Option<String> {
    let handle = std_handle(STD_INPUT);
    if is_console(handle) {
        out(prompt);
        let mut buffer = [0u16; 512];
        let mut read = 0u32;
        let ok = unsafe {
            ReadConsoleW(
                handle,
                buffer.as_mut_ptr() as *mut c_void,
                (buffer.len() - 1) as u32,
                &mut read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return None;
        }
        return Some(trim_end(&String::from_utf16_lossy(&buffer[..read as usize])));
    }

    use std::io::BufRead;
    let mut text = String::new();
    std::io::stdin().lock().read_line(&mut text).ok()?;
    Some(trim_end(&text))
}

/// 读密码：关掉回显，读完恢复。
pub fn read_secret(prompt: &str) -> Option<String> {
    let handle = std_handle(STD_INPUT);
    if is_console(handle) {
        let mut mode = 0u32;
        unsafe { GetConsoleMode(handle, &mut mode) };
        unsafe { SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT) };
        out(prompt);

        let mut buffer = [0u16; 512];
        let mut read = 0u32;
        let ok = unsafe {
            ReadConsoleW(
                handle,
                buffer.as_mut_ptr() as *mut c_void,
                (buffer.len() - 1) as u32,
                &mut read,
                std::ptr::null_mut(),
            )
        };
        unsafe { SetConsoleMode(handle, mode) };
        out("\r\n");

        if ok == 0 {
            return None;
        }
        return Some(trim_end(&String::from_utf16_lossy(&buffer[..read as usize])));
    }
    read_line(prompt)
}
