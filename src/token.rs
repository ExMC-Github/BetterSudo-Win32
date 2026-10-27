//! 访问令牌相关：是否已提权、是否属于管理员组、密码校验、查别人的组。

use std::ffi::OsStr;
use std::mem::size_of;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetUserGetLocalGroups, LOCALGROUP_USERS_INFO_0,
};
use windows_sys::Win32::Security::{
    AllocateAndInitializeSid, CheckTokenMembership, FreeSid, GetTokenInformation, LogonUserW,
    LookupAccountNameW, LookupAccountSidW, TokenElevation, TokenElevationType,
    TokenElevationTypeLimited, TokenLinkedToken, PSID, SECURITY_NT_AUTHORITY, TOKEN_DUPLICATE,
    TOKEN_ELEVATION, TOKEN_ELEVATION_TYPE, TOKEN_QUERY, LOGON32_LOGON_NETWORK,
    LOGON32_PROVIDER_DEFAULT,
};
use windows_sys::Win32::System::SystemServices::{
    DOMAIN_ALIAS_RID_ADMINS, SECURITY_BUILTIN_DOMAIN_RID,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::win::{error_text, last_error, wide, wide_str};

pub enum LogonError {
    /// 用户名或密码不对、密码过期、账户锁定
    Credentials,
    /// 环境和策略层面的失败（比如这个账户不接受密码登录）
    Other(u32, String),
}

pub fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut core::ffi::c_void,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// 当前用户是否属于 Administrators（受限令牌下查链接令牌）。
pub fn in_admin_group() -> bool {
    unsafe {
        let authority = SECURITY_NT_AUTHORITY;
        let mut admins: PSID = ptr::null_mut();
        if AllocateAndInitializeSid(
            &authority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID as u32,
            DOMAIN_ALIAS_RID_ADMINS as u32,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut admins,
        ) == 0
        {
            return false;
        }

        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut token,
        ) == 0
        {
            FreeSid(admins);
            return false;
        }

        let mut elevation_type: TOKEN_ELEVATION_TYPE = 0;
        let mut returned = 0u32;
        GetTokenInformation(
            token,
            TokenElevationType,
            &mut elevation_type as *mut _ as *mut core::ffi::c_void,
            size_of::<TOKEN_ELEVATION_TYPE>() as u32,
            &mut returned,
        );

        let member = if elevation_type == TokenElevationTypeLimited {
            let mut linked: HANDLE = ptr::null_mut();
            let got = GetTokenInformation(
                token,
                TokenLinkedToken,
                &mut linked as *mut _ as *mut core::ffi::c_void,
                size_of::<HANDLE>() as u32,
                &mut returned,
            );
            if got != 0 {
                let mut is_member = 0i32;
                let ok = CheckTokenMembership(linked, admins, &mut is_member);
                CloseHandle(linked);
                ok != 0 && is_member != 0
            } else {
                false
            }
        } else {
            let mut is_member = 0i32;
            let ok = CheckTokenMembership(token, admins, &mut is_member);
            ok != 0 && is_member != 0
        };

        CloseHandle(token);
        FreeSid(admins);
        member
    }
}

pub fn current_account() -> String {
    std::env::var("USERNAME").unwrap_or_else(|_| "unknown".into())
}

fn current_domain() -> Option<String> {
    std::env::var("USERDOMAIN")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
}

/// 拆 "域\用户" / "user@domain" / "用户"
pub fn split_account(account: &str) -> (String, Option<String>) {
    if let Some((domain, user)) = account.split_once('\\') {
        if !domain.is_empty() && !user.is_empty() {
            return (user.to_string(), Some(domain.to_string()));
        }
    }
    if account.contains('@') {
        return (account.to_string(), None);
    }
    (account.to_string(), current_domain())
}

/// 用 LogonUser 校验账户密码（网络登录，不加载配置、不建用户配置目录）。
pub fn verify_password(account: &str, password: &str) -> Result<(), LogonError> {
    let (user, domain) = split_account(account);
    let user_w = wide_str(&user);
    let domain_w = domain.as_ref().map(|d| wide_str(d));
    let pass_w = wide_str(password);

    let mut token: HANDLE = ptr::null_mut();
    let ok = unsafe {
        LogonUserW(
            user_w.as_ptr(),
            domain_w
                .as_ref()
                .map(|d| d.as_ptr())
                .unwrap_or(ptr::null()),
            pass_w.as_ptr(),
            LOGON32_LOGON_NETWORK,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )
    };
    if ok != 0 {
        unsafe { CloseHandle(token) };
        return Ok(());
    }

    let code = last_error();
    match code {
        // 1326 登录失败 / 1330 密码过期 / 1907 必须改密码 / 1909 账户锁定
        1326 | 1330 | 1331 | 1907 | 1909 => Err(LogonError::Credentials),
        _ => Err(LogonError::Other(code, error_text(code))),
    }
}

/// 内置 Administrators 组的本地化名字（中文系统上也是 "Administrators"，
/// 但不同语言版本可能不一样，所以从知名 SID 反查）。
fn administrators_group_name() -> Option<String> {
    unsafe {
        let authority = SECURITY_NT_AUTHORITY;
        let mut admins: PSID = ptr::null_mut();
        if AllocateAndInitializeSid(
            &authority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID as u32,
            DOMAIN_ALIAS_RID_ADMINS as u32,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut admins,
        ) == 0
        {
            return None;
        }

        let mut name = [0u16; 256];
        let mut name_len = name.len() as u32;
        let mut domain = [0u16; 256];
        let mut domain_len = domain.len() as u32;
        let mut sid_type = 0i32;

        let ok = LookupAccountSidW(
            ptr::null(),
            admins,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut sid_type,
        );
        FreeSid(admins);
        if ok == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&name[..name_len as usize]))
    }
}

/// 某个账户是否在 Administrators 里（用于 `-l -U 别人` 这种查询）。
pub fn account_is_admin(account: &str) -> Result<bool, String> {
    let group = administrators_group_name()
        .ok_or_else(|| "无法解析内置管理员组名称".to_string())?;
    let (user, _) = split_account(account);
    let user_w = wide(OsStr::new(&user));

    unsafe {
        let mut buffer: *mut u8 = ptr::null_mut();
        let mut read = 0u32;
        let mut total = 0u32;
        let status = NetUserGetLocalGroups(
            ptr::null(),
            user_w.as_ptr(),
            0,
            1, // LG_INCLUDE_INDIRECT
            &mut buffer,
            u32::MAX,
            &mut read,
            &mut total,
        );
        if status != 0 {
            return Err(format!("无法查询 {user} 的组信息: {}", error_text(status)));
        }

        let entries = std::slice::from_raw_parts(
            buffer as *const LOCALGROUP_USERS_INFO_0,
            read as usize,
        );
        let mut is_admin = false;
        for entry in entries {
            if entry.lgrui0_name.is_null() {
                continue;
            }
            let mut len = 0usize;
            while *entry.lgrui0_name.add(len) != 0 {
                len += 1;
            }
            let name = String::from_utf16_lossy(std::slice::from_raw_parts(
                entry.lgrui0_name,
                len,
            ));
            if name.eq_ignore_ascii_case(&group) {
                is_admin = true;
                break;
            }
        }
        NetApiBufferFree(buffer as *const core::ffi::c_void);
        Ok(is_admin)
    }
}

/// 账户是否存在
pub fn account_exists(account: &str) -> bool {
    let (user, _) = split_account(account);
    let user_w = wide(OsStr::new(&user));
    let mut sid_len = 0u32;
    let mut domain_len = 0u32;
    let mut sid_type = 0i32;
    let code = unsafe {
        LookupAccountNameW(
            ptr::null(),
            user_w.as_ptr(),
            ptr::null_mut(),
            &mut sid_len,
            ptr::null_mut(),
            &mut domain_len,
            &mut sid_type,
        );
        last_error()
    };
    // ERROR_INSUFFICIENT_BUFFER：名字存在，只是需要缓冲区
    code == 122
}
