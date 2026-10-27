//! 主流程：解析选项 → 认证 → 提权 → 执行。

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use crate::cli::Options;
use crate::payload::{Request, FLAG_DETACHED, FLAG_SET_HOME};
use crate::{auth, cli, console, elevate, launch, payload, su, token, usage, win};

/// console 子系统的入口
pub fn main_console() -> i32 {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();

    // 万一有人把它当提权进程直接调起来（比如注册表指向了 sudo.exe），也照常干活
    if args
        .first()
        .map(|arg| arg.as_os_str() == payload::FLAG)
        .unwrap_or(false)
    {
        return elevate::elevated_entry(args.get(1).map(|arg| arg.as_os_str()));
    }

    run(args)
}

fn fail(message: &str) -> i32 {
    if console::has_console() {
        console::err(&format!("sudo: {message}\r\n"));
    } else {
        // 连控制台都没有（从 GUI / 计划任务里启动），错误只能弹窗
        console::message_box(message);
    }
    1
}

fn run(args: Vec<OsString>) -> i32 {
    let options = match cli::parse(&args) {
        Ok(options) => options,
        Err(message) => {
            if console::has_console() {
                console::err(&format!("sudo: {message}\r\n"));
                console::err(&format!("{}\r\n", usage::USAGE));
            } else {
                console::message_box(&message);
            }
            return 1;
        }
    };

    if options.help {
        console::out(&format!("{}\r\n\r\n{}\r\n", usage::USAGE, usage::HELP_NOTE));
        return 0;
    }
    if options.version {
        console::out(&format!("{}\r\n", usage::version_line()));
        return 0;
    }

    // Windows 上没有对应机制的选项：明确报错，而不是默默忽略
    if options.host.is_some() {
        return fail("-h host（远程主机）在 Windows 版里没有实现");
    }
    if options.role.is_some() || options.sel_type.is_some() {
        return fail("SELinux 的角色 / 类型（-r / -t）在 Windows 上不存在");
    }
    if options.chroot.is_some() {
        return fail("chroot（-R）在 Windows 上不存在；要换目录请用 -D");
    }

    let account = options
        .other_user
        .clone()
        .unwrap_or_else(token::current_account);

    // -k / -K：清时间戳，没跟命令就直接结束
    if options.invalidate || options.invalidate_all {
        if options.invalidate_all {
            auth::clear_all();
        } else {
            auth::clear_current(&account);
        }
        if options.command.is_empty() && !options.list && !options.validate {
            return 0;
        }
    }

    // -l：列出权限
    if options.list {
        return list(&account);
    }

    // -v：刷新时间戳
    if options.validate {
        let request = auth::AuthRequest {
            user: &account,
            prompt: options.prompt.as_deref(),
            non_interactive: options.non_interactive,
            from_stdin: options.stdin_password,
            askpass: options.askpass,
        };
        return match auth::require(&request) {
            Ok(()) => 0,
            Err(message) => fail(&message),
        };
    }

    if options.command.is_empty() && !options.login {
        if console::has_console() {
            console::err(&format!("{}\r\n", usage::USAGE));
        }
        return 1;
    }

    let command = match build_command(&options) {
        Ok(command) => command,
        Err(message) => return fail(&message),
    };

    let cwd = match &options.chdir {
        Some(dir) => {
            if !dir.is_dir() {
                return fail(&format!("目录不存在: {}", dir.display()));
            }
            dir.clone()
        }
        None => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    };

    // -u 换成另一个账户：这条路不走 UAC，需要那个账户自己的密码
    let other = options
        .user
        .clone()
        .filter(|user| !user.eq_ignore_ascii_case(&token::current_account()));
    if let Some(target) = other {
        if options.group.is_some() {
            return fail("-u 与 -g 不能同时使用");
        }
        return run_as_other(&target, &options, command, cwd);
    }

    // 有没有可以交互的终端，决定了走哪条提权路：
    //   有  → 劫持 ms-settings + fodhelper 静默提权，前面加一道密码提示（sudo 的味道）
    //   没有 → 直接用 ShellExecute 的 runas 动词，弹 Windows 原生 UAC，不问密码（也没地方问）
    let interactive = console::has_console();

    if !token::is_elevated() && !token::in_admin_group() {
        return fail("当前用户不在 Administrators 组中，无法提权");
    }

    if interactive {
        let auth_user = token::current_account();
        let auth_request = auth::AuthRequest {
            user: &auth_user,
            prompt: options.prompt.as_deref(),
            non_interactive: options.non_interactive,
            from_stdin: options.stdin_password,
            askpass: options.askpass,
        };
        if let Err(message) = auth::require(&auth_request) {
            return fail(&message);
        }
    }

    let detached = options.background;
    let flags = (if detached { FLAG_DETACHED } else { 0 })
        | (if options.set_home { FLAG_SET_HOME } else { 0 });

    // 本来就在管理员令牌里，直接就地跑
    if token::is_elevated() {
        let mut env = options.env.clone();
        env.push((
            OsString::from(su::CONSOLE_PID_ENV),
            OsString::from(win::parent_pid().to_string()),
        ));
        let job = launch::Job {
            command,
            cwd: Some(cwd),
            env,
            set_home: options.set_home,
            detached,
            timeout: options.timeout.map(Duration::from_secs),
            new_console: !interactive,
            credentials: None,
            group: options.group.clone().map(OsString::from),
        };
        return match launch::run(&job) {
            Ok(code) => code,
            Err(message) => fail(&message),
        };
    }

    let request = Request {
        parent_pid: win::parent_pid(),
        flags,
        timeout: options.timeout.unwrap_or(0),
        cwd,
        rc_path: elevate::new_rc_path(),
        env: options.env.clone(),
        group: options.group.clone().map(OsString::from),
        command,
    };

    let strategy = if interactive {
        elevate::Strategy::Hijack
    } else {
        elevate::Strategy::Uac
    };

    match elevate::request(&request, strategy) {
        Ok(code) => code,
        Err(message) => fail(&message),
    }
}

/// 组装真正要执行的命令行
fn build_command(options: &Options) -> Result<Vec<OsString>, String> {
    if options.edit {
        if options.command.is_empty() {
            return Err("没有要编辑的文件".into());
        }
        let mut parts = split_words(&editor());
        parts.extend(options.command.iter().cloned());
        return Ok(parts);
    }

    if options.login {
        return Ok(vec![shell_path()]);
    }

    if options.shell {
        let mut joined = OsString::new();
        for (index, part) in options.command.iter().enumerate() {
            if index > 0 {
                joined.push(" ");
            }
            let text = part.to_string_lossy();
            if text.contains(' ') {
                joined.push(format!("\"{text}\""));
            } else {
                joined.push(text.as_ref());
            }
        }
        return Ok(vec![shell_path(), OsString::from("/c"), joined]);
    }

    if options.command.is_empty() {
        return Err("没有要执行的命令".into());
    }
    Ok(options.command.clone())
}

fn shell_path() -> OsString {
    if let Some(comspec) = std::env::var_os("COMSPEC") {
        return comspec;
    }
    match std::env::var_os("SystemRoot") {
        Some(root) => {
            let mut path = PathBuf::from(root);
            path.push("System32");
            path.push("cmd.exe");
            path.into_os_string()
        }
        None => OsString::from(r"C:\Windows\System32\cmd.exe"),
    }
}

fn editor() -> String {
    for key in ["SUDO_EDITOR", "VISUAL", "EDITOR"] {
        if let Ok(value) = std::env::var(key) {
            if !value.trim().is_empty() {
                return value;
            }
        }
    }
    "notepad.exe".to_string()
}

fn split_words(text: &str) -> Vec<OsString> {
    text.split_whitespace().map(OsString::from).collect()
}

fn run_as_other(target: &str, options: &Options, command: Vec<OsString>, cwd: PathBuf) -> i32 {
    if !token::account_exists(target) {
        return fail(&format!("账户不存在: {target}"));
    }
    let prompt = format!("[sudo] password for {target}: ");
    let password = match console::read_secret(&prompt) {
        Some(value) => value,
        None => return fail("没有可用的终端读取密码"),
    };

    let job = launch::Job {
        command,
        cwd: Some(cwd),
        env: options.env.clone(),
        set_home: options.set_home,
        detached: options.background,
        timeout: options.timeout.map(Duration::from_secs),
        new_console: true,
        credentials: Some((target.to_string(), password)),
        group: None,
    };
    match launch::run(&job) {
        Ok(code) => code,
        Err(message) => fail(&message),
    }
}

fn list(account: &str) -> i32 {
    let is_self = account.eq_ignore_ascii_case(&token::current_account());
    let admin = if is_self {
        token::in_admin_group()
    } else {
        match token::account_is_admin(account) {
            Ok(value) => value,
            Err(message) => return fail(&message),
        }
    };

    let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "localhost".into());
    if admin {
        console::out(&format!("用户 {account} 可以在 {host} 上运行以下命令：\r\n"));
        console::out("    (ALL : ALL) ALL\r\n");
        0
    } else {
        console::out(&format!("用户 {account} 不在管理员组中，无法提权。\r\n"));
        1
    }
}
