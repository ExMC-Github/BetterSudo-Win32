//! 命令行解析。
//!
//! 用法提示里列出的每个选项都在这里被真正接住，语义见各字段注释。

use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Default)]
pub struct Options {
    pub help: bool,
    pub version: bool,
    pub validate: bool,
    pub list: bool,
    pub invalidate: bool,
    pub invalidate_all: bool,
    pub edit: bool,
    pub login: bool,
    pub shell: bool,
    pub preserve_env: bool,
    pub set_home: bool,
    pub background: bool,
    pub non_interactive: bool,
    pub stdin_password: bool,
    pub askpass: bool,
    pub no_bell: bool,
    pub preserve_groups: bool,

    pub prompt: Option<String>,
    pub user: Option<String>,
    pub other_user: Option<String>,
    pub group: Option<String>,
    pub close_from: Option<u32>,
    pub chdir: Option<PathBuf>,
    pub chroot: Option<String>,
    pub role: Option<String>,
    pub sel_type: Option<String>,
    pub host: Option<String>,
    pub timeout: Option<u64>,

    pub env: Vec<(OsString, OsString)>,
    pub command: Vec<OsString>,
}

fn looks_like_assignment(text: &str) -> bool {
    match text.split_once('=') {
        Some((name, _)) => {
            !name.is_empty()
                && name
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_alphabetic() || c == '_')
                    .unwrap_or(false)
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

pub fn parse(args: &[OsString]) -> Result<Options, String> {
    let mut options = Options::default();
    let mut index = 0;

    while index < args.len() {
        let text = args[index].to_string_lossy().into_owned();

        if text == "--" {
            options.command.extend_from_slice(&args[index + 1..]);
            break;
        }

        if let Some(long) = text.strip_prefix("--") {
            index += 1;
            let (name, inline) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value.to_string())),
                None => (long, None),
            };
            apply_long(&mut options, name, inline, args, &mut index)?;
            continue;
        }

        if text.len() > 1 && text.starts_with('-') {
            index += 1;
            let chars: Vec<char> = text.chars().skip(1).collect();
            let mut position = 0;
            while position < chars.len() {
                let flag = chars[position];
                position += 1;

                let needs_value = matches!(
                    flag,
                    'u' | 'g' | 'p' | 'C' | 'D' | 'R' | 'r' | 't' | 'T' | 'U' | 'h'
                );
                if !needs_value {
                    apply_flag(&mut options, flag)?;
                    continue;
                }

                // -h 单独出现是 help，带值才是远程主机
                let attached: Option<String> = if position < chars.len() {
                    let rest: String = chars[position..].iter().collect();
                    position = chars.len();
                    Some(rest)
                } else {
                    None
                };
                let value = match attached {
                    Some(value) => value,
                    None => match args.get(index) {
                        Some(value) => {
                            index += 1;
                            value.to_string_lossy().into_owned()
                        }
                        None => {
                            if flag == 'h' {
                                options.help = true;
                                continue;
                            }
                            return Err(format!("选项 -{flag} 需要一个参数"));
                        }
                    },
                };
                apply_value(&mut options, flag, value)?;
            }
            continue;
        }

        // 命令之前的 VAR=value 当作环境变量
        if options.command.is_empty() && looks_like_assignment(&text) {
            if let Some((name, value)) = text.split_once('=') {
                options.env.push((
                    OsString::from(name),
                    OsString::from(value),
                ));
            }
            index += 1;
            continue;
        }

        options.command.extend_from_slice(&args[index..]);
        break;
    }

    Ok(options)
}

fn apply_flag(options: &mut Options, flag: char) -> Result<(), String> {
    match flag {
        'h' => options.help = true,
        'V' => options.version = true,
        'v' => options.validate = true,
        'k' => options.invalidate = true,
        'K' => options.invalidate_all = true,
        'l' => options.list = true,
        'e' => options.edit = true,
        'i' => options.login = true,
        's' => options.shell = true,
        'E' => options.preserve_env = true,
        'H' => options.set_home = true,
        'b' => options.background = true,
        'n' => options.non_interactive = true,
        'S' => options.stdin_password = true,
        'A' => options.askpass = true,
        'B' => options.no_bell = true,
        'P' => options.preserve_groups = true,
        other => return Err(format!("invalid option -- '{other}'")),
    }
    Ok(())
}

fn apply_value(options: &mut Options, flag: char, value: String) -> Result<(), String> {
    match flag {
        'u' => options.user = Some(value),
        'U' => options.other_user = Some(value),
        'g' => options.group = Some(value),
        'p' => options.prompt = Some(value),
        'D' => options.chdir = Some(PathBuf::from(value)),
        'R' => options.chroot = Some(value),
        'r' => options.role = Some(value),
        't' => options.sel_type = Some(value),
        'h' => options.host = Some(value),
        'C' => {
            options.close_from = Some(
                value
                    .parse()
                    .map_err(|_| format!("-C 需要一个数字，收到 '{value}'"))?,
            )
        }
        'T' => {
            options.timeout = Some(
                value
                    .parse()
                    .map_err(|_| format!("-T 需要一个秒数，收到 '{value}'"))?,
            )
        }
        other => return Err(format!("invalid option -- '{other}'")),
    }
    Ok(())
}

fn apply_long(
    options: &mut Options,
    name: &str,
    inline: Option<String>,
    args: &[OsString],
    index: &mut usize,
) -> Result<(), String> {
    let mut take_value = |name: &str| -> Result<String, String> {
        match &inline {
            Some(value) => Ok(value.clone()),
            None => match args.get(*index) {
                Some(value) => {
                    *index += 1;
                    Ok(value.to_string_lossy().into_owned())
                }
                None => Err(format!("选项 --{name} 需要一个参数")),
            },
        }
    };

    match name {
        "help" => options.help = true,
        "version" => options.version = true,
        "validate" => options.validate = true,
        "reset-timestamp" => options.invalidate = true,
        "remove-timestamp" => options.invalidate_all = true,
        "list" => options.list = true,
        "edit" => options.edit = true,
        "login" => options.login = true,
        "shell" => options.shell = true,
        "preserve-env" => options.preserve_env = true,
        "set-home" => options.set_home = true,
        "background" => options.background = true,
        "non-interactive" => options.non_interactive = true,
        "stdin" => options.stdin_password = true,
        "askpass" => options.askpass = true,
        "no-bell" => options.no_bell = true,
        "preserve-groups" => options.preserve_groups = true,
        "user" => options.user = Some(take_value(name)?),
        "other-user" => options.other_user = Some(take_value(name)?),
        "group" => options.group = Some(take_value(name)?),
        "prompt" => options.prompt = Some(take_value(name)?),
        "chdir" => options.chdir = Some(PathBuf::from(take_value(name)?)),
        "chroot" => options.chroot = Some(take_value(name)?),
        "role" => options.role = Some(take_value(name)?),
        "type" => options.sel_type = Some(take_value(name)?),
        "host" => options.host = Some(take_value(name)?),
        "close-from" => {
            let value = take_value(name)?;
            options.close_from = Some(
                value
                    .parse()
                    .map_err(|_| format!("--close-from 需要一个数字，收到 '{value}'"))?,
            );
        }
        "timeout" => {
            let value = take_value(name)?;
            options.timeout = Some(
                value
                    .parse()
                    .map_err(|_| format!("--timeout 需要一个秒数，收到 '{value}'"))?,
            );
        }
        other => return Err(format!("unrecognized option '--{other}'")),
    }
    Ok(())
}
