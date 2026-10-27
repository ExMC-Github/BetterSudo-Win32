//! 用法提示与版本号。

/// 与 Linux 版 sudo 保持一致的用法提示（help 里列出的选项都已实现，
/// 少数 Windows 上不存在对应机制的选项会给出明确报错，见 cli.rs / main.rs）。
pub const USAGE: &str = "\
usage: sudo -h | -K | -k | -V
usage: sudo -v [-ABknS] [-g group] [-h host] [-p prompt] [-u user]
usage: sudo -l [-ABknS] [-g group] [-h host] [-p prompt] [-U user] [-u user] [command]
usage: sudo [-ABbEHknPS] [-r role] [-t type] [-C num] [-D directory] [-g group] [-h host] [-p prompt] [-R directory] [-T timeout] [-u user] [VAR=value] [-i|-s] [<command>]
usage: sudo -e [-ABknS] [-r role] [-t type] [-C num] [-D directory] [-g group] [-h host] [-p prompt] [-R directory] [-T timeout] [-u user] file ...";

pub const HELP_NOTE: &str = "\
Windows 版 sudo：命令在**当前终端**里以管理员身份运行（不再弹新窗口）。
首次在本终端里使用时需要输入当前 Windows 账户的密码，之后 15 分钟内免密；
换个终端（新的 cmd / Windows Terminal 标签页）就要重新输入。

-Windows 上不存在对应机制、因此无法生效的选项：
  -h host   远程主机（不支持）
  -r role   SELinux 角色（不支持）
  -t type   SELinux 类型（不支持）
  -R dir    chroot（不支持）";

pub fn version_line() -> String {
    format!("Sudo version {} (windows)", env!("CARGO_PKG_VERSION"))
}
