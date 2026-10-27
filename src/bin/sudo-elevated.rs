//! 提权工作进程（GUI 子系统）。
//!
//! 由 fodhelper（静默提权）或 ShellExecute 的 runas 动词（原生 UAC）拉起来，
//! 运行在管理员令牌下。因为本 exe 是 GUI 子系统，被拉起时不会分配任何
//! 控制台窗口，所以整个过程看不到窗口闪烁；需要输出时再挂到父终端上。

#![windows_subsystem = "windows"]

fn main() {
    let payload = std::env::args_os().nth(2);
    std::process::exit(sudo::elevate::elevated_entry(payload.as_deref()));
}
