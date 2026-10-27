//! `su` 的命令行入口（console 子系统）。
//!
//! 必须是 console 子系统：`sudo su` 时由提权实例就地启动，
//! 子进程（SYSTEM 的 cmd）继承当前控制台，输出和输入都留在同一个终端里。

fn main() {
    std::process::exit(sudo::su::main_console());
}
