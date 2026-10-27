//! 命令行入口（console 子系统）。
//!
//! 这个 exe 是用户直接敲 `sudo` 时运行的，**必须是 console 子系统**：
//! cmd.exe 只会等待 console 子系统程序，GUI 程序会被它当成"后台启动"，
//! 于是提示符立刻回来、和密码提示抢同一个终端，输出全乱。
//!
//! 真正被 fodhelper / UAC 拉起来做提权工作的是同目录下的
//! `sudo-elevated.exe`（GUI 子系统，永不创建控制台窗口，所以不会闪）。

fn main() {
    std::process::exit(sudo::app::main_console());
}
