//! sudo for Windows 的内部库。
//!
//! 两个可执行文件共用这里的实现：
//! * `sudo.exe`          —— console 子系统，用户直接运行的那个
//! * `sudo-elevated.exe` —— GUI 子系统，被提权拉起后干活的那个

pub mod app;
pub mod auth;
pub mod cli;
pub mod console;
pub mod elevate;
pub mod launch;
pub mod payload;
pub mod registry;
pub mod su;
pub mod token;
pub mod usage;
pub mod win;
