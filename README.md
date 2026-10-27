## BetterSudo-Win32
**我解决了Windows命令行不能使用sudo的问题**

实现语言: <img src="https://img.shields.io/badge/Rust-353940?style=flat&logo=rust">
## 实现原理

### sudo

1. 解析命令行参数生成配置
2. 使用`auth::require`, `token::verify_password``LogonUserW(LOGON32_LOGON_NETWORK)`进行密码校验
3. 将请求编码为UTF-16
4. 设置fodhelper Bypass注册表，调用sudo-elevated使用刚刚的utf-16 hex载荷，并启动fodhelper.exe
5. 删除注册表
6. 使用`AttachConsole`打开`CONOUT$` 与 `CONIN$` 和 `SetStdHandle`
### su

1. 判断环境变量`SUDO_CONSOLE_PID`是否存在
2. 若启动时不带管理员，就使用`ShellExecuteExW(lpVerb="runas")`重写拉起
3. 拿走`winlogon.exe`的Token，使用`AdjustTokenPrivileges`打开`SeDebugPrivilege`和`SeImpersonatePrivilege`
4. `OpenProcess(PROCESS_QUERY_INFORMATION)`然后`OpenProcessToken`再`DuplicateTokenEx(TOKEN_ALL_ACCESS, TokenPrimary)`得到可用SYSTEM用户令牌
5. 剩下的步骤与sudo的第6步大致一致，不再讲述

## ScreenShots
如图:

<img src="https://static-global-res.iamexrfy.top/res/bettersudo_preview.png" width="75%" height="75%">