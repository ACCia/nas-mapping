mod test;

use serde_json::Value;
use std::io::{self, BufRead, Write};
use std::time::Duration;

const SUBNET: &str = "10.15.0";
const PORT: u16 = 5001;

fn entry_url(server: &str) -> String {
    format!("https://{server}:{PORT}/webapi/entry.cgi")
}

/// SYNO.API.Auth 常见错误码的中文说明
fn auth_error_msg(code: i64) -> String {
    let meaning = match code {
        400 => "账号不存在或密码错误",
        401 => "账号已被停用",
        402 => "没有登录权限",
        403 => "需要两步验证",
        404 => "两步验证码错误",
        406 => "尝试次数过多，账号被临时锁定",
        407 => "密码已过期，需在 DSM 网页修改",
        _ => "未知错误",
    };
    format!("DSM 错误码 {code}：{meaning}")
}

async fn login(
    client: &reqwest::Client,
    server: &str,
    account: &str,
    passwd: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let resp: Value = client
        .get(entry_url(server))
        .query(&[
            ("api", "SYNO.API.Auth"),
            ("version", "6"),
            ("method", "login"),
            ("account", account),
            ("passwd", passwd),
            ("session", "FileStation"),
            ("format", "sid"),
        ])
        .send()
        .await?
        .json()
        .await?;

    if !resp["success"].as_bool().unwrap_or(false) {
        return Err(format!(
            "登录失败: {}",
            auth_error_msg(resp["error"]["code"].as_i64().unwrap_or(-1))
        )
        .into());
    }
    resp["data"]["sid"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "登录响应中缺少 sid".into())
}

async fn list_shares(
    client: &reqwest::Client,
    sid: &str,
    server: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let resp: Value = client
        .get(entry_url(server))
        .query(&[
            ("api", "SYNO.FileStation.List"),
            ("version", "2"),
            ("method", "list_share"),
            ("_sid", sid),
        ])
        .send()
        .await?
        .json()
        .await?;

    if !resp["success"].as_bool().unwrap_or(false) {
        return Err(format!(
            "列出共享失败: DSM 错误码 {}",
            resp["error"]["code"].as_i64().unwrap_or(-1)
        )
        .into());
    }

    Ok(resp["data"]["shares"]
        .as_array()
        .ok_or("响应中缺少 shares 数据")?
        .iter()
        .filter_map(|s| s["name"].as_str().map(|n| n.to_string()))
        .collect())
}

/// 探测单台主机是否为群晖 DSM
async fn probe_dsm(
    client: reqwest::Client,
    ip: String,
) -> Result<String, Box<dyn std::error::Error>> {
    let url = format!(
        "https://{ip}:{PORT}/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=SYNO.API.Auth"
    );
    let resp = client.get(&url).send().await?;
    let json: Value = resp.json().await?;
    if json["success"].as_bool().unwrap_or(false) {
        Ok(ip)
    } else {
        Err("非 DSM 服务".into())
    }
}

/// 扫描网段，返回开放了 DSM Web API（5001 端口）的主机列表
async fn scan_nas(client: &reqwest::Client) -> Vec<String> {
    let mut set = tokio::task::JoinSet::new();
    for i in 1u8..=254 {
        let ip = format!("{SUBNET}.{i}");
        let client = client.clone();
        set.spawn(async move {
            let probe = probe_dsm(client, ip);
            match tokio::time::timeout(Duration::from_millis(1500), probe).await {
                Ok(Ok(ip)) => Some(ip),
                _ => None,
            }
        });
    }

    let mut found = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(Some(ip)) = res {
            found.push(ip);
        }
    }
    // 按 IP 末段排序
    found.sort_by_key(|ip| ip.rsplit('.').next().and_then(|s| s.parse::<u8>().ok()).unwrap_or(0));
    found
}

// ==================== Windows：盘符 / 网络位置 ====================
#[cfg(windows)]
mod platform {
    use std::io::{self, BufRead, Write};
    use std::path::Path;
    use std::process::Command;

    pub fn prompt_operation() -> Option<u8> {
        let stdin = io::stdin();
        let mut line = String::new();
        println!("\n请选择映射方式：");
        println!("  1. 映射为盘符");
        println!("  2. 映射为网络位置");
        print!("请输入（直接回车退出）: ");
        io::stdout().flush().ok();
        stdin.lock().read_line(&mut line).ok()?;
        match line.trim() {
            "1" => Some(1),
            "2" => Some(2),
            "" => None,
            other => {
                println!("无效选项：{other}");
                None
            }
        }
    }

    fn pick_drive_letter() -> Option<char> {
        for code in (b'A'..=b'Z').rev() {
            let letter = code as char;
            if !Path::new(&format!("{letter}:\\")).exists() {
                return Some(letter);
            }
        }
        None
    }

    /// net use 在中文 Windows 上输出 GBK 编码，需要转码
    fn decode_gbk(bytes: &[u8]) -> String {
        let (decoded, _, _) = encoding_rs::GBK.decode(bytes);
        decoded.into_owned()
    }

    fn map_drive(server: &str, letter: char, share: &str, account: &str, passwd: &str) -> Result<(), String> {
        let drive = format!("{letter}:");
        let unc = format!(r"\\{server}\{share}");

        let output = Command::new("net")
            .args([
                "use",
                &drive,
                &unc,
                &format!("/user:{account}"),
                passwd,
                "/persistent:yes",
            ])
            .output()
            .map_err(|e| format!("执行 net use 失败: {e}"))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(decode_gbk(&output.stderr).trim().to_string())
        }
    }

    /// 通过"网络快捷方式"目录创建网络位置（此电脑 > 网络位置）
    fn map_network_location(server: &str, share: &str) -> Result<(), String> {
        // 显示名称带服务器前缀，如 "10.15.0.2-home"
        let display_name = format!("{server}-{share}");
        let appdata = std::env::var("APPDATA").map_err(|_| "未找到 APPDATA 环境变量".to_string())?;
        let place_dir = Path::new(&appdata)
            .join("Microsoft")
            .join("Windows")
            .join("Network Shortcuts")
            .join(&display_name);
        let unc = format!(r"\\{server}\{share}");

        std::fs::create_dir_all(&place_dir).map_err(|e| format!("创建目录失败: {e}"))?;

        // CLSID2 指向网络连接点对象，Flags=2 使其显示在"此电脑 > 网络位置"
        std::fs::write(
            place_dir.join("desktop.ini"),
            "[.ShellClassInfo]\r\nCLSID2={0AFACED1-E828-11D1-9187-B532F1E9575D}\r\nFlags=2\r\n",
        )
        .map_err(|e| format!("写入 desktop.ini 失败: {e}"))?;

        let lnk = place_dir.join("target.lnk");
        let script = format!(
            "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{}'); $s.TargetPath='{}'; $s.Save()",
            lnk.display(),
            unc
        );
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .output()
            .map_err(|e| format!("创建快捷方式失败: {e}"))?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
        }

        // desktop.ini 需要隐藏+系统属性，文件夹需要系统属性才能被识别为网络位置
        let dir_str = place_dir.as_os_str().to_string_lossy().into_owned();
        let ini_str = place_dir.join("desktop.ini").as_os_str().to_string_lossy().into_owned();
        let _ = Command::new("attrib").args(["+s", &dir_str]).output();
        let _ = Command::new("attrib").args(["+s", "+h", &ini_str]).output();

        Ok(())
    }

    pub fn perform_mapping(
        server: &str,
        shares: &[&str],
        account: &str,
        passwd: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Some(op) = prompt_operation() else {
            println!("已退出。");
            return Ok(());
        };

        for share in shares {
            match op {
                1 => {
                    let Some(letter) = pick_drive_letter() else {
                        println!("\n没有可用的盘符（A-Z 全部被占用），跳过 {share}");
                        continue;
                    };
                    print!("\n正在映射 {share} -> {letter}: ... ");
                    io::stdout().flush().ok();
                    match map_drive(server, letter, share, account, passwd) {
                        Ok(()) => println!("成功！已映射为 {letter}: 盘（重启后仍有效）。"),
                        Err(e) => println!("失败：{e}"),
                    }
                }
                2 => {
                    print!("\n正在创建网络位置 {server}-{share} ... ");
                    io::stdout().flush().ok();
                    match map_network_location(server, share) {
                        Ok(()) => println!("成功！已添加到\"此电脑 > 网络位置\"（如未显示请刷新窗口）。"),
                        Err(e) => println!("失败：{e}"),
                    }
                }
                _ => unreachable!(),
            }
        }
        Ok(())
    }
}

// ==================== macOS：osascript 挂载（走系统 NetFS 通道） ====================
#[cfg(target_os = "macos")]
mod platform {
    use std::path::Path;
    use std::process::Command;

    /// RFC 3986 percent-encoding（用于 smb URL 的 userinfo 和路径）
    fn url_encode(s: &str) -> String {
        let mut out = String::new();
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    out.push(b as char)
                }
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }

    pub fn perform_mapping(
        server: &str,
        shares: &[&str],
        account: &str,
        passwd: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for share in shares {
            println!("\n正在挂载 {share} ...");
            let url = format!(
                "smb://{}:{}@{}/{}",
                url_encode(account),
                url_encode(passwd),
                server,
                url_encode(share)
            );
            let script = format!("mount volume \"{url}\"");
            let output = Command::new("osascript")
                .args(["-e", &script])
                .output()
                .map_err(|e| format!("执行 osascript 失败: {e}"))?;

            if output.status.success() {
                println!("成功！{share} 已挂载（Finder 侧边栏\"位置\"中可见）。");
                continue;
            }

            // 回退：无 GUI 会话等场景下用 mount_smbfs 挂到 ~/Volumes/{share}
            println!(
                "osascript 挂载失败（{}），尝试回退方案...",
                String::from_utf8_lossy(&output.stderr).trim()
            );
            let home = std::env::var("HOME").map_err(|_| "未找到 HOME 环境变量".to_string())?;
            let mp = Path::new(&home).join("Volumes").join(share);
            std::fs::create_dir_all(&mp).map_err(|e| format!("创建挂载点失败: {e}"))?;
            let direct = format!("smb://{}:{}@{}/{}", url_encode(account), url_encode(passwd), server, url_encode(share));
            let output = Command::new("mount_smbfs")
                .args([&direct, &mp.to_string_lossy().into_owned()])
                .output()
                .map_err(|e| format!("执行 mount_smbfs 失败: {e}"))?;

            if output.status.success() {
                println!("成功！已挂载到 {}", mp.display());
            } else {
                let _ = std::fs::remove_dir(&mp);
                println!("失败：{}", String::from_utf8_lossy(&output.stderr).trim());
            }
        }
        Ok(())
    }
}

/// 解析多选输入，如 "1,3-5 9"，返回下标列表；解析失败返回 None
fn parse_selections(input: &str, max: usize) -> Option<Vec<usize>> {
    let mut seen = std::collections::BTreeSet::new();
    for part in input.split(|c: char| c == ',' || c == '，' || c == '、' || c == ' ') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let a: usize = a.trim().parse().ok()?;
            let b: usize = b.trim().parse().ok()?;
            if a == 0 || b < a || b > max {
                return None;
            }
            for n in a..=b {
                seen.insert(n - 1);
            }
        } else {
            let n: usize = part.parse().ok()?;
            if n == 0 || n > max {
                return None;
            }
            seen.insert(n - 1);
        }
    }
    if seen.is_empty() {
        None
    } else {
        Some(seen.into_iter().collect())
    }
}

/// 服务器选择仍是单选
fn prompt_choice(labels: &[String], what: &str) -> Option<usize> {
    let stdin = io::stdin();
    let mut line = String::new();
    print!("请输入要{}的编号（直接回车退出）: ", what);
    io::stdout().flush().ok();
    stdin.lock().read_line(&mut line).ok()?;
    let input = line.trim();
    if input.is_empty() {
        return None;
    }
    match input.parse::<usize>() {
        Ok(n) if (1..=labels.len()).contains(&n) => Some(n - 1),
        _ => {
            println!("无效编号：{input}");
            None
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    print!("请输入 NAS 账号: ");
    io::stdout().flush().ok();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let account = buf.trim().to_string();
    if account.is_empty() {
        return Err("未输入账号".into());
    }
    // 密码可先用环境变量 NAS_PASS 传入（便于脚本调用），否则交互输入且不回显
    let passwd = match std::env::var("NAS_PASS") {
        Ok(p) if !p.is_empty() => p,
        _ => {
            print!("请输入密码: ");
            io::stdout().flush().ok();
            rpassword::read_password()?
        }
    };

    // 群晖使用自签名证书，需跳过校验
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    println!("正在扫描 {SUBNET}.0/24 网段的群晖服务...");
    let servers = scan_nas(&client).await;
    if servers.is_empty() {
        return Err(format!("未在 {SUBNET}.0/24 网段发现可用的群晖 DSM 服务").into());
    }

    println!("\n可用的群晖 DSM 服务：");
    for (idx, server) in servers.iter().enumerate() {
        println!("  {:>2}. https://{}:{}", idx + 1, server, PORT);
    }

    let server = if servers.len() == 1 {
        println!("\n仅发现一台，自动选择 {}", servers[0]);
        servers[0].clone()
    } else {
        let Some(choice) = prompt_choice(&servers, "连接") else {
            println!("已退出。");
            return Ok(());
        };
        servers[choice].clone()
    };

    let sid = login(&client, &server, &account, &passwd).await?;
    let shares = list_shares(&client, &sid, &server).await?;

    println!("\n服务器 {} 上当前用户（{account}）可访问的共享（共 {} 个）：", server, shares.len());
    for (idx, share) in shares.iter().enumerate() {
        println!("  {:>2}. {}", idx + 1, share);
    }

    // 循环映射：每轮可输入多个编号（如 1,3-5），完成后回到共享列表，回车退出
    loop {
        print!("\n请输入要映射的编号（可多个，如 1,3-5；直接回车退出）: ");
        io::stdout().flush().ok();
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        let input = line.trim();
        if input.is_empty() {
            println!("已退出。");
            break;
        }
        let Some(selection) = parse_selections(input, shares.len()) else {
            println!("无效输入：{input}");
            continue;
        };
        let selected: Vec<&str> = selection.iter().map(|&i| shares[i].as_str()).collect();

        if let Err(e) = platform::perform_mapping(&server, &selected, &account, &passwd) {
            println!("出错：{e}");
        }
    }

    // 登出 DSM 会话
    let _ = client
        .get(entry_url(&server))
        .query(&[
            ("api", "SYNO.API.Auth"),
            ("version", "6"),
            ("method", "logout"),
            ("session", "FileStation"),
            ("_sid", sid.as_str()),
        ])
        .send()
        .await;
    Ok(())
}
