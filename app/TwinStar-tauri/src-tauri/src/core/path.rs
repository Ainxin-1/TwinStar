//! 文件路径安全（对应 Dart 版 `file_transfer.dart`）。
//!
//! 对端声明的相对路径必须先经 [`validate_relative`] 严格校验，
//! 落盘前再经 [`is_inside`] 确认仍在下载目录内（纵深防御）。

use std::path::{Path, PathBuf};

use super::limits::{
    MAX_DIRECTORY_DEPTH, MAX_NAME_COMPONENT_LENGTH, MAX_RELATIVE_PATH_LENGTH,
};

/// Windows 保留设备名（不分大小写）。
const RESERVED: [&str; 15] = [
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2",
];

fn is_reserved(stem: &str) -> bool {
    let s = stem.to_ascii_lowercase();
    RESERVED.contains(&s.as_str())
        || (3..=4).contains(&s.len())
            && (s.starts_with("com") || s.starts_with("lpt"))
            && s.chars().skip(3).all(|c| c.is_ascii_digit())
}

/// 严格校验对端发来的相对路径。返回 `Err(原因)` 表示非法。
pub fn validate_relative(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("文件名为空".into());
    }
    if name.len() > MAX_RELATIVE_PATH_LENGTH {
        return Err("相对路径过长".into());
    }
    // 绝对路径 / UNC。
    if name.starts_with('/') || name.starts_with('\\') {
        return Err("不允许绝对路径".into());
    }
    // 盘符开头（C:、c:/ 等）。
    let b = name.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        return Err("不允许盘符路径".into());
    }

    let norm = name.replace('\\', "/");
    let parts: Vec<&str> = norm.split('/').collect();
    if parts.len() > MAX_DIRECTORY_DEPTH {
        return Err("目录层级过深".into());
    }
    for p in parts {
        if p.is_empty() {
            return Err("含空路径段".into());
        }
        if p == "." || p == ".." {
            return Err("含目录穿越片段".into());
        }
        if p.contains(':') {
            return Err("含非法冒号".into());
        }
        if p.chars()
            .any(|c| matches!(c, '<' | '>' | '"' | '|' | '?' | '*') || (c as u32) < 0x20)
        {
            return Err("含非法文件名字符".into());
        }
        if p.len() > MAX_NAME_COMPONENT_LENGTH {
            return Err("单层文件名过长".into());
        }
        let stem = p.split('.').next().unwrap_or(p);
        if is_reserved(stem) {
            return Err("含系统保留文件名".into());
        }
        if p.ends_with(' ') || p.ends_with('.') {
            return Err("文件名结尾非法".into());
        }
    }
    Ok(())
}

/// 安全化相对路径（仅在已通过 [`validate_relative`] 后使用）。
pub fn sanitize_relative(name: &str) -> String {
    if validate_relative(name).is_err() {
        return "unknown".into();
    }
    name.replace('\\', "/")
        .split('/')
        .collect::<Vec<_>>()
        .join(std::path::MAIN_SEPARATOR.to_string().as_str())
}

/// 词法规范化：折叠 `.` / `..` 段，统一分隔符。
///
/// 关键点：`std::fs::canonicalize` 只能解析**已存在**的路径。目标文件往往还没创建，
/// 直接 canonicalize 整条路径会失败并退化为纯词法拼接，从而漏掉"中间某层是
/// 指向外部的符号链接/目录联接"的情况。因此先解析存在的最长祖先，再拼回尾部。
fn canon(p: &Path) -> String {
    let mut base = p.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    while !base.exists() {
        match base.file_name().map(|n| n.to_os_string()) {
            Some(name) => {
                tail.push(name);
                if !base.pop() {
                    break;
                }
            }
            None => break,
        }
    }
    let mut resolved = std::fs::canonicalize(&base).unwrap_or_else(|_| base.clone());
    while let Some(name) = tail.pop() {
        resolved = resolved.join(name);
    }
    let raw = resolved.to_string_lossy().replace('\\', "/");
    let raw = raw.trim_end_matches('/').to_string();
    let leading = if raw.starts_with('/') { "/" } else { "" };
    let mut out: Vec<&str> = Vec::new();
    for seg in raw.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            if out.last().map(|s| *s != "..").unwrap_or(false) {
                out.pop();
            } else {
                out.push("..");
            }
        } else {
            out.push(seg);
        }
    }
    format!("{}{}", leading, out.join("/"))
}

/// 词法判断 `target` 是否位于 `root` 之内。
///
/// 必须先折叠 `.`/`..` 段再比较，否则 `root/../x` 会被前缀匹配误判为内部。
pub fn is_inside(root: &Path, target: &Path) -> bool {
    let r = canon(root);
    let t = canon(target);
    t == r || t.starts_with(&format!("{}/", r))
}

/// 在 `dir` 下生成不冲突的目标路径（如 `file (1).txt`）。
pub fn unique_path(dir: &Path, filename: &str) -> PathBuf {
    let mut candidate = dir.join(filename);
    if !candidate.exists() {
        return candidate;
    }
    let (base, ext) = match filename.rfind('.') {
        Some(0) | None => (filename.to_string(), String::new()),
        Some(i) => (filename[..i].to_string(), filename[i..].to_string()),
    };
    let mut i = 1;
    loop {
        candidate = dir.join(format!("{} ({}){}", base, i, ext));
        if !candidate.exists() {
            return candidate;
        }
        i += 1;
    }
}

pub fn basename(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    match normalized.rfind('/') {
        Some(i) => normalized[i + 1..].to_string(),
        None => normalized,
    }
}

pub fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{} B", bytes);
    }
    let kb = bytes as f64 / 1024.0;
    if kb < 1024.0 {
        return format!("{:.1} KB", kb);
    }
    let mb = kb / 1024.0;
    if mb < 1024.0 {
        return format!("{:.1} MB", mb);
    }
    format!("{:.2} GB", mb / 1024.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_rejected() {
        assert!(validate_relative("../evil.txt").is_err());
        assert!(validate_relative("a/../../b").is_err());
        assert!(validate_relative("C:/x").is_err());
        assert!(validate_relative("/etc/passwd").is_err());
        assert!(validate_relative("con.txt").is_err());
        assert!(validate_relative("ok/文件 (1).txt").is_ok());
    }

    #[test]
    fn containment_is_lexical() {
        assert!(is_inside(Path::new("/a/b"), Path::new("/a/b/c")));
        assert!(!is_inside(Path::new("/root"), Path::new("/root/../evil")));
    }
}
