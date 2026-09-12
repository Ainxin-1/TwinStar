//! 用户配置持久化（JSON，存放在系统配置目录）。

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// 用户可调设置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub nickname: String,
    /// 接收目录；`None` 表示用默认（Downloads）。选目录后立即写回，重启保持。
    #[serde(default)]
    pub download_dir: Option<String>,
    /// 已授权设备名单（对端连接码 id，hex）。确认弹窗勾选"记住此设备"时追加，
    /// 之后的传输自动接收。纯本地存储，不涉及任何账号 / 云端。
    #[serde(default)]
    pub trusted_devices: Vec<String>,
    /// 首启引导是否已完成。老用户（升级前就有 settings.json，但文件里没有这个
    /// 字段）在 [`Config::load`] 里被识别并置真，不会被打扰。
    #[serde(default)]
    pub onboarded: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            nickname: whoami_nickname(),
            download_dir: None,
            trusted_devices: Vec::new(),
            onboarded: false,
        }
    }
}

/// 昵称的统一入口：去首尾空白、限长 24、拒控制字符。
/// 空串非法（发送端拿它编进元数据给对方看）。
pub fn validate_nickname(raw: &str) -> Result<String, String> {
    let name = raw.trim();
    if name.is_empty() {
        return Err("昵称不能为空".into());
    }
    if name.chars().any(char::is_control) {
        return Err("昵称不能包含控制字符".into());
    }
    if name.chars().count() > 24 {
        return Err("昵称最长 24 个字符".into());
    }
    Ok(name.to_string())
}

impl Config {
    fn file_path() -> Option<PathBuf> {
        // Android 上 dirs 系列全部返回 None（无 XDG 概念），退到应用私有目录——
        // 该路径由包名确定性推导，属于应用可写存储。
        let base = dirs::config_dir()
            .or_else(|| Some(PathBuf::from("/data/data/com.ainxin.twinstar/files")))?;
        Some(base.join("TwinStar").join("settings.json"))
    }

    pub fn load() -> Self {
        let Some(path) = Self::file_path() else {
            return Self::default();
        };
        if let Ok(raw) = std::fs::read_to_string(&path) {
            if let Ok(mut cfg) = serde_json::from_str::<Config>(&raw) {
                // 老用户的 settings.json 早于 onboarding 字段：视为已完成引导，
                // 升级后不被首启弹窗打扰。
                if !raw.contains("\"onboarded\"") {
                    cfg.onboarded = true;
                }
                return cfg;
            }
        }
        Self::default()
    }

    pub fn save(&self) -> Result<(), String> {
        let Some(path) = Self::file_path() else {
            return Err("无法获取配置目录".into());
        };
        let _ = std::fs::create_dir_all(path.parent().unwrap_or(&path));
        let raw = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, raw).map_err(|e| e.to_string())
    }

    /// 该设备是否在信任名单里。
    pub fn is_trusted(&self, peer_id: &str) -> bool {
        self.trusted_devices.iter().any(|x| x == peer_id)
    }

    /// 加入信任名单（幂等）。注意：只改内存副本，持久化由调用方 `save()` 负责。
    pub fn trust_device(&mut self, peer_id: &str) {
        if !peer_id.is_empty() && !self.is_trusted(peer_id) {
            self.trusted_devices.push(peer_id.to_string());
        }
    }
}

fn whoami_nickname() -> String {
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("USERNAME").ok().filter(|s| !s.is_empty()))
            .unwrap_or_else(|| "用户".into())
    }
    #[cfg(not(windows))]
    {
        // macOS / Linux 有 USER；Android 没有，退到机型名（getprop），再不行就"用户"。
        std::env::var("USER")
            .ok()
            .filter(|s| !s.is_empty() && s != "root")
            .or_else(|| {
                let out = std::process::Command::new("getprop")
                    .arg("ro.product.model")
                    .output()
                    .ok()?;
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if s.is_empty() { None } else { Some(s) }
            })
            .unwrap_or_else(|| "用户".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_and_roundtrip() {
        let cfg = Config::default();
        assert!(!cfg.nickname.is_empty());
        let json = serde_json::to_string(&cfg).unwrap();
        let back: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(back.nickname, cfg.nickname);
        assert!(back.download_dir.is_none());
        assert!(back.trusted_devices.is_empty());
    }

    #[test]
    fn download_dir_roundtrip_and_legacy_json() {
        // 新字段写读一致
        let cfg = Config {
            download_dir: Some("D:/recv".into()),
            ..Config::default()
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(back.download_dir.as_deref(), Some("D:/recv"));
        // 旧版 settings.json（只有 nickname）也能加载
        let legacy = serde_json::from_str::<Config>(&serde_json::json!({
            "nickname": "old-pc"
        })
        .to_string())
        .unwrap();
        assert_eq!(legacy.nickname, "old-pc");
        assert!(legacy.download_dir.is_none());
        assert!(legacy.trusted_devices.is_empty(), "旧配置应缺省为空信任名单");
    }

    #[test]
    fn trusted_devices_roundtrip_and_idempotent_trust() {
        let mut cfg = Config::default();
        cfg.trust_device("aaaa1111");
        cfg.trust_device("bbbb2222");
        cfg.trust_device("aaaa1111"); // 幂等：重复信任不重复入列
        assert_eq!(cfg.trusted_devices.len(), 2);
        assert!(cfg.is_trusted("aaaa1111"));
        assert!(cfg.is_trusted("bbbb2222"));
        assert!(!cfg.is_trusted("cccc3333"));
        cfg.trust_device(""); // 空 id 不入列
        assert_eq!(cfg.trusted_devices.len(), 2);
        // 序列化 → 反序列化保持
        let json = serde_json::to_string(&cfg).unwrap();
        let back: Config = serde_json::from_str(&json).unwrap();
        assert!(back.is_trusted("aaaa1111") && back.is_trusted("bbbb2222"));
    }

    #[test]
    fn legacy_config_without_onboarded_counts_as_onboarded() {
        // 首次使用（没有 settings.json）：默认值应为"未引导"
        assert!(!Config::default().onboarded);
        // 老用户升级：文件里没有 onboarded 字段 → load 后视为已引导，不被弹窗打扰
        let legacy = serde_json::json!({ "nickname": "old-pc" }).to_string();
        assert!(!legacy.contains("onboarded"));
        let cfg: Config = serde_json::from_str(&legacy).unwrap();
        assert!(!cfg.onboarded, "直接反序列化仍是缺省 false");
        // load() 里的文件级判断用字符串探测模拟：raw 不含 "onboarded" → 置真
        let mut loaded = cfg;
        if !legacy.contains("\"onboarded\"") {
            loaded.onboarded = true;
        }
        assert!(loaded.onboarded);
        // 新版写出的文件带该字段 → 原样保留
        let mut fresh = Config::default();
        assert!(!fresh.onboarded);
        fresh.onboarded = true;
        let raw = serde_json::to_string(&fresh).unwrap();
        assert!(raw.contains("\"onboarded\""));
    }

    #[test]
    fn nickname_validation_trims_limits_rejects() {
        assert_eq!(validate_nickname("  我的笔记本  ").unwrap(), "我的笔记本");
        assert_eq!(validate_nickname("ab").unwrap(), "ab");
        assert!(validate_nickname("   ").is_err(), "纯空白非法");
        assert!(validate_nickname("").is_err());
        assert!(validate_nickname("ab\u{7}c").is_err(), "控制字符非法");
        let long = "汉".repeat(25);
        assert!(validate_nickname(&long).is_err(), "25 个字符超限");
        let ok24 = "汉".repeat(24);
        assert_eq!(validate_nickname(&ok24).unwrap(), ok24);
        let long_ascii = "x".repeat(25);
        assert!(validate_nickname(&long_ascii).is_err());
    }
}
