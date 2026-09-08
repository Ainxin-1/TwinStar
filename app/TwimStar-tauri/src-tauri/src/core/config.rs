//! 用户配置持久化（JSON，存放在系统配置目录）。

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// 用户可调设置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub nickname: String,
    pub download_dir: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            nickname: whoami_nickname(),
            download_dir: dirs::download_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("TwinStar"),
        }
    }
}

impl Config {
    fn file_path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("TwinStar").join("settings.json"))
    }

    pub fn load() -> Self {
        let Some(path) = Self::file_path() else {
            return Self::default();
        };
        if let Ok(raw) = std::fs::read_to_string(&path) {
            if let Ok(cfg) = serde_json::from_str::<Config>(&raw) {
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
}

fn whoami_nickname() -> String {
    std::env::var("COMPUTERNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("USERNAME").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "用户".into())
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
    }
}
