//! 用户配置持久化（JSON，存放在系统配置目录）。

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// 用户可调设置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub nickname: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            nickname: whoami_nickname(),
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
