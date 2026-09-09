//! TwinStar 传输核心 —— 纯逻辑层（自 TwinStar v4.0.1 移植）
//!
//! 模块分层（上层依赖下层，禁止反向依赖）：
//!   - [`limits`]    协议常量与入站校验（一切越界输入在入口处拒绝）
//!   - [`path`]      相对路径安全化、目录逃逸防护
//!   - [`crypto`]    AES-256-GCM / PBKDF2 / SHA-256
//!
//! 注意：当前传输层由 iroh 承担，自研 UDP 通道（crypto/framing/handshake/message/limits/peer）
//! 暂未全部接入，因此这些模块有大量"未使用"符号。它们是为将来功能预留的协议库，
//! 不是垃圾代码，故在此整体放行 dead_code 警告，避免掩盖真正的告警。
#![allow(dead_code)]
//!   - [`identity`]  Ed25519 设备身份 + X25519 会话密钥协商
//!   - [`message`]   控制消息信封（JSON）
//!   - [`framing`]   明文帧与封装包编解码
//!   - [`handshake`] 设备认证状态机
//!   - [`peer`]      设备描述与序列化
//!   - [`config`]    本地配置
//!
//! 传输层由 iroh 承担（见 crate 根），不再使用原项目的自研 UDP 通道。

pub mod config;
pub mod crypto;
pub mod framing;
pub mod handshake;
pub mod identity;
pub mod limits;
pub mod message;
pub mod path;
pub mod peer;

// 便捷再导出
#[allow(unused_imports)]
pub use {
    crypto::{derive_key, random_passphrase, seal, sha256_hex},
    framing::{build_frame, parse_frame, unwrap_packet, wrap},
    handshake::Handshake,
    identity::DeviceIdentity,
    limits::*,
    message::{data_str, data_u64, Message, MessageType, PROTOCOL_VERSION},
    peer::PeerInfo,
    path::format_size,
};
