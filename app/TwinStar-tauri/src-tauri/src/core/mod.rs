//! TwinStar 传输核心 —— 纯逻辑层
//!
//! 模块分层（上层依赖下层，禁止反向依赖）：
//!   - [`path`]      相对路径安全化、目录逃逸防护
//!   - [`identity`]  Ed25519 设备身份 + iroh 端点密钥派生
//!   - [`config`]    本地配置
//!
//! 传输与加密由 iroh 承担（QUIC/TLS 1.3，见 crate 根），本层只保留
//! 身份、路径安全等主链路真正在用的纯逻辑。

pub mod config;
pub mod identity;
pub mod path;
