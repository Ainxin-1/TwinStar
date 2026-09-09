//! 双向设备认证握手（对应 Dart 版 `handshake.dart`）。
//!
//! 协议（v2，双方角色对称，连接建立后立即执行，认证通过前不转发任何业务消息）：
//!
//! 1. 双方各自生成 32B 随机挑战 nonce 和一对临时 X25519 密钥，发送
//!    `authChallenge {n, x, v}`；
//! 2. 收到对端挑战后，用自己的 Ed25519 私钥对"双方 nonce + 双方临时公钥"签名，
//!    返回 `authResponse {n(回显), p, x, s, d, v}`；
//! 3. 验证方复算 `deviceId = SHA256(p)`，校验 `d`、可选的期望 peerId/公钥，
//!    用 `p` 验证签名；通过后做 X25519 ECDH，再用 HKDF-SHA256 派生
//!    AES-256-GCM 传输密钥。
//!
//! 安全性质：挑战随机一次性 → 防重放；签名绑定双方 nonce 与双方临时公钥 →
//! 防跨连接反射、防 ECDH 中间人；主动连接方校验期望 deviceId → 改 peer.id
//! 冒充会被拒绝；被动方的 peerId 由"验证通过的公钥"派生，不信任自报字段。

use base64::Engine;
use serde_json::{json, Value};

use super::identity::{ct_eq, secure_random, DeviceIdentity, EphemeralX25519, SessionKeys};
use super::identity::DEVICE_AUTH_DOMAIN;
use super::message::{is_connection_version_supported, Message, MessageType, PROTOCOL_VERSION};

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakePhase {
    Running,
    Authed,
    /// 失败以 [`Outcome::failed`] 上报，阶段枚举不落 Failed。
    #[allow(dead_code)]
    Failed,
}

#[derive(Debug, Clone)]
pub struct HandshakeResult {
    /// 由对端静态公钥派生并验证过的对端 deviceId（连接身份以此为准）。
    pub peer_id: String,
    pub peer_static_pub: [u8; 32],
    /// 仅本连接有效的 AES-256-GCM 传输密钥。
    pub transport_key: [u8; 32],
}

/// 握手处理产出：待发送消息 + 认证/失败结果。
#[derive(Debug, Default)]
pub struct Outcome {
    pub send: Vec<Message>,
    pub authed: Option<HandshakeResult>,
    pub failed: Option<String>,
}

pub struct Handshake {
    me: std::sync::Arc<DeviceIdentity>,
    expected_peer_id: Option<String>,
    expected_peer_pub_b64: Option<String>,
    my_nonce: [u8; 32],
    my_eph: EphemeralX25519,
    peer_nonce: Option<[u8; 32]>,
    peer_eph: Option<[u8; 32]>,
    pub phase: HandshakePhase,
    result: Option<HandshakeResult>,
    early: Vec<Message>,
    started: bool,
}

impl Handshake {
    pub fn new(
        me: std::sync::Arc<DeviceIdentity>,
        expected_peer_id: Option<String>,
        expected_peer_pub_b64: Option<String>,
    ) -> Self {
        let my_nonce: [u8; 32] = secure_random(32).try_into().expect("32 字节");
        Self {
            me,
            expected_peer_id,
            expected_peer_pub_b64,
            my_nonce,
            my_eph: EphemeralX25519::generate(),
            peer_nonce: None,
            peer_eph: None,
            phase: HandshakePhase::Running,
            result: None,
            early: Vec::new(),
            started: false,
        }
    }

    pub fn is_settled(&self) -> bool {
        self.phase != HandshakePhase::Running
    }

    /// 启动：发送 authChallenge，并补处理握手材料就绪前排队的消息。
    pub fn start(&mut self) -> Outcome {
        let mut out = Outcome::default();
        if self.is_settled() {
            return out;
        }
        self.started = true;
        out.send.push(self.challenge());
        let queued = std::mem::take(&mut self.early);
        for msg in queued {
            if self.is_settled() {
                break;
            }
            let o = self.handle(&msg);
            out.send.extend(o.send);
            out.authed = o.authed.or(out.authed);
            out.failed = o.failed.or(out.failed);
        }
        out
    }

    /// 挑战重传（响应丢失时安全：Ed25519 签名确定性，重复发送同一响应无副作用）。
    pub fn resend(&self) -> Vec<Message> {
        if self.phase == HandshakePhase::Running {
            vec![self.challenge()]
        } else {
            Vec::new()
        }
    }

    fn challenge(&self) -> Message {
        let mut m = Message::new(MessageType::AuthChallenge);
        m.from_id = self.me.device_id.clone();
        m.data.insert("n".into(), json!(B64.encode(self.my_nonce)));
        m.data.insert("x".into(), json!(B64.encode(self.my_eph.public_key)));
        m.data.insert("v".into(), json!(PROTOCOL_VERSION));
        m
    }

    /// 处理一条认证消息；返回是否被握手消费（非认证消息返回 `None`）。
    pub fn handle(&mut self, msg: &Message) -> Outcome {
        let mut out = Outcome::default();
        if msg.kind != MessageType::AuthChallenge && msg.kind != MessageType::AuthResponse {
            return out;
        }
        if self.is_settled() {
            return out; // 握手结束后的认证消息直接吞掉
        }
        if !self.started {
            self.early.push(msg.clone());
            return out;
        }
        match msg.kind {
            MessageType::AuthChallenge => {
                if let Err(reason) = self.on_challenge(msg, &mut out.send) {
                    out.failed = Some(reason);
                }
            }
            MessageType::AuthResponse => {
                if let Err(reason) = self.on_response(msg) {
                    out.failed = Some(reason);
                } else if let Ok(Some(result)) = self.take_authed() {
                    out.authed = Some(result);
                }
            }
            _ => {}
        }
        out
    }

    fn on_challenge(&mut self, msg: &Message, send: &mut Vec<Message>) -> Result<(), String> {
        if !is_connection_version_supported(msg.data.get("v").and_then(Value::as_u64).map(|v| v as u32)) {
            return Err("协议版本不兼容".into());
        }
        let n = decode_fixed(msg.data.get("n"), 32).ok_or("挑战字段非法")?;
        let x = decode_fixed(msg.data.get("x"), 32).ok_or("挑战字段非法")?;
        if let Some(prev) = self.peer_nonce {
            if !ct_eq(&prev, &n) {
                return Err("对端挑战 nonce 不一致".into());
            }
        }
        if let Some(prev) = self.peer_eph {
            if !ct_eq(&prev, &x) {
                return Err("对端临时公钥不一致".into());
            }
        }
        self.peer_nonce = Some(n);
        self.peer_eph = Some(x);
        send.push(self.response()?);
        Ok(())
    }

    fn response(&self) -> Result<Message, String> {
        let (peer_nonce, peer_eph) = match (self.peer_nonce, self.peer_eph) {
            (Some(n), Some(x)) => (n, x),
            _ => return Err("缺少对端挑战上下文".into()),
        };
        let payload = signed_payload(&self.my_nonce, &self.my_eph.public_key, &peer_nonce, &peer_eph);
        let sig = self.me.sign(&payload);
        let mut m = Message::new(MessageType::AuthResponse);
        m.from_id = self.me.device_id.clone();
        m.data.insert("n".into(), json!(B64.encode(peer_nonce)));
        m.data.insert("p".into(), json!(self.me.public_key_base64()));
        m.data.insert("x".into(), json!(B64.encode(self.my_eph.public_key)));
        m.data.insert("s".into(), json!(B64.encode(sig)));
        m.data.insert("d".into(), json!(self.me.device_id));
        m.data.insert("v".into(), json!(PROTOCOL_VERSION));
        Ok(m)
    }

    fn on_response(&mut self, msg: &Message) -> Result<(), String> {
        if !is_connection_version_supported(msg.data.get("v").and_then(Value::as_u64).map(|v| v as u32)) {
            return Err("协议版本不兼容".into());
        }
        let (peer_nonce, peer_eph) = match (self.peer_nonce, self.peer_eph) {
            (Some(n), Some(x)) => (n, x),
            _ => return Err("缺少对端挑战上下文".into()),
        };
        // 1) 必须原样回显我发出的挑战（一次性、随机 → 防重放）。
        let echo = decode_fixed(msg.data.get("n"), 32).ok_or("认证响应字段非法")?;
        if !ct_eq(&echo, &self.my_nonce) {
            return Err("挑战回显不匹配（可能为重放）".into());
        }
        // 2) 字段长度严格校验。
        let p = decode_fixed(msg.data.get("p"), 32).ok_or("认证响应字段非法")?;
        let x = decode_fixed(msg.data.get("x"), 32).ok_or("认证响应字段非法")?;
        let s = decode_sig(msg.data.get("s")).ok_or("认证响应字段非法")?;
        let d = msg.data.get("d").and_then(Value::as_str).ok_or("认证响应字段非法")?;
        // 3) 响应中的临时公钥必须与挑战中一致（防 ECDH 替换）。
        if !ct_eq(&x, &peer_eph) {
            return Err("临时公钥与挑战不一致".into());
        }
        // 4) deviceId 必须由静态公钥派生；主动方还要匹配期望身份。
        let derived = DeviceIdentity::derive_device_id(&p);
        if derived != d {
            return Err("deviceId 与公钥不一致".into());
        }
        if let Some(expected) = &self.expected_peer_id {
            if *expected != derived {
                return Err("对端身份与期望 deviceId 不一致".into());
            }
        }
        if let Some(expected) = &self.expected_peer_pub_b64 {
            if *expected != B64.encode(p) {
                return Err("对端公钥与期望公钥不一致".into());
            }
        }
        // 5) 复算签名载荷并验证 Ed25519 签名。
        let payload = signed_payload(&peer_nonce, &peer_eph, &self.my_nonce, &self.my_eph.public_key);
        if !DeviceIdentity::verify(&p, &payload, &s) {
            return Err("设备签名验证失败".into());
        }
        // 6) X25519 ECDH → HKDF 派生传输密钥。
        let ecdh = self.my_eph.shared_secret(&x)?;
        let info = SessionKeys::build_transport_info(&self.me.public_key, &p);
        let key = SessionKeys::derive_transport_key(&ecdh, &info, &[])?;
        self.result = Some(HandshakeResult {
            peer_id: derived,
            peer_static_pub: p,
            transport_key: key,
        });
        self.phase = HandshakePhase::Authed;
        Ok(())
    }

    fn take_authed(&mut self) -> Result<Option<HandshakeResult>, String> {
        Ok(self.result.take())
    }
}

/// 签名载荷：域分隔 + 签名方 nonce/临时公钥 + 验证方 nonce/临时公钥。
fn signed_payload(signer_nonce: &[u8], signer_eph: &[u8], peer_nonce: &[u8], peer_eph: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DEVICE_AUTH_DOMAIN.len() + 128);
    out.extend_from_slice(DEVICE_AUTH_DOMAIN);
    out.extend_from_slice(signer_nonce);
    out.extend_from_slice(signer_eph);
    out.extend_from_slice(peer_nonce);
    out.extend_from_slice(peer_eph);
    out
}

fn decode_fixed(value: Option<&Value>, expected: usize) -> Option<[u8; 32]> {
    let s = value?.as_str()?;
    let bytes = B64.decode(s).ok()?;
    if bytes.len() != expected {
        return None;
    }
    // 签名 64B 单独处理，这里只用于 32B 字段。
    if expected != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

fn decode_sig(value: Option<&Value>) -> Option<Vec<u8>> {
    let s = value?.as_str()?;
    let bytes = B64.decode(s).ok()?;
    if bytes.len() != 64 {
        return None;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// 双向认证往返：挑战→响应→ECDH 派生同一传输密钥（回归：签名 64B 解析）。
    #[test]
    fn two_sides_auth_roundtrip() {
        let a = Arc::new(DeviceIdentity::from_seed([0x5a; 32]));
        let b = Arc::new(DeviceIdentity::from_seed([0x7b; 32]));
        let mut ha = Handshake::new(a.clone(), Some(b.device_id.clone()), None);
        let mut hb = Handshake::new(b.clone(), Some(a.device_id.clone()), None);

        // 双方同时发起挑战（与真实网络一致）。
        let mut to_b: Vec<Message> = Vec::new();
        let mut to_a: Vec<Message> = Vec::new();
        to_b.extend(ha.start().send);
        to_a.extend(hb.start().send);

        let (mut a_key, mut b_key): (Option<[u8; 32]>, Option<[u8; 32]>) = (None, None);
        let (mut a_peer, mut b_peer) = (String::new(), String::new());
        for _ in 0..10 {
            // A → B
            let mut next_a: Vec<Message> = Vec::new();
            for m in to_b.drain(..) {
                let out = hb.handle(&m);
                if let Some(r) = out.authed {
                    b_key = Some(r.transport_key);
                    b_peer = r.peer_id;
                }
                next_a.extend(out.send);
            }
            to_a.extend(next_a);
            // B → A
            let mut next_b: Vec<Message> = Vec::new();
            for m in to_a.drain(..) {
                let out = ha.handle(&m);
                if let Some(r) = out.authed {
                    a_key = Some(r.transport_key);
                    a_peer = r.peer_id;
                }
                next_b.extend(out.send);
            }
            to_b.extend(next_b);
            if a_key.is_some() && b_key.is_some() {
                break;
            }
        }

        assert!(a_key.is_some() && b_key.is_some(), "双向认证应完成");
        assert_eq!(a_peer, b.device_id, "A 验证的身份应为 B");
        assert_eq!(b_peer, a.device_id, "B 验证的身份应为 A");
        assert_eq!(a_key, b_key, "双方应派生同一传输密钥");
        assert_eq!(ha.phase, HandshakePhase::Authed);
        assert_eq!(hb.phase, HandshakePhase::Authed);
    }

    /// 期望身份不符时拒绝（防冒充）。
    #[test]
    fn rejects_wrong_expected_identity() {
        let a = Arc::new(DeviceIdentity::from_seed([0x11; 32]));
        let b = Arc::new(DeviceIdentity::from_seed([0x22; 32]));
        let attacker = Arc::new(DeviceIdentity::from_seed([0x33; 32]));
        let mut ha = Handshake::new(a.clone(), Some(attacker.device_id.clone()), None);
        let mut hb = Handshake::new(b.clone(), None, None);

        let mut to_b: Vec<Message> = Vec::new();
        let mut to_a: Vec<Message> = Vec::new();
        to_b.extend(ha.start().send);
        to_a.extend(hb.start().send);

        let mut failed = None;
        for _ in 0..4 {
            let mut next_a: Vec<Message> = Vec::new();
            for m in to_b.drain(..) {
                let out = hb.handle(&m);
                next_a.extend(out.send);
            }
            to_a.extend(next_a);
            let mut next_b: Vec<Message> = Vec::new();
            for m in to_a.drain(..) {
                let out = ha.handle(&m);
                failed = out.failed.or(failed);
                next_b.extend(out.send);
            }
            to_b.extend(next_b);
            if failed.is_some() {
                break;
            }
        }
        assert!(failed.is_some(), "期望身份不匹配应被拒绝");
        assert_eq!(ha.phase, HandshakePhase::Running); // 未通过不置 Authed
    }
}
