//! 线上帧封装（对应 Dart 版 `connection_manager.dart` 的帧协议）。
//!
//! ```text
//! 明文帧：[4 字节大端 headerLen][header UTF-8 JSON][data 字节]
//! 封装包：[1B 标记][明文帧]  (标记 0x00=明文，0x01=AES-256-GCM 密文)
//! TCP 外层再前缀 [4B 封装包总长度]。
//! ```

use super::crypto::{open, seal, GCM_OVERHEAD};
use super::limits::{is_valid_header_length, is_valid_wire_packet_length, MAX_HEADER_BYTES};

pub const ENVELOPE_PLAIN: u8 = 0x00;
pub const ENVELOPE_ENCRYPTED: u8 = 0x01;

/// 组装明文帧：`[4B headerLen][header][data?]`。
pub fn build_frame(header: &[u8], data: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + header.len() + data.map_or(0, |d| d.len()));
    out.extend_from_slice(&(header.len() as u32).to_be_bytes());
    out.extend_from_slice(header);
    if let Some(d) = data {
        out.extend_from_slice(d);
    }
    out
}

/// 拆分明文帧；头部长度非法或不是合法 UTF-8 返回 `None`。
pub fn parse_frame(frame: &[u8]) -> Option<(String, &[u8])> {
    if frame.len() < 4 {
        return None;
    }
    let header_len = u32::from_be_bytes(frame[..4].try_into().ok()?) as usize;
    if !is_valid_header_length(header_len, frame.len()) || header_len > MAX_HEADER_BYTES {
        return None;
    }
    let header = std::str::from_utf8(&frame[4..4 + header_len]).ok()?.to_string();
    let data = &frame[4 + header_len..];
    Some((header, data))
}

/// 加密封装：认证后整帧（含头部）都被 AES-256-GCM 保护。
pub fn wrap(plain_frame: &[u8], key: Option<&[u8; 32]>) -> Result<Vec<u8>, String> {
    match key {
        None => {
            let mut out = Vec::with_capacity(1 + plain_frame.len());
            out.push(ENVELOPE_PLAIN);
            out.extend_from_slice(plain_frame);
            Ok(out)
        }
        Some(k) => {
            let sealed = seal(plain_frame, k)?;
            let mut out = Vec::with_capacity(1 + sealed.len());
            out.push(ENVELOPE_ENCRYPTED);
            out.extend_from_slice(&sealed);
            Ok(out)
        }
    }
}

/// 解封装：明文包只允许出现在认证前，密文包必须有密钥。
pub fn unwrap_packet(packet: &[u8], key: Option<&[u8; 32]>) -> Result<Vec<u8>, String> {
    if packet.len() < 2 || !is_valid_wire_packet_length(packet.len()) {
        return Err("封装包长度非法".into());
    }
    match packet[0] {
        ENVELOPE_PLAIN => Ok(packet[1..].to_vec()),
        ENVELOPE_ENCRYPTED => match key {
            Some(k) => open(&packet[1..], k),
            None => Err("未协商密钥就收到密文".into()),
        },
        _ => Err("未知封装标记".into()),
    }
}

/// 封装包密文体积上界（明文帧 + 标记 + GCM 开销）。
pub fn wire_len(plain_frame_len: usize) -> usize {
    1 + plain_frame_len + GCM_OVERHEAD
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let f = build_frame(b"{\"i\":\"t\"}", Some(&[1, 2, 3]));
        let (header, data) = parse_frame(&f).unwrap();
        assert_eq!(header, "{\"i\":\"t\"}");
        assert_eq!(data, &[1, 2, 3]);
    }

    #[test]
    fn envelope_roundtrip_and_tamper() {
        let frame = build_frame(b"hdr", Some(b"payload"));
        let key = [7u8; 32];
        let packet = wrap(&frame, Some(&key)).unwrap();
        assert_eq!(packet[0], ENVELOPE_ENCRYPTED);
        assert_eq!(unwrap_packet(&packet, Some(&key)).unwrap(), frame);
        assert!(unwrap_packet(&packet, None).is_err());
        let mut bad = packet.clone();
        let n = bad.len() - 1;
        bad[n] ^= 0xff;
        assert!(unwrap_packet(&bad, Some(&key)).is_err());
    }

    #[test]
    fn bad_header_rejected() {
        assert!(parse_frame(&[0, 0, 0, 1]).is_none());
        assert!(parse_frame(&[0xff, 0xff, 0xff, 0xff, b'a']).is_none());
    }
}
