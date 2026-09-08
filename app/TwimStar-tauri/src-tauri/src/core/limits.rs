//! 协议与资源限制的唯一权威来源（对应 Dart 版 `protocol_limits.dart`）。
//!
//! 所有来自远端的字段都必须先经过这里的校验，再进入业务逻辑。
//! 任何超限、类型异常或边界不一致的输入都应被拒绝，而不是"尽量处理"。

/// 单文件大小上限：1 TiB。
pub const MAX_FILE_SIZE: u64 = 1 << 40;
/// 空文件允许传输。
pub const MIN_FILE_SIZE: u64 = 0;

/// 明文数据块上限（4 MiB）。
pub const MAX_PLAIN_CHUNK: usize = 4 * 1024 * 1024;
/// AES-256-GCM 附加开销：12B nonce + 16B tag。
pub const GCM_OVERHEAD: usize = 28;
/// 线上单个密文块上限。
pub const MAX_ENCRYPTED_CHUNK: usize = MAX_PLAIN_CHUNK + GCM_OVERHEAD;

/// 控制消息 JSON 头部上限（64 KiB）。
pub const MAX_HEADER_BYTES: usize = 64 * 1024;
/// 传输层封装额外开销：1B 明文/密文标记 + GCM 开销。
pub const FRAME_ENVELOPE_OVERHEAD: usize = 1 + GCM_OVERHEAD;
/// 单个"帧"（头部 + 数据）明文上限。
pub const MAX_PLAIN_FRAME: usize = MAX_PLAIN_CHUNK + MAX_HEADER_BYTES;
/// 线上单个封装包上限。
pub const MAX_WIRE_PACKET: usize = MAX_PLAIN_FRAME + FRAME_ENVELOPE_OVERHEAD;

pub const MAX_TASK_ID_LENGTH: usize = 64;
pub const MAX_RELATIVE_PATH_LENGTH: usize = 4096;
pub const MAX_NAME_COMPONENT_LENGTH: usize = 255;
pub const MAX_DIRECTORY_DEPTH: usize = 32;
pub const MAX_CONCURRENT_TASKS: usize = 64;
pub const MAX_FILES_PER_BATCH: usize = 100_000;
pub const MAX_PEER_NAME_LENGTH: usize = 128;
pub const MAX_PASSPHRASE_LENGTH: usize = 256;

/// taskId 字符集（与 Dart 版 `taskIdPattern` 一致）。
pub fn validate_task_id(raw: &str) -> Result<(), String> {
    if raw.is_empty() {
        return Err("taskId 缺失".into());
    }
    if raw.len() > MAX_TASK_ID_LENGTH {
        return Err("taskId 过长".into());
    }
    if !raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("taskId 含非法字符".into());
    }
    Ok(())
}

pub fn validate_file_size(size: u64) -> Result<(), String> {
    if size < MIN_FILE_SIZE {
        return Err("文件大小为负".into());
    }
    if size > MAX_FILE_SIZE {
        return Err("文件大小超过上限".into());
    }
    Ok(())
}

/// 校验写入区间 `[offset, offset+length)` 是否落在 `[0, fileSize)` 内。
pub fn validate_chunk(
    offset: u64,
    length: usize,
    file_size: Option<u64>,
    max_chunk: usize,
) -> Result<(), String> {
    if length > max_chunk {
        return Err("块超过单块上限".into());
    }
    match file_size {
        Some(size) => {
            if offset > size {
                return Err("offset 超过文件大小".into());
            }
            if length as u64 > size - offset {
                return Err("块尾超过文件大小".into());
            }
        }
        None if offset > MAX_FILE_SIZE => return Err("offset 超过文件大小上限".into()),
        None => {}
    }
    Ok(())
}

/// 帧长度（线上字节数）合法性。
pub fn is_valid_wire_packet_length(total_len: usize) -> bool {
    (2..=MAX_WIRE_PACKET).contains(&total_len)
}

/// 头部长度合法性：`[1, max_header_bytes]`，且 `4 + header_len` 不越过整帧（可留空 data）。
pub fn is_valid_header_length(header_len: usize, total_len: usize) -> bool {
    header_len >= 1 && header_len <= MAX_HEADER_BYTES && header_len + 4 <= total_len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_id_rules() {
        assert!(validate_task_id("a-b_1").is_ok());
        assert!(validate_task_id("").is_err());
        assert!(validate_task_id("../etc").is_err());
        assert!(validate_task_id(&"x".repeat(65)).is_err());
    }

    #[test]
    fn chunk_bounds() {
        assert!(validate_chunk(0, 10, Some(10), MAX_ENCRYPTED_CHUNK).is_ok());
        assert!(validate_chunk(5, 10, Some(10), MAX_ENCRYPTED_CHUNK).is_err());
        assert!(validate_chunk(0, MAX_ENCRYPTED_CHUNK + 1, None, MAX_ENCRYPTED_CHUNK).is_err());
    }

    #[test]
    fn oversized_size_rejected() {
        assert!(validate_file_size(MAX_FILE_SIZE + 1).is_err());
    }
}
