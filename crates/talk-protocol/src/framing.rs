//! Line-based framing for ZSMTP, with length-prefixed binary blobs.
//!
//! Commands are CRLF-terminated lines. Binary payloads (the sealed invoice)
//! use a length prefix so we avoid SMTP's dot-stuffing entirely:
//! `BLOB <n>\r\n<n bytes>`.

use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Error)]
pub enum FramingError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("line too long (max {0} bytes)")]
    LineTooLong(usize),
    #[error("blob too large (max {0} bytes)")]
    BlobTooLarge(usize),
}

pub const MAX_LINE: usize = 4096;
pub const MAX_BLOB: usize = 1 << 20; // 1 MiB

/// Read a CRLF-terminated line, returning it without the trailing CRLF.
pub async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<String, FramingError> {
    let mut line = Vec::new();
    let n = reader.read_until(b'\n', &mut line).await?;
    if n == 0 {
        return Err(FramingError::Protocol("connection closed".into()));
    }
    if line.len() > MAX_LINE {
        return Err(FramingError::LineTooLong(MAX_LINE));
    }
    if line.ends_with(b"\r\n") {
        line.truncate(line.len() - 2);
    } else if line.ends_with(b"\n") {
        line.truncate(line.len() - 1);
    } else {
        return Err(FramingError::Protocol("line not newline-terminated".into()));
    }
    String::from_utf8(line).map_err(|_| FramingError::Protocol("line not utf-8".into()))
}

/// Write a CRLF-terminated line.
pub async fn write_line<W: AsyncWrite + Unpin>(
    writer: &mut W,
    line: &str,
) -> Result<(), FramingError> {
    if line.len() > MAX_LINE {
        return Err(FramingError::LineTooLong(MAX_LINE));
    }
    writer.write_all(line.as_bytes()).await?;
    writer.write_all(b"\r\n").await?;
    Ok(())
}

/// Read a length-prefixed blob: a `BLOB <n>` header line then exactly `n` bytes.
pub async fn read_blob<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, FramingError> {
    let header = read_line(reader).await?;
    let n: usize = header
        .strip_prefix("BLOB ")
        .ok_or_else(|| FramingError::Protocol("expected BLOB header".into()))?
        .trim()
        .parse()
        .map_err(|_| FramingError::Protocol("malformed BLOB size".into()))?;
    if n > MAX_BLOB {
        return Err(FramingError::BlobTooLarge(MAX_BLOB));
    }
    let mut buf = vec![0u8; n];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Write a length-prefixed blob.
pub async fn write_blob<W: AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> Result<(), FramingError> {
    if data.len() > MAX_BLOB {
        return Err(FramingError::BlobTooLarge(MAX_BLOB));
    }
    write_line(writer, &format!("BLOB {}", data.len())).await?;
    writer.write_all(data).await?;
    Ok(())
}

/// Write a status line (used by the server).
pub async fn write_status<W: AsyncWrite + Unpin>(
    writer: &mut W,
    status: &crate::status::Status,
) -> Result<(), FramingError> {
    write_line(writer, &status.render()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn line_roundtrip() {
        let (mut writer, reader) = tokio::io::duplex(1024);
        let mut reader = BufReader::new(reader);
        write_line(&mut writer, "ZSMTP 1.0").await.unwrap();
        let line = read_line(&mut reader).await.unwrap();
        assert_eq!(line, "ZSMTP 1.0");
    }

    #[tokio::test]
    async fn line_split_across_reads() {
        let (mut writer, reader) = tokio::io::duplex(1024);
        let mut reader = BufReader::new(reader);
        writer.write_all(b"HELO exam").await.unwrap();
        writer.write_all(b"ple.com\r\n").await.unwrap();
        let line = read_line(&mut reader).await.unwrap();
        assert_eq!(line, "HELO example.com");
    }

    #[tokio::test]
    async fn blob_roundtrip_binary() {
        let (mut writer, reader) = tokio::io::duplex(1024);
        let mut reader = BufReader::new(reader);
        let data: Vec<u8> = (0..100u8).collect();
        write_blob(&mut writer, &data).await.unwrap();
        let got = read_blob(&mut reader).await.unwrap();
        assert_eq!(got, data);
    }

    #[tokio::test]
    async fn empty_blob_roundtrip() {
        let (mut writer, reader) = tokio::io::duplex(1024);
        let mut reader = BufReader::new(reader);
        write_blob(&mut writer, b"").await.unwrap();
        let got = read_blob(&mut reader).await.unwrap();
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn blob_wrong_header_fails() {
        let (mut writer, reader) = tokio::io::duplex(1024);
        let mut reader = BufReader::new(reader);
        writer.write_all(b"NOTABLOB\r\n").await.unwrap();
        assert!(read_blob(&mut reader).await.is_err());
    }

    #[tokio::test]
    async fn blob_too_large_rejected() {
        let (mut writer, reader) = tokio::io::duplex(1024);
        let mut reader = BufReader::new(reader);
        writer.write_all(b"BLOB 99999999\r\n").await.unwrap();
        let err = read_blob(&mut reader).await.unwrap_err();
        assert!(matches!(err, FramingError::BlobTooLarge(_)));
    }

    #[tokio::test]
    async fn status_roundtrip() {
        let (mut writer, reader) = tokio::io::duplex(1024);
        let mut reader = BufReader::new(reader);
        let status = crate::status::Status::new(crate::status::StatusCode::OK, "queued");
        write_status(&mut writer, &status).await.unwrap();
        let line = read_line(&mut reader).await.unwrap();
        assert_eq!(line, "250 queued");
    }

    #[tokio::test]
    async fn eof_mid_line_is_protocol_error() {
        let (writer, reader) = tokio::io::duplex(1024);
        let mut reader = BufReader::new(reader);
        drop(writer);
        let err = read_line(&mut reader).await.unwrap_err();
        assert!(matches!(err, FramingError::Protocol(_)));
    }
}
