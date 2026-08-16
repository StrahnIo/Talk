//! Per-session IMAP transcript capture (`talkd --capture-dir`).
//!
//! [`Captured`] wraps a connection stream and tees every byte read from the
//! client (`C>`) and every byte written to it (`S>`) into a per-connection
//! text file, as raw bytes plus a hex dump — useful for debugging what real
//! clients send and how the server responds.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use time::format_description::well_known::Rfc3339;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// An opened capture file with its header written.
pub struct CaptureFile {
    file: std::io::BufWriter<std::fs::File>,
    path: PathBuf,
    finished: bool,
}

impl CaptureFile {
    /// Open a fresh timestamped transcript file in `dir`.
    pub fn open(dir: &Path, seq: u64, peer: &str) -> std::io::Result<Self> {
        let path = capture_path(dir, seq)?;
        let file = std::io::BufWriter::new(std::fs::File::create(&path)?);
        let mut this = Self {
            file,
            path,
            finished: false,
        };
        let _ = writeln!(this.file, "# talkd IMAP session capture");
        let _ = writeln!(this.file, "# file={}", this.path.display());
        let _ = writeln!(this.file, "# peer={peer}");
        let _ = writeln!(this.file, "# started={}", now_rfc3339());
        let _ = this.file.flush();
        Ok(this)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn record(&mut self, direction: char, buf: &[u8]) {
        let _ = writeln!(self.file, "\n{direction}> {} bytes", buf.len());
        // Raw bytes as text (IMAP lines are CRLF-terminated, so the next
        // marker starts on a fresh line), then the byte-exact hex dump.
        let _ = self.file.write_all(buf);
        let _ = writeln!(self.file);
        let _ = writeln!(self.file, "{direction}> hex: {}", hex::encode(buf));
        let _ = self.file.flush();
    }

    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        let _ = writeln!(self.file, "\n# ended={}", now_rfc3339());
        let _ = self.file.flush();
    }
}

/// A stream wrapper that logs each read/write chunk to a capture file.
///
/// Capture is best-effort: a failing log file never fails the connection.
pub struct Captured<S> {
    inner: S,
    capture: CaptureFile,
}

impl<S> Captured<S> {
    /// Wrap `inner` with an already-opened [`CaptureFile`].
    pub fn new(inner: S, capture: CaptureFile) -> Self {
        Self { inner, capture }
    }

    /// Write the session footer (idempotent).
    pub fn finish(&mut self) {
        self.capture.finish();
    }
}

/// The next capture filename: compact UTC timestamp + a per-server sequence.
fn capture_path(dir: &Path, seq: u64) -> std::io::Result<PathBuf> {
    let ts = now_compact();
    Ok(dir.join(format!("imap-{ts}-{seq:05}.pcap.txt")))
}

fn now_compact() -> String {
    use time::macros::format_description;
    let fmt = format_description!(
        "[year][month][day]-[hour][minute][second]-[subsecond digits:3]"
    );
    time::OffsetDateTime::now_utc()
        .format(&fmt)
        .unwrap_or_else(|_| "unknown".to_string())
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

impl<S: AsyncRead + Unpin> AsyncRead for Captured<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = res {
            let got = &buf.filled()[before..];
            if !got.is_empty() {
                self.capture.record('C', got);
            }
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Captured<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                self.capture.record('S', &buf[..n]);
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let res = Pin::new(&mut self.inner).poll_shutdown(cx);
        if res.is_ready() {
            self.capture.finish();
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    #[tokio::test]
    async fn captures_reads_and_writes() {
        use tokio::io::AsyncWriteExt;
        let dir = tempfile::tempdir().unwrap();
        let (mut writer, reader) = tokio::io::duplex(4096);

        let capture = CaptureFile::open(dir.path(), 1, "127.0.0.1:9").unwrap();
        let mut captured = Captured::new(reader, capture);
        writer.write_all(b"A1 LOGIN violet pw\r\n").await.unwrap();

        let mut buf = [0u8; 64];
        let n = tokio::io::AsyncReadExt::read(&mut captured, &mut buf)
            .await
            .unwrap();
        assert_eq!(&buf[..n], b"A1 LOGIN violet pw\r\n");

        tokio::io::AsyncWriteExt::write_all(&mut captured, b"* OK ready\r\n")
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::flush(&mut captured).await.unwrap();
        captured.finish();

        let entries = std::fs::read_dir(dir.path()).unwrap();
        let file = entries
            .into_iter()
            .find_map(|e| e.ok())
            .expect("one capture file");
        assert!(file.file_name().to_string_lossy().ends_with(".pcap.txt"));

        let mut contents = String::new();
        std::fs::File::open(file.path())
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        assert!(contents.contains("# peer=127.0.0.1:9"), "{contents}");
        assert!(contents.contains("C> 20 bytes"), "{contents}");
        assert!(contents.contains("A1 LOGIN violet pw"), "{contents}");
        assert!(
            contents.contains("C> hex: 4131204c4f47494e20"),
            "{contents}"
        );
        assert!(contents.contains("S> 12 bytes"), "{contents}");
        assert!(contents.contains("* OK ready"), "{contents}");
        assert!(contents.contains("S> hex: 2a204f4b207265616479"), "{contents}");
        assert!(contents.contains("# ended="), "{contents}");
    }

    #[test]
    fn capture_filenames_are_timestamped() {
        let dir = tempfile::tempdir().unwrap();
        let path = capture_path(dir.path(), 42).unwrap();
        let name = path.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("imap-"), "{name}");
        assert!(name.ends_with("-00042.pcap.txt"), "{name}");
    }
}
