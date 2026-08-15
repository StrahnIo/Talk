use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::net::{UnixListener, UnixStream};

#[derive(Debug, Error)]
pub enum SocketError {
    #[error("failed to remove stale socket {path}: {source}")]
    StaleRemove {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to create parent directory for {path}: {source}")]
    ParentMkdir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to bind socket {path}: {source}")]
    Bind {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// A bound Unix domain socket listener that removes its socket file on drop.
///
/// Binding uses a blocking std listener so it works without a tokio runtime.
/// `accept` converts to tokio lazily (it is async and requires a runtime).
pub struct SocketListener {
    pub path: PathBuf,
    listener: StdUnixListener,
}

impl SocketListener {
    /// Bind a Unix domain socket at `path`, removing any stale socket file and
    /// creating parent directories first.
    ///
    /// A socket file is considered stale only if nothing is listening on it.
    /// A live socket is never removed (that would steal another process's
    /// listener); binding then fails with `Bind`.
    pub fn bind(path: impl Into<PathBuf>) -> Result<Self, SocketError> {
        let path = path.into();

        if path.exists() && !is_listening(&path) {
            std::fs::remove_file(&path).map_err(|source| SocketError::StaleRemove {
                path: path.clone(),
                source,
            })?;
        }

        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|source| SocketError::ParentMkdir {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        let listener = StdUnixListener::bind(&path).map_err(|source| SocketError::Bind {
            path: path.clone(),
            source,
        })?;

        Ok(Self { path, listener })
    }

    /// Accept the next connection. Requires a tokio runtime.
    pub async fn accept(&self) -> std::io::Result<(UnixStream, tokio::net::unix::SocketAddr)> {
        let clone = self.listener.try_clone()?;
        clone.set_nonblocking(true)?;
        let tokio_listener = UnixListener::from_std(clone)?;
        tokio_listener.accept().await
    }

    /// Convert to a tokio listener for long-lived accept loops. Requires a
    /// tokio runtime; the original remains usable for further converts.
    pub fn to_tokio(&self) -> std::io::Result<UnixListener> {
        let clone = self.listener.try_clone()?;
        clone.set_nonblocking(true)?;
        UnixListener::from_std(clone)
    }

    pub fn local_path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SocketListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Whether another process is currently listening on the socket at `path`.
///
/// A successful `connect` means a live listener accepted (or queued) our
/// connection; a stale socket file yields `ECONNREFUSED`.
fn is_listening(path: &Path) -> bool {
    use std::os::unix::net::UnixStream;
    UnixStream::connect(path).is_ok()
}
