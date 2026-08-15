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
pub struct SocketListener {
    pub path: PathBuf,
    listener: UnixListener,
}

impl SocketListener {
    /// Bind a Unix domain socket at `path`, removing any stale socket file and
    /// creating parent directories first.
    pub fn bind(path: impl Into<PathBuf>) -> Result<Self, SocketError> {
        let path = path.into();

        if path.exists() {
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

        let listener = UnixListener::bind(&path).map_err(|source| SocketError::Bind {
            path: path.clone(),
            source,
        })?;

        Ok(Self { path, listener })
    }

    /// Accept the next connection.
    pub async fn accept(&self) -> std::io::Result<(UnixStream, tokio::net::unix::SocketAddr)> {
        self.listener.accept().await
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
