//! Storage traits and implementations for persisted vault data.

use crate::error::CoreError;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Type alias for pinned storage operation futures.
pub type StorageFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, CoreError>> + Send + 'a>>;

/// Abstraction for storing and loading raw encrypted vault payloads.
pub trait VaultStorage: Send + Sync {
    /// Read encrypted vault payload from underlying storage medium.
    /// Returns `Ok(None)` if no storage entry currently exists.
    fn load<'a>(&'a self) -> StorageFuture<'a, Option<Vec<u8>>>;

    /// Persist encrypted vault payload to underlying storage medium.
    fn store<'a>(&'a self, data: &'a [u8]) -> StorageFuture<'a, ()>;
}

/// In-memory storage implementation for tests and ephemeral sessions.
#[derive(Debug, Default, Clone)]
pub struct MemoryVaultStorage {
    data: Arc<Mutex<Option<Vec<u8>>>>,
}

impl MemoryVaultStorage {
    /// Create a new empty in-memory vault storage.
    pub fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(None)),
        }
    }

    /// Create an in-memory vault storage initialized with specific data.
    pub fn with_initial_data(data: Vec<u8>) -> Self {
        Self {
            data: Arc::new(Mutex::new(Some(data))),
        }
    }
}

impl VaultStorage for MemoryVaultStorage {
    fn load<'a>(&'a self) -> StorageFuture<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            let lock = self.data.lock().await;
            Ok(lock.clone())
        })
    }

    fn store<'a>(&'a self, data: &'a [u8]) -> StorageFuture<'a, ()> {
        Box::pin(async move {
            let mut lock = self.data.lock().await;
            *lock = Some(data.to_vec());
            Ok(())
        })
    }
}

/// File-based vault storage for native desktop platforms.
#[derive(Debug, Clone)]
pub struct FileVaultStorage {
    file_path: PathBuf,
}

impl FileVaultStorage {
    /// Create a new file storage targeting `file_path`.
    pub fn new<P: AsRef<Path>>(file_path: P) -> Self {
        Self {
            file_path: file_path.as_ref().to_path_buf(),
        }
    }
}

impl VaultStorage for FileVaultStorage {
    fn load<'a>(&'a self) -> StorageFuture<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            if !self.file_path.exists() {
                return Ok(None);
            }
            let bytes = tokio::fs::read(&self.file_path).await?;
            Ok(Some(bytes))
        })
    }

    fn store<'a>(&'a self, data: &'a [u8]) -> StorageFuture<'a, ()> {
        Box::pin(async move {
            if let Some(parent) = self.file_path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::write(&self.file_path, data).await?;
            Ok(())
        })
    }
}
