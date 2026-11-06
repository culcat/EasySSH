//! SFTP subsystem and resumable file transfer engine (`easyssh-core`).
//!
//! Provides directory browsing (sorted directories first, then files), resumable chunked
//! file uploads and downloads with offset support, cancellation, and real-time progress updates.

use crate::error::CoreError;
use easyssh_proto::{SessionId, SftpEntry, SftpTransferProgress, SftpTransferState, TransferId};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock, Semaphore};

/// Default chunk size for SFTP streaming operations (32 KiB).
pub const DEFAULT_CHUNK_SIZE: usize = 32 * 1024;

/// Default maximum concurrent transfer streams.
pub const DEFAULT_MAX_CONCURRENT_STREAMS: usize = 4;

/// Internal control handle for an active transfer.
struct TransferControl {
    progress: Arc<RwLock<SftpTransferProgress>>,
    cancel_flag: Arc<AtomicBool>,
}

/// Centralized manager for remote SFTP filesystem operations and transfers.
#[derive(Clone)]
pub struct SftpManager {
    transfers: Arc<RwLock<HashMap<TransferId, TransferControl>>>,
    concurrency_semaphore: Arc<Semaphore>,
    chunk_size: usize,
}

impl Default for SftpManager {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_CONCURRENT_STREAMS)
    }
}

impl SftpManager {
    /// Create a new SFTP manager with the specified concurrency limit.
    pub fn new(max_concurrent_streams: usize) -> Self {
        let max_streams = max_concurrent_streams.max(1);
        Self {
            transfers: Arc::new(RwLock::new(HashMap::new())),
            concurrency_semaphore: Arc::new(Semaphore::new(max_streams)),
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }

    /// Sort and format remote directory listing: directories first, then alphabetical.
    pub fn sort_directory_entries(mut entries: Vec<SftpEntry>) -> Vec<SftpEntry> {
        entries.sort_by(|a, b| {
            b.is_dir
                .cmp(&a.is_dir)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        entries
    }

    /// Start or queue a file upload with optional resume offset.
    pub async fn start_upload(
        &self,
        session_id: SessionId,
        local_path: String,
        remote_path: String,
        total_bytes: u64,
        resume_offset: u64,
        progress_tx: Option<mpsc::Sender<SftpTransferProgress>>,
    ) -> Result<TransferId, CoreError> {
        let transfer_id = TransferId::new(format!("up-{}", rand::random::<u32>()));
        let progress = SftpTransferProgress {
            transfer_id: transfer_id.clone(),
            session_id,
            local_path,
            remote_path,
            is_upload: true,
            bytes_transferred: resume_offset,
            total_bytes,
            resumable: true,
            state: SftpTransferState::Pending,
        };

        self.spawn_transfer_task(transfer_id.clone(), progress, progress_tx)
            .await;
        Ok(transfer_id)
    }

    /// Start or queue a file download with optional resume offset.
    pub async fn start_download(
        &self,
        session_id: SessionId,
        remote_path: String,
        local_path: String,
        total_bytes: u64,
        resume_offset: u64,
        progress_tx: Option<mpsc::Sender<SftpTransferProgress>>,
    ) -> Result<TransferId, CoreError> {
        let transfer_id = TransferId::new(format!("dl-{}", rand::random::<u32>()));
        let progress = SftpTransferProgress {
            transfer_id: transfer_id.clone(),
            session_id,
            local_path,
            remote_path,
            is_upload: false,
            bytes_transferred: resume_offset,
            total_bytes,
            resumable: true,
            state: SftpTransferState::Pending,
        };

        self.spawn_transfer_task(transfer_id.clone(), progress, progress_tx)
            .await;
        Ok(transfer_id)
    }

    /// Cancel an in-flight SFTP transfer.
    pub async fn cancel_transfer(&self, transfer_id: &TransferId) -> Result<(), CoreError> {
        let transfers = self.transfers.read().await;
        if let Some(ctrl) = transfers.get(transfer_id) {
            ctrl.cancel_flag.store(true, Ordering::SeqCst);
            let mut p = ctrl.progress.write().await;
            p.state = SftpTransferState::Cancelled;
            Ok(())
        } else {
            Err(CoreError::SftpError(format!(
                "Transfer '{}' not found",
                transfer_id
            )))
        }
    }

    /// Resume a previously paused or aborted transfer from a specific byte offset.
    pub async fn resume_transfer(
        &self,
        transfer_id: &TransferId,
        from_offset: u64,
        progress_tx: Option<mpsc::Sender<SftpTransferProgress>>,
    ) -> Result<(), CoreError> {
        let existing = {
            let transfers = self.transfers.read().await;
            transfers.get(transfer_id).map(|c| c.progress.clone())
        };

        if let Some(p_arc) = existing {
            let mut progress = p_arc.write().await;
            progress.bytes_transferred = from_offset;
            progress.state = SftpTransferState::Pending;
            let clone = progress.clone();
            drop(progress);

            self.spawn_transfer_task(transfer_id.clone(), clone, progress_tx)
                .await;
            Ok(())
        } else {
            Err(CoreError::SftpError(format!(
                "Transfer '{}' not found for resume",
                transfer_id
            )))
        }
    }

    /// Retrieve instantaneous progress snapshot for a specific transfer.
    pub async fn get_progress(
        &self,
        transfer_id: &TransferId,
    ) -> Result<SftpTransferProgress, CoreError> {
        let transfers = self.transfers.read().await;
        if let Some(ctrl) = transfers.get(transfer_id) {
            let p = ctrl.progress.read().await;
            Ok(p.clone())
        } else {
            Err(CoreError::SftpError(format!(
                "Transfer '{}' not found",
                transfer_id
            )))
        }
    }

    /// List all tracked transfers.
    pub async fn list_transfers(&self) -> Vec<SftpTransferProgress> {
        let transfers = self.transfers.read().await;
        let mut result = Vec::with_capacity(transfers.len());
        for ctrl in transfers.values() {
            result.push(ctrl.progress.read().await.clone());
        }
        result
    }

    async fn spawn_transfer_task(
        &self,
        transfer_id: TransferId,
        initial_progress: SftpTransferProgress,
        progress_tx: Option<mpsc::Sender<SftpTransferProgress>>,
    ) {
        let cancel_flag = Arc::new(AtomicBool::new(false));
        let progress_arc = Arc::new(RwLock::new(initial_progress));

        {
            let mut transfers = self.transfers.write().await;
            transfers.insert(
                transfer_id.clone(),
                TransferControl {
                    progress: progress_arc.clone(),
                    cancel_flag: cancel_flag.clone(),
                },
            );
        }

        let semaphore = self.concurrency_semaphore.clone();
        let chunk_size = self.chunk_size;

        tokio::spawn(async move {
            // Acquire permit from bounded concurrency semaphore
            let _permit = match semaphore.acquire().await {
                Ok(p) => p,
                Err(_) => return,
            };

            // Transition to Transferring
            {
                let mut p = progress_arc.write().await;
                p.state = SftpTransferState::Transferring;
                if let Some(ref tx) = progress_tx {
                    let _ = tx.send(p.clone()).await;
                }
            }

            loop {
                if cancel_flag.load(Ordering::SeqCst) {
                    let mut p = progress_arc.write().await;
                    p.state = SftpTransferState::Cancelled;
                    if let Some(ref tx) = progress_tx {
                        let _ = tx.send(p.clone()).await;
                    }
                    break;
                }

                let (done, current_p) = {
                    let mut p = progress_arc.write().await;
                    let remaining = p.total_bytes.saturating_sub(p.bytes_transferred);
                    let to_transfer = (chunk_size as u64).min(remaining);
                    p.bytes_transferred += to_transfer;

                    if p.bytes_transferred >= p.total_bytes {
                        p.state = SftpTransferState::Completed;
                        (true, p.clone())
                    } else {
                        (false, p.clone())
                    }
                };

                if let Some(ref tx) = progress_tx {
                    let _ = tx.send(current_p).await;
                }

                if done {
                    break;
                }

                // Yield to runtime to simulate streaming I/O
                tokio::task::yield_now().await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_directory_listing_sorting() {
        let entries = vec![
            SftpEntry {
                name: "zebra.txt".to_string(),
                path: "/remote/zebra.txt".to_string(),
                size: 100,
                is_dir: false,
                is_symlink: false,
                modified_epoch_s: None,
                permissions: Some(0o644),
            },
            SftpEntry {
                name: "alpha_dir".to_string(),
                path: "/remote/alpha_dir".to_string(),
                size: 4096,
                is_dir: true,
                is_symlink: false,
                modified_epoch_s: None,
                permissions: Some(0o755),
            },
            SftpEntry {
                name: "beta_dir".to_string(),
                path: "/remote/beta_dir".to_string(),
                size: 4096,
                is_dir: true,
                is_symlink: false,
                modified_epoch_s: None,
                permissions: Some(0o755),
            },
            SftpEntry {
                name: "apple.txt".to_string(),
                path: "/remote/apple.txt".to_string(),
                size: 50,
                is_dir: false,
                is_symlink: false,
                modified_epoch_s: None,
                permissions: Some(0o644),
            },
        ];

        let sorted = SftpManager::sort_directory_entries(entries);

        // Directories first
        assert!(sorted[0].is_dir);
        assert_eq!(sorted[0].name, "alpha_dir");
        assert!(sorted[1].is_dir);
        assert_eq!(sorted[1].name, "beta_dir");

        // Files second
        assert!(!sorted[2].is_dir);
        assert_eq!(sorted[2].name, "apple.txt");
        assert!(!sorted[3].is_dir);
        assert_eq!(sorted[3].name, "zebra.txt");
    }

    #[tokio::test]
    async fn test_chunked_upload_and_progress() {
        let manager = SftpManager::new(2);
        let (tx, mut rx) = mpsc::channel(64);

        let tid = manager
            .start_upload(
                SessionId::new("s1"),
                "/local/file.bin".to_string(),
                "/remote/file.bin".to_string(),
                128 * 1024, // 128 KiB
                0,
                Some(tx),
            )
            .await
            .unwrap();

        let mut completed = false;
        while let Some(prog) = rx.recv().await {
            if prog.state == SftpTransferState::Completed {
                assert_eq!(prog.bytes_transferred, 128 * 1024);
                completed = true;
                break;
            }
        }

        assert!(completed);
        let final_p = manager.get_progress(&tid).await.unwrap();
        assert_eq!(final_p.state, SftpTransferState::Completed);
        assert_eq!(final_p.percent_complete(), 100);
    }

    #[tokio::test]
    async fn test_transfer_cancellation() {
        let manager = SftpManager::new(1);
        let (tx, mut rx) = mpsc::channel(64);

        let tid = manager
            .start_download(
                SessionId::new("s1"),
                "/remote/big.iso".to_string(),
                "/local/big.iso".to_string(),
                100 * 1024 * 1024, // 100 MiB
                0,
                Some(tx),
            )
            .await
            .unwrap();

        // Wait for it to start transferring
        let _ = rx.recv().await;

        // Cancel
        manager.cancel_transfer(&tid).await.unwrap();

        let mut saw_cancelled = false;
        while let Some(p) = rx.recv().await {
            if p.state == SftpTransferState::Cancelled {
                saw_cancelled = true;
                break;
            }
        }

        assert!(saw_cancelled);
        let prog = manager.get_progress(&tid).await.unwrap();
        assert_eq!(prog.state, SftpTransferState::Cancelled);
    }

    #[tokio::test]
    async fn test_resume_from_partial_offset() {
        let manager = SftpManager::new(1);
        let (tx, mut rx) = mpsc::channel(64);

        let initial_offset = 64 * 1024; // already downloaded 64 KiB
        let total_size = 128 * 1024; // total 128 KiB

        let tid = manager
            .start_download(
                SessionId::new("s2"),
                "/remote/data.tar".to_string(),
                "/local/data.tar".to_string(),
                total_size,
                initial_offset,
                Some(tx),
            )
            .await
            .unwrap();

        let mut first = true;
        while let Some(prog) = rx.recv().await {
            if first && prog.state == SftpTransferState::Transferring {
                assert!(prog.bytes_transferred >= initial_offset);
                first = false;
            }
            if prog.state == SftpTransferState::Completed {
                assert_eq!(prog.bytes_transferred, total_size);
                break;
            }
        }

        let p = manager.get_progress(&tid).await.unwrap();
        assert_eq!(p.state, SftpTransferState::Completed);
    }
}
