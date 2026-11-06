/**
 * Protocol contract between EasySSH Core (Rust/WASM) and UI (React/Rust).
 *
 * This contract mirrors crates/proto definitions and acts as the Single Source of Truth
 * for commands, events, and UI state models.
 *
 * CRITICAL SECURITY INVARIANT:
 * Raw private keys, cleartext passphrases, or decrypted vault blobs MUST NEVER
 * exist in UI state. Keys are represented solely by opaque KeyHandle IDs.
 */

export const PROTO_VERSION = '1.0.0' as const;

/**
 * Branded types for type safety - prevents accidental mixup between different IDs.
 */
declare const BrandSymbol: unique symbol;
export type Brand<T, B> = T & { readonly [BrandSymbol]: B };

export type HostId = Brand<string, 'HostId'>;
export type SessionId = Brand<string, 'SessionId'>;
export type KeyHandle = Brand<string, 'KeyHandle'>;
export type TransferId = Brand<string, 'TransferId'>;

export const toHostId = (id: string): HostId => id as HostId;
export const toSessionId = (id: string): SessionId => id as SessionId;
export const toKeyHandle = (id: string): KeyHandle => id as KeyHandle;
export const toTransferId = (id: string): TransferId => id as TransferId;

export type AuthMethodType = 'password' | 'publicKey' | 'agent' | 'interactive';

export interface HostConfig {
  readonly id: HostId;
  readonly label: string;
  readonly hostname: string;
  readonly port: number;
  readonly username: string;
  readonly authMethod: AuthMethodType;
  /** Opaque handle to a stored private key in the Rust core vault. Cleartext keys never enter JS. */
  readonly keyHandle?: KeyHandle;
  readonly tags: readonly string[];
  readonly jumpHostId?: HostId;
  readonly identityFile?: string;
  readonly createdAt: number;
  readonly updatedAt: number;
}

export type HostKeyStatus = 'new' | 'mismatch' | 'matched';

export interface HostKeyVerification {
  readonly hostId: HostId;
  readonly hostname: string;
  readonly port: number;
  readonly keyType: string;
  readonly fingerprintSha256: string;
  readonly status: HostKeyStatus;
  /** In case of status === 'mismatch', contains the known previously trusted fingerprint */
  readonly previousFingerprintSha256?: string;
}

export interface VaultStatus {
  readonly isInitialized: boolean;
  readonly isUnlocked: boolean;
  readonly entryCount: number;
  readonly autoLockTimeoutSeconds: number;
}

export type SessionStatus =
  | 'connecting'
  | 'authenticating'
  | 'connected'
  | 'disconnected'
  | 'error';

export interface SessionSnapshot {
  readonly sessionId: SessionId;
  readonly hostId: HostId;
  readonly title: string;
  readonly status: SessionStatus;
  readonly latencyMs: number;
  readonly fps: number;
  readonly createdAt: number;
  readonly errorMessage?: string;
}

/**
 * Metadata for a file or directory entry retrieved via SFTP.
 * Matches crates/proto::sftp::SftpEntry.
 */
export interface SftpEntry {
  readonly name: string;
  readonly path: string;
  readonly size: number;
  readonly isDir: boolean;
  readonly isSymlink: boolean;
  readonly modifiedEpochS?: number;
  readonly permissions?: number;
}

export type TransferDirection = 'upload' | 'download';
export type SftpTransferState =
  | 'pending'
  | 'transferring'
  | 'paused'
  | 'completed'
  | 'failed'
  | 'cancelled';

export interface SftpTransferProgress {
  readonly transferId: TransferId;
  readonly sessionId: SessionId;
  readonly remotePath: string;
  readonly localPath: string;
  readonly localFileName: string;
  readonly direction: TransferDirection;
  readonly isUpload: boolean;
  readonly bytesTransferred: number;
  readonly totalBytes: number;
  readonly resumable: boolean;
  readonly state: SftpTransferState;
  readonly speedBytesPerSec: number;
  readonly errorMessage?: string;
}

export type Command =
  | { readonly type: 'init' }
  | { readonly type: 'unlock_vault'; readonly passphrase: string }
  | { readonly type: 'lock_vault' }
  | { readonly type: 'connect_host'; readonly hostId: HostId }
  | { readonly type: 'disconnect_session'; readonly sessionId: SessionId }
  | { readonly type: 'terminal_input'; readonly sessionId: SessionId; readonly data: string }
  | { readonly type: 'terminal_resize'; readonly sessionId: SessionId; readonly cols: number; readonly rows: number }
  | { readonly type: 'confirm_host_key'; readonly hostId: HostId; readonly accepted: boolean; readonly remember: boolean }
  | { readonly type: 'create_host'; readonly host: HostConfig }
  | { readonly type: 'save_host'; readonly host: HostConfig }
  | { readonly type: 'delete_host'; readonly hostId: HostId }
  | { readonly type: 'select_session'; readonly sessionId: SessionId }
  | { readonly type: 'import_ssh_config'; readonly configText: string }
  | { readonly type: 'sftp_list_dir'; readonly sessionId: SessionId; readonly remotePath: string }
  | { readonly type: 'sftp_upload'; readonly sessionId: SessionId; readonly localPath: string; readonly remotePath: string; readonly size?: number }
  | { readonly type: 'sftp_download'; readonly sessionId: SessionId; readonly remotePath: string; readonly localPath: string; readonly size?: number }
  | { readonly type: 'sftp_pause_resume'; readonly transferId: TransferId }
  | { readonly type: 'sftp_cancel'; readonly transferId: TransferId };

export type Event =
  | { readonly type: 'state_snapshot'; readonly state: UiState }
  | { readonly type: 'vault_status_changed'; readonly status: VaultStatus }
  | { readonly type: 'session_updated'; readonly session: SessionSnapshot }
  | { readonly type: 'session_closed'; readonly sessionId: SessionId; readonly reason?: string }
  | { readonly type: 'terminal_output'; readonly sessionId: SessionId; readonly data: string }
  | { readonly type: 'host_key_verify_request'; readonly verification: HostKeyVerification }
  | { readonly type: 'sftp_progress'; readonly progress: SftpTransferProgress }
  | { readonly type: 'sftp_dir_listed'; readonly sessionId: SessionId; readonly remotePath: string; readonly entries: readonly SftpEntry[] }
  | { readonly type: 'ssh_config_imported'; readonly importedCount: number; readonly ignoredProxyCommands: readonly string[] }
  | { readonly type: 'error_occurred'; readonly code: string; readonly message: string; readonly details?: string };

export interface UiState {
  readonly vault: VaultStatus;
  readonly hosts: readonly HostConfig[];
  readonly activeSessions: readonly SessionSnapshot[];
  readonly selectedSessionId?: SessionId;
  readonly pendingHostKeyVerification?: HostKeyVerification;
  readonly sftpTransfers: readonly SftpTransferProgress[];
  readonly sftpEntriesBySession?: Readonly<Record<SessionId, { readonly remotePath: string; readonly entries: readonly SftpEntry[] }>>;
}
