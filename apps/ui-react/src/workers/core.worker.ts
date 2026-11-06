/**
 * WebWorker hosting the EasySSH Core (WASM module).
 *
 * CRITICAL SECURITY INVARIANT:
 * All SSH connections, cryptographic operations, host key validations,
 * OpenSSH config parsing, and decrypted private key material live strictly
 * inside this worker's isolated thread. Raw private keys and cleartext
 * passphrases NEVER leave this worker.
 */

import type {
  Command,
  Event,
  UiState,
  HostConfig,
  SessionSnapshot,
  HostKeyVerification,
  HostId,
  SessionId,
  TransferId,
  SftpEntry,
  SftpTransferProgress,
} from '../types/proto';
import { toHostId, toSessionId, toKeyHandle, toTransferId } from '../types/proto';

// Initial mock state for M0 scaffold
const initialHosts: HostConfig[] = [
  {
    id: toHostId('host-prod-db'),
    label: 'Production Database',
    hostname: 'db.internal.easyssh.local',
    port: 22,
    username: 'postgres',
    authMethod: 'publicKey',
    keyHandle: toKeyHandle('key-prod-root'),
    tags: ['production', 'database'],
    createdAt: Date.now() - 86400000 * 5,
    updatedAt: Date.now() - 86400000,
  },
  {
    id: toHostId('host-staging-web'),
    label: 'Staging Web Gateway',
    hostname: 'staging.easyssh.local',
    port: 2222,
    username: 'deploy',
    authMethod: 'password',
    tags: ['staging', 'web'],
    createdAt: Date.now() - 86400000 * 2,
    updatedAt: Date.now(),
  },
];

interface ParsedSshBlock {
  alias: string;
  hostName?: string;
  user?: string;
  port?: number;
  identityFile?: string;
  proxyJump?: string;
}

class CoreWorkerInstance {
  private readonly onEvent?: (event: Event) => void;

  public constructor(onEvent?: (event: Event) => void) {
    this.onEvent = onEvent;
  }

  private state: UiState = {
    vault: {
      isInitialized: true,
      isUnlocked: false,
      entryCount: 2,
      autoLockTimeoutSeconds: 300,
    },
    hosts: initialHosts,
    activeSessions: [],
    selectedSessionId: undefined,
    pendingHostKeyVerification: undefined,
    sftpTransfers: [],
    sftpEntriesBySession: {},
  };

  public handleCommand(command: Command): void {
    switch (command.type) {
      case 'init': {
        this.emitState();
        break;
      }

      case 'unlock_vault': {
        const isPassphraseValid = command.passphrase.trim().length > 0;
        if (isPassphraseValid) {
          this.state = {
            ...this.state,
            vault: {
              ...this.state.vault,
              isUnlocked: true,
            },
          };
          this.emit({
            type: 'vault_status_changed',
            status: this.state.vault,
          });
          this.emitState();
        } else {
          this.emit({
            type: 'error_occurred',
            code: 'VAULT_INVALID_PASSPHRASE',
            message: 'Failed to decrypt vault with provided passphrase.',
          });
        }
        break;
      }

      case 'lock_vault': {
        this.state = {
          ...this.state,
          vault: {
            ...this.state.vault,
            isUnlocked: false,
          },
        };
        this.emit({
          type: 'vault_status_changed',
          status: this.state.vault,
        });
        this.emitState();
        break;
      }

      case 'connect_host': {
        this.initiateConnection(command.hostId);
        break;
      }

      case 'confirm_host_key': {
        this.resolveHostKeyVerification(command.hostId, command.accepted, command.remember);
        break;
      }

      case 'disconnect_session': {
        this.terminateSession(command.sessionId);
        break;
      }

      case 'terminal_input': {
        if (command.data === '\r') {
          this.emit({
            type: 'terminal_output',
            sessionId: command.sessionId,
            data: '\r\n$ ',
          });
        } else {
          this.emit({
            type: 'terminal_output',
            sessionId: command.sessionId,
            data: command.data,
          });
        }
        break;
      }

      case 'terminal_resize': {
        break;
      }

      case 'create_host':
      case 'save_host': {
        const existingIndex = this.state.hosts.findIndex((h) => h.id === command.host.id);
        const updatedHosts = [...this.state.hosts];
        if (existingIndex >= 0) {
          updatedHosts[existingIndex] = command.host;
        } else {
          updatedHosts.push(command.host);
        }
        this.state = {
          ...this.state,
          hosts: updatedHosts,
        };
        this.emitState();
        break;
      }

      case 'delete_host': {
        this.state = {
          ...this.state,
          hosts: this.state.hosts.filter((h) => h.id !== command.hostId),
        };
        this.emitState();
        break;
      }

      case 'select_session': {
        this.state = {
          ...this.state,
          selectedSessionId: command.sessionId,
        };
        this.emitState();
        break;
      }

      case 'import_ssh_config': {
        this.handleImportSshConfig(command.configText);
        break;
      }

      case 'sftp_list_dir': {
        this.handleSftpListDir(command.sessionId, command.remotePath);
        break;
      }

      case 'sftp_upload': {
        this.handleSftpUpload(command.sessionId, command.localPath, command.remotePath, command.size);
        break;
      }

      case 'sftp_download': {
        this.handleSftpDownload(command.sessionId, command.remotePath, command.localPath, command.size);
        break;
      }

      case 'sftp_pause_resume': {
        this.handleSftpPauseResume(command.transferId);
        break;
      }

      case 'sftp_cancel': {
        this.handleSftpCancel(command.transferId);
        break;
      }
    }
  }

  /**
   * Safely parse OpenSSH ~/.ssh/config format.
   *
   * SECURITY INVARIANT:
   * ProxyCommand is intentionally IGNORED and NOT EXECUTED to prevent arbitrary
   * command injection from malicious configuration files.
   */
  private handleImportSshConfig(configText: string): void {
    const lines = configText.split(/\r?\n/);
    const parsedBlocks: ParsedSshBlock[] = [];
    const ignoredProxyCommands: string[] = [];

    let currentBlock: ParsedSshBlock | null = null;

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) {
        continue;
      }

      // Check key-value pairs (space or equal separated)
      const match = line.match(/^([A-Za-z0-9_]+)[=\s]+(.*)$/);
      if (!match) continue;

      const key = match[1]?.toLowerCase();
      const value = match[2]?.trim() ?? '';

      if (key === 'host') {
        // Start of new host block(s)
        const aliases = value.split(/\s+/).filter(Boolean);
        for (const alias of aliases) {
          if (alias === '*') {
            // Global wildcard defaults can be skipped for host card creation
            currentBlock = null;
            continue;
          }
          currentBlock = { alias };
          parsedBlocks.push(currentBlock);
        }
      } else if (currentBlock) {
        if (key === 'hostname') {
          currentBlock.hostName = value;
        } else if (key === 'user') {
          currentBlock.user = value;
        } else if (key === 'port') {
          const parsedPort = parseInt(value, 10);
          if (!isNaN(parsedPort) && parsedPort > 0) {
            currentBlock.port = parsedPort;
          }
        } else if (key === 'identityfile') {
          currentBlock.identityFile = value;
        } else if (key === 'proxyjump') {
          currentBlock.proxyJump = value;
        } else if (key === 'proxycommand') {
          // SECURITY VIOLATION PREVENTION:
          // Strictly reject and ignore ProxyCommand directives!
          ignoredProxyCommands.push(`${currentBlock.alias}: ${value}`);
        }
      }
    }

    const newHosts: HostConfig[] = parsedBlocks.map((block) => {
      const tags: string[] = ['ssh-config'];
      if (block.proxyJump) {
        tags.push('jump-host');
      }

      return {
        id: toHostId(`host-sshconfig-${block.alias.toLowerCase().replace(/[^a-z0-9-]/g, '-')}`),
        label: block.alias,
        hostname: block.hostName || block.alias,
        port: block.port || 22,
        username: block.user || 'root',
        authMethod: block.identityFile ? 'publicKey' : 'password',
        identityFile: block.identityFile,
        tags,
        createdAt: Date.now(),
        updatedAt: Date.now(),
      };
    });

    // Merge without duplicate IDs
    const existingIds = new Set(this.state.hosts.map((h) => h.id));
    const uniqueNewHosts = newHosts.filter((h) => !existingIds.has(h.id));

    this.state = {
      ...this.state,
      hosts: [...this.state.hosts, ...uniqueNewHosts],
    };

    this.emit({
      type: 'ssh_config_imported',
      importedCount: uniqueNewHosts.length,
      ignoredProxyCommands,
    });
    this.emitState();
  }

  private handleSftpListDir(sessionId: SessionId, remotePath: string): void {
    const cleanPath = remotePath.startsWith('/') ? remotePath : `/${remotePath}`;

    // Generate mock directory listing representing standard remote server hierarchy
    const mockEntries: SftpEntry[] = [
      {
        name: '..',
        path: cleanPath === '/' ? '/' : cleanPath.replace(/\/[^/]+$/, '') || '/',
        size: 4096,
        isDir: true,
        isSymlink: false,
        modifiedEpochS: Math.floor(Date.now() / 1000) - 3600,
        permissions: 0o755,
      },
      {
        name: 'bin',
        path: `${cleanPath === '/' ? '' : cleanPath}/bin`,
        size: 4096,
        isDir: true,
        isSymlink: false,
        modifiedEpochS: Math.floor(Date.now() / 1000) - 86400 * 10,
        permissions: 0o755,
      },
      {
        name: 'etc',
        path: `${cleanPath === '/' ? '' : cleanPath}/etc`,
        size: 4096,
        isDir: true,
        isSymlink: false,
        modifiedEpochS: Math.floor(Date.now() / 1000) - 86400 * 5,
        permissions: 0o755,
      },
      {
        name: 'logs',
        path: `${cleanPath === '/' ? '' : cleanPath}/logs`,
        size: 4096,
        isDir: true,
        isSymlink: false,
        modifiedEpochS: Math.floor(Date.now() / 1000) - 600,
        permissions: 0o755,
      },
      {
        name: 'app.config.yaml',
        path: `${cleanPath === '/' ? '' : cleanPath}/app.config.yaml`,
        size: 2048,
        isDir: false,
        isSymlink: false,
        modifiedEpochS: Math.floor(Date.now() / 1000) - 3600 * 2,
        permissions: 0o644,
      },
      {
        name: 'server.log',
        path: `${cleanPath === '/' ? '' : cleanPath}/server.log`,
        size: 1548576, // ~1.5 MB
        isDir: false,
        isSymlink: false,
        modifiedEpochS: Math.floor(Date.now() / 1000) - 60,
        permissions: 0o644,
      },
      {
        name: 'current_build.tar.gz',
        path: `${cleanPath === '/' ? '' : cleanPath}/current_build.tar.gz`,
        size: 8388608, // 8 MB
        isDir: false,
        isSymlink: false,
        modifiedEpochS: Math.floor(Date.now() / 1000) - 86400,
        permissions: 0o644,
      },
    ];

    const currentEntriesMap = { ...this.state.sftpEntriesBySession };
    currentEntriesMap[sessionId] = {
      remotePath: cleanPath,
      entries: mockEntries,
    };

    this.state = {
      ...this.state,
      sftpEntriesBySession: currentEntriesMap,
    };

    this.emit({
      type: 'sftp_dir_listed',
      sessionId,
      remotePath: cleanPath,
      entries: mockEntries,
    });
    this.emitState();
  }

  private handleSftpUpload(sessionId: SessionId, localPath: string, remotePath: string, size?: number): void {
    const transferId = toTransferId(`xfer-up-${Date.now()}`);
    const fileName = localPath.split(/[/\\]/).pop() || 'upload.bin';
    const totalBytes = size || 2097152; // 2MB

    const newTransfer: SftpTransferProgress = {
      transferId,
      sessionId,
      localPath,
      localFileName: fileName,
      remotePath,
      direction: 'upload',
      isUpload: true,
      bytesTransferred: 524288,
      totalBytes,
      resumable: true,
      state: 'transferring',
      speedBytesPerSec: 524288,
    };

    this.state = {
      ...this.state,
      sftpTransfers: [newTransfer, ...this.state.sftpTransfers],
    };

    this.emit({
      type: 'sftp_progress',
      progress: newTransfer,
    });
    this.emitState();
  }

  private handleSftpDownload(sessionId: SessionId, remotePath: string, localPath: string, size?: number): void {
    const transferId = toTransferId(`xfer-down-${Date.now()}`);
    const fileName = remotePath.split('/').pop() || 'download.bin';
    const totalBytes = size || 4194304; // 4MB

    const newTransfer: SftpTransferProgress = {
      transferId,
      sessionId,
      localPath,
      localFileName: fileName,
      remotePath,
      direction: 'download',
      isUpload: false,
      bytesTransferred: 1048576,
      totalBytes,
      resumable: true,
      state: 'transferring',
      speedBytesPerSec: 1048576,
    };

    this.state = {
      ...this.state,
      sftpTransfers: [newTransfer, ...this.state.sftpTransfers],
    };

    this.emit({
      type: 'sftp_progress',
      progress: newTransfer,
    });
    this.emitState();
  }

  private handleSftpPauseResume(transferId: TransferId): void {
    const transfer = this.state.sftpTransfers.find((t) => t.transferId === transferId);
    if (!transfer) return;

    const nextState = transfer.state === 'transferring' ? 'paused' : 'transferring';
    const updatedTransfer: SftpTransferProgress = {
      ...transfer,
      state: nextState,
      speedBytesPerSec: nextState === 'paused' ? 0 : 524288,
    };

    this.state = {
      ...this.state,
      sftpTransfers: this.state.sftpTransfers.map((t) =>
        t.transferId === transferId ? updatedTransfer : t
      ),
    };

    this.emit({
      type: 'sftp_progress',
      progress: updatedTransfer,
    });
    this.emitState();
  }

  private handleSftpCancel(transferId: TransferId): void {
    const transfer = this.state.sftpTransfers.find((t) => t.transferId === transferId);
    if (!transfer) return;

    const updatedTransfer: SftpTransferProgress = {
      ...transfer,
      state: 'cancelled',
      speedBytesPerSec: 0,
    };

    this.state = {
      ...this.state,
      sftpTransfers: this.state.sftpTransfers.map((t) =>
        t.transferId === transferId ? updatedTransfer : t
      ),
    };

    this.emit({
      type: 'sftp_progress',
      progress: updatedTransfer,
    });
    this.emitState();
  }

  private initiateConnection(hostId: HostId): void {
    const host = this.state.hosts.find((h) => h.id === hostId);
    if (!host) {
      this.emit({
        type: 'error_occurred',
        code: 'HOST_NOT_FOUND',
        message: `Host with ID ${hostId} does not exist.`,
      });
      return;
    }

    if (host.hostname.includes('staging')) {
      const verification: HostKeyVerification = {
        hostId: host.id,
        hostname: host.hostname,
        port: host.port,
        keyType: 'ssh-ed25519',
        fingerprintSha256: 'SHA256:7u7mB9xKq+O2F3g5H9QZ+8JmY9sE7rP0x4vW1a2b3c4',
        status: 'new',
      };
      this.state = {
        ...this.state,
        pendingHostKeyVerification: verification,
      };
      this.emit({
        type: 'host_key_verify_request',
        verification,
      });
      this.emitState();
      return;
    }

    this.createActiveSession(host);
  }

  private resolveHostKeyVerification(hostId: HostId, accepted: boolean, _remember: boolean): void {
    this.state = {
      ...this.state,
      pendingHostKeyVerification: undefined,
    };

    const host = this.state.hosts.find((h) => h.id === hostId);
    if (!host) return;

    if (accepted) {
      this.createActiveSession(host);
    } else {
      this.emit({
        type: 'error_occurred',
        code: 'HOST_KEY_REJECTED',
        message: 'Connection aborted by user: Untrusted host key rejected.',
      });
      this.emitState();
    }
  }

  private createActiveSession(host: HostConfig): void {
    const sessionId = toSessionId(`sess-${Date.now()}`);
    const newSession: SessionSnapshot = {
      sessionId,
      hostId: host.id,
      title: `${host.username}@${host.label}`,
      status: 'connected',
      latencyMs: 12,
      fps: 60,
      createdAt: Date.now(),
    };

    const updatedSessions = [...this.state.activeSessions, newSession];
    this.state = {
      ...this.state,
      activeSessions: updatedSessions,
      selectedSessionId: sessionId,
    };

    this.emit({
      type: 'session_updated',
      session: newSession,
    });
    this.emitState();

    this.emit({
      type: 'terminal_output',
      sessionId,
      data: `\x1b[32mConnected to ${host.label} (${host.hostname}:${host.port})\x1b[0m\r\n` +
            `Authenticated via ${host.authMethod}.\r\n` +
            `Last login: ${new Date().toLocaleString()} from 127.0.0.1\r\n$ `,
    });
  }

  private terminateSession(sessionId: SessionId): void {
    this.state = {
      ...this.state,
      activeSessions: this.state.activeSessions.filter((s) => s.sessionId !== sessionId),
      selectedSessionId:
        this.state.selectedSessionId === sessionId
          ? this.state.activeSessions.find((s) => s.sessionId !== sessionId)?.sessionId
          : this.state.selectedSessionId,
    };

    this.emit({
      type: 'session_closed',
      sessionId,
      reason: 'User disconnected',
    });
    this.emitState();
  }

  private emitState(): void {
    this.emit({
      type: 'state_snapshot',
      state: this.state,
    });
  }

  private emit(event: Event): void {
    if (this.onEvent) {
      this.onEvent(event);
      return;
    }
    if (typeof self !== 'undefined' && typeof self.postMessage === 'function') {
      self.postMessage(event);
    }
  }
}

const workerInstance = new CoreWorkerInstance();

if (typeof self !== 'undefined') {
  self.onmessage = (messageEvent: MessageEvent<Command>) => {
    workerInstance.handleCommand(messageEvent.data);
  };
}

export { CoreWorkerInstance };
