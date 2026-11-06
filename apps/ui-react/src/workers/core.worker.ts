/**
 * WebWorker hosting the EasySSH Core (WASM module).
 *
 * CRITICAL SECURITY INVARIANT:
 * All SSH connections, cryptographic operations, host key validations,
 * and decrypted private key material live strictly inside this worker's
 * isolated thread. Raw private keys and cleartext passphrases NEVER
 * leave this worker.
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
  KeyHandle,
} from '../types/proto';
import { toHostId, toSessionId, toKeyHandle } from '../types/proto';

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

class CoreWorkerInstance {
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
  };

  public handleCommand(command: Command): void {
    switch (command.type) {
      case 'init': {
        this.emitState();
        break;
      }

      case 'unlock_vault': {
        // In full WASM integration, passphrase is fed to Argon2id in crates/core.
        // Once decrypted, memory holding passphrase must be scrubbed immediately.
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
        // Echo input back with simple simulation for M0 scaffold
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
        // PTY window resize command
        break;
      }

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
    }
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

    // Check if host requires TOFU verification (e.g., simulating TOFU for first connect or mismatch test)
    if (host.hostname.includes('staging')) {
      // Simulate TOFU first-time verification
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

    // Direct connect
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

    // Initial terminal greeting
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
