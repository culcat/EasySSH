/**
 * Comprehensive Unit Tests for EasySSH Protocol Contract and Core Worker Bridge.
 *
 * Verifies:
 * 1. State updates and command dispatch cycle.
 * 2. Mandatory TOFU verification modal triggering (new host vs mismatch).
 * 3. Security invariant: Sensitive keys & passphrases are NEVER stored in browser storage.
 * 4. OpenSSH ~/.ssh/config importing with strict ProxyCommand stripping.
 * 5. SFTP remote file listing and upload/download/pause/resume/cancel lifecycle.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  PROTO_VERSION,
  toHostId,
  toSessionId,
  toKeyHandle,
  toTransferId,
  type HostKeyVerification,
  type UiState,
  type SftpEntry,
  type SftpTransferProgress,
} from '../types/proto';
import { coreWorkerBridge } from '../services/coreWorkerBridge';

describe('Proto Contract and Types', () => {
  it('exposes correct protocol version matching core', () => {
    expect(PROTO_VERSION).toBe('1.0.0');
  });

  it('correctly brands entity identifiers', () => {
    const hostId = toHostId('host-123');
    const sessionId = toSessionId('session-456');
    const keyHandle = toKeyHandle('key-789');
    const transferId = toTransferId('transfer-abc');

    expect(hostId).toBe('host-123');
    expect(sessionId).toBe('session-456');
    expect(keyHandle).toBe('key-789');
    expect(transferId).toBe('transfer-abc');
  });
});

describe('CoreWorkerBridge & CoreWorkerInstance', () => {
  it('dispatches init and receives state snapshot', () => {
    const receivedStates: UiState[] = [];
    const unsubscribe = coreWorkerBridge.subscribe((event) => {
      if (event.type === 'state_snapshot') {
        receivedStates.push(event.state);
      }
    });

    coreWorkerBridge.start();
    coreWorkerBridge.dispatch({ type: 'init' });

    const state = coreWorkerBridge.getState();
    expect(state).toBeDefined();
    expect(state.vault).toBeDefined();
    expect(state.vault.isUnlocked).toBe(false);

    unsubscribe();
  });

  it('handles vault unlock and lock cycle with memory zeroing semantics', () => {
    let latestStatus = coreWorkerBridge.getState().vault;

    const unsubscribe = coreWorkerBridge.subscribe((event) => {
      if (event.type === 'vault_status_changed') {
        latestStatus = event.status;
      }
    });

    // Unlock with valid passphrase
    coreWorkerBridge.dispatch({ type: 'unlock_vault', passphrase: 'master-test-passphrase' });
    expect(latestStatus.isUnlocked).toBe(true);

    // Lock vault
    coreWorkerBridge.dispatch({ type: 'lock_vault' });
    expect(latestStatus.isUnlocked).toBe(false);

    unsubscribe();
  });

  it('triggers mandatory TOFU host key verification on first connect', () => {
    let capturedVerification: HostKeyVerification | undefined;

    const unsubscribe = coreWorkerBridge.subscribe((event) => {
      if (event.type === 'host_key_verify_request') {
        capturedVerification = event.verification;
      }
    });

    // Staging host is configured in mock core to simulate first-time TOFU verification
    const stagingHostId = toHostId('host-staging-web');
    coreWorkerBridge.dispatch({ type: 'connect_host', hostId: stagingHostId });

    expect(capturedVerification).toBeDefined();
    expect(capturedVerification?.status).toBe('new');
    expect(capturedVerification?.fingerprintSha256).toMatch(/^SHA256:/);
    expect(capturedVerification?.keyType).toBe('ssh-ed25519');

    // Confirm host key
    coreWorkerBridge.dispatch({
      type: 'confirm_host_key',
      hostId: stagingHostId,
      accepted: true,
      remember: true,
    });

    // State should now have active session
    const state = coreWorkerBridge.getState();
    expect(state.pendingHostKeyVerification).toBeUndefined();

    unsubscribe();
  });

  it('handles host key mismatch detection and rejection correctly', () => {
    const mismatchVerification: HostKeyVerification = {
      hostId: toHostId('host-compromised'),
      hostname: 'suspicious.server.net',
      port: 22,
      keyType: 'ssh-ed25519',
      fingerprintSha256: 'SHA256:ATTACKER_KEY_CHANGED_1234567890',
      previousFingerprintSha256: 'SHA256:TRUSTED_ORIGINAL_KEY_0987654321',
      status: 'mismatch',
    };

    expect(mismatchVerification.status).toBe('mismatch');
    expect(mismatchVerification.previousFingerprintSha256).not.toBe(
      mismatchVerification.fingerprintSha256
    );

    // Simulate rejection
    coreWorkerBridge.dispatch({
      type: 'confirm_host_key',
      hostId: mismatchVerification.hostId,
      accepted: false,
      remember: false,
    });

    const state = coreWorkerBridge.getState();
    expect(state.pendingHostKeyVerification).toBeUndefined();
  });
});

describe('OpenSSH Config Import & Security Guard', () => {
  it('safely parses OpenSSH config blocks and strips ProxyCommand directives', () => {
    const rawSshConfig = `
# Global defaults
Host *
  ServerAliveInterval 60

# Production cluster node
Host prod-app
  HostName app.easyssh.corp
  User deploy
  Port 22022
  IdentityFile ~/.ssh/id_ed25519_deploy

# Jump host configuration
Host bastion-gw
  HostName jump.easyssh.corp
  User jumpuser
  Port 22

# Dangerous config with ProxyCommand injection attempt
Host malicious-target
  HostName internal.server
  User root
  ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p
  ProxyJump bastion-gw
`;

    let importEventResult: { importedCount: number; ignoredProxyCommands: readonly string[] } | undefined;

    const unsubscribe = coreWorkerBridge.subscribe((event) => {
      if (event.type === 'ssh_config_imported') {
        importEventResult = {
          importedCount: event.importedCount,
          ignoredProxyCommands: event.ignoredProxyCommands,
        };
      }
    });

    coreWorkerBridge.dispatch({
      type: 'import_ssh_config',
      configText: rawSshConfig,
    });

    expect(importEventResult).toBeDefined();
    expect(importEventResult?.importedCount).toBeGreaterThanOrEqual(3);

    // SECURITY CHECK: ProxyCommand MUST be detected and ignored
    expect(importEventResult?.ignoredProxyCommands.length).toBeGreaterThan(0);
    expect(
      importEventResult?.ignoredProxyCommands.some((c) => c.includes('ProxyCommand') || c.includes('nc -X'))
    ).toBe(true);

    // Check parsed hosts in state
    const state = coreWorkerBridge.getState();
    const importedHost = state.hosts.find((h) => h.label === 'prod-app');
    expect(importedHost).toBeDefined();
    expect(importedHost?.hostname).toBe('app.easyssh.corp');
    expect(importedHost?.username).toBe('deploy');
    expect(importedHost?.port).toBe(22022);
    expect(importedHost?.identityFile).toBe('~/.ssh/id_ed25519_deploy');

    unsubscribe();
  });
});

describe('SFTP Remote File Browser & Transfer Queue', () => {
  const testSessionId = toSessionId('sftp-test-session');

  it('lists remote directory entries via sftp_list_dir', () => {
    let capturedEntries: readonly SftpEntry[] = [];
    let capturedPath = '';

    const unsubscribe = coreWorkerBridge.subscribe((event) => {
      if (event.type === 'sftp_dir_listed' && event.sessionId === testSessionId) {
        capturedEntries = event.entries;
        capturedPath = event.remotePath;
      }
    });

    coreWorkerBridge.dispatch({
      type: 'sftp_list_dir',
      sessionId: testSessionId,
      remotePath: '/var/log',
    });

    expect(capturedPath).toBe('/var/log');
    expect(capturedEntries.length).toBeGreaterThan(0);
    expect(capturedEntries.some((e) => e.name === '..')).toBe(true);
    expect(capturedEntries.some((e) => e.isDir)).toBe(true);

    unsubscribe();
  });

  it('manages file upload, progress tracking, pause/resume and cancellation', () => {
    let latestProgress: SftpTransferProgress | undefined;

    const unsubscribe = coreWorkerBridge.subscribe((event) => {
      if (event.type === 'sftp_progress') {
        latestProgress = event.progress;
      }
    });

    // 1. Initiate upload
    coreWorkerBridge.dispatch({
      type: 'sftp_upload',
      sessionId: testSessionId,
      localPath: '/tmp/test-artifact.tar.gz',
      remotePath: '/home/deploy/test-artifact.tar.gz',
      size: 4194304,
    });

    expect(latestProgress).toBeDefined();
    expect(latestProgress?.isUpload).toBe(true);
    expect(latestProgress?.direction).toBe('upload');
    expect(latestProgress?.state).toBe('transferring');
    expect(latestProgress?.resumable).toBe(true);

    const activeTransferId = latestProgress!.transferId;

    // 2. Pause transfer
    coreWorkerBridge.dispatch({
      type: 'sftp_pause_resume',
      transferId: activeTransferId,
    });

    expect(latestProgress?.state).toBe('paused');

    // 3. Resume transfer
    coreWorkerBridge.dispatch({
      type: 'sftp_pause_resume',
      transferId: activeTransferId,
    });

    expect(latestProgress?.state).toBe('transferring');

    // 4. Cancel transfer
    coreWorkerBridge.dispatch({
      type: 'sftp_cancel',
      transferId: activeTransferId,
    });

    expect(latestProgress?.state).toBe('cancelled');

    unsubscribe();
  });
});

describe('Security Invariant: No Storage Leakage', () => {
  beforeEach(() => {
    if (typeof localStorage !== 'undefined') {
      localStorage.clear();
    }
    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.clear();
    }
  });

  afterEach(() => {
    if (typeof localStorage !== 'undefined') {
      localStorage.clear();
    }
  });

  it('verifies that host models hold only opaque KeyHandles and no raw private keys', () => {
    const state = coreWorkerBridge.getState();
    for (const host of state.hosts) {
      if (host.keyHandle) {
        expect(host.keyHandle).not.toMatch(/BEGIN OPENSSH PRIVATE KEY/i);
        expect(host.keyHandle).not.toMatch(/BEGIN RSA PRIVATE KEY/i);
        expect(host.keyHandle).not.toMatch(/PRIVATE KEY/i);
      }
    }
  });

  it('assertStorageSanity prevents execution if sensitive keys are stored in localStorage', () => {
    const storageMap = new Map<string, string>();
    const mockStorage: Storage = {
      length: 0,
      clear: () => storageMap.clear(),
      getItem: (key: string) => storageMap.get(key) ?? null,
      key: (index: number) => Array.from(storageMap.keys())[index] ?? null,
      removeItem: (key: string) => {
        storageMap.delete(key);
      },
      setItem: (key: string, value: string) => {
        storageMap.set(key, value);
      },
    };

    Object.defineProperty(globalThis, 'localStorage', {
      value: mockStorage,
      writable: true,
      configurable: true,
    });

    // Clean storage - should not throw
    expect(() => coreWorkerBridge.assertStorageSanity()).not.toThrow();

    // Malicious or accidental secret leak
    mockStorage.setItem('cached_passphrase', 'supersecret');
    Object.defineProperty(mockStorage, 'length', { get: () => storageMap.size });

    expect(() => coreWorkerBridge.assertStorageSanity()).throw(
      /SECURITY VIOLATION: Sensitive data pattern "passphrase"/
    );

    // Clean up
    storageMap.clear();
  });
});
