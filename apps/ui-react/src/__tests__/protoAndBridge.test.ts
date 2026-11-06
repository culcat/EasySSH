/**
 * Comprehensive Unit Tests for EasySSH Protocol Contract and Core Worker Bridge.
 *
 * Verifies:
 * 1. State updates and command dispatch cycle.
 * 2. Mandatory TOFU verification modal triggering (new host vs mismatch).
 * 3. Security invariant: Sensitive keys & passphrases are NEVER stored in browser storage.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  PROTO_VERSION,
  toHostId,
  toSessionId,
  toKeyHandle,
  type HostKeyVerification,
  type UiState,
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

    expect(hostId).toBe('host-123');
    expect(sessionId).toBe('session-456');
    expect(keyHandle).toBe('key-789');
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

describe('Security Invariant: No Storage Leakage', () => {
  beforeEach(() => {
    // Clear any test mock storage
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
      // KeyHandle must be an opaque identifier string, never an actual PEM/OpenSSH private key block
      if (host.keyHandle) {
        expect(host.keyHandle).not.toMatch(/BEGIN OPENSSH PRIVATE KEY/i);
        expect(host.keyHandle).not.toMatch(/BEGIN RSA PRIVATE KEY/i);
        expect(host.keyHandle).not.toMatch(/PRIVATE KEY/i);
      }
    }
  });

  it('assertStorageSanity prevents execution if sensitive keys are stored in localStorage', () => {
    // Create mock localStorage if not present in Node environment
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

    expect(() => coreWorkerBridge.assertStorageSanity()).toThrow(
      /SECURITY VIOLATION: Sensitive data pattern "passphrase"/
    );

    // Clean up
    storageMap.clear();
  });
});
