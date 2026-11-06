/**
 * CoreWorkerBridge: Manages communication between React UI and Core WebWorker.
 *
 * CRITICAL SECURITY INVARIANT:
 * 1. UI receives only sanitized state snapshots and opaque KeyHandle references.
 * 2. Raw private keys and plaintext passphrases must NEVER be written to localStorage,
 *    sessionStorage, or any browser cache.
 */

import type { Command, Event, UiState } from '../types/proto';
import { CoreWorkerInstance } from '../workers/core.worker';

export type EventListener = (event: Event) => void;

class CoreWorkerBridge {
  private worker: Worker | null = null;
  private fallbackWorker: CoreWorkerInstance | null = null;
  private listeners: Set<EventListener> = new Set();
  private currentState: UiState = {
    vault: {
      isInitialized: true,
      isUnlocked: false,
      entryCount: 0,
      autoLockTimeoutSeconds: 300,
    },
    hosts: [],
    activeSessions: [],
    selectedSessionId: undefined,
    pendingHostKeyVerification: undefined,
    sftpTransfers: [],
  };

  /**
   * Defensive assertion: Verify no secret keys or passwords leak into browser storage.
   */
  public assertStorageSanity(): void {
    const forbiddenPatterns = [
      'passphrase',
      'password',
      'secret',
      'privatekey',
      'id_rsa',
      'id_ed25519',
      'vault_key',
    ];

    const checkStorage = (storage: Storage | undefined, name: string): void => {
      if (!storage) return;
      for (let i = 0; i < storage.length; i++) {
        const key = storage.key(i);
        if (!key) continue;
        const lowerKey = key.toLowerCase();
        for (const pattern of forbiddenPatterns) {
          if (lowerKey.includes(pattern)) {
            throw new Error(
              `SECURITY VIOLATION: Sensitive data pattern "${pattern}" detected in ${name} key "${key}"`
            );
          }
        }
      }
    };

    try {
      checkStorage(globalThis.localStorage, 'localStorage');
      checkStorage(globalThis.sessionStorage, 'sessionStorage');
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('SECURITY VIOLATION')) {
        throw err;
      }
    }
  }

  public start(): void {
    if (this.worker || this.fallbackWorker) {
      return;
    }

    this.assertStorageSanity();

    if (typeof Worker !== 'undefined') {
      try {
        this.worker = new Worker(
          new URL('../workers/core.worker.ts', import.meta.url),
          { type: 'module' }
        );

        this.worker.onmessage = (event: MessageEvent<Event>) => {
          this.handleIncomingEvent(event.data);
        };

        this.worker.onerror = (error) => {
          console.error('[CoreWorkerBridge] Worker error:', error);
        };

        this.dispatch({ type: 'init' });
        return;
      } catch (e) {
        console.warn('[CoreWorkerBridge] Worker initialization failed, using in-memory worker:', e);
      }
    }

    // Node or environment without Worker support (e.g. unit tests)
    this.fallbackWorker = new CoreWorkerInstance((event: Event) => {
      this.handleIncomingEvent(event);
    });
    this.dispatch({ type: 'init' });
  }

  public dispatch(command: Command): void {
    // Assert storage sanity on each command dispatch
    this.assertStorageSanity();

    if (this.worker) {
      this.worker.postMessage(command);
    } else if (this.fallbackWorker) {
      this.fallbackWorker.handleCommand(command);
    }
  }

  public subscribe(listener: EventListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  public getState(): UiState {
    return this.currentState;
  }

  public handleIncomingEvent(event: Event): void {
    if (event.type === 'state_snapshot') {
      this.currentState = event.state;
    } else if (event.type === 'vault_status_changed') {
      this.currentState = {
        ...this.currentState,
        vault: event.status,
      };
    }

    for (const listener of this.listeners) {
      listener(event);
    }
  }

  public terminate(): void {
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }
    this.fallbackWorker = null;
    this.listeners.clear();
  }
}

export const coreWorkerBridge = new CoreWorkerBridge();
