import { useState, useEffect, useCallback, useMemo } from 'react';
import type {
  UiState,
  Command,
  Event,
  HostId,
  SessionId,
  HostConfig,
  SessionSnapshot,
} from '../types/proto';
import { coreWorkerBridge } from '../services/coreWorkerBridge';

export interface UseCoreStateReturn {
  readonly state: UiState;
  readonly activeSession: SessionSnapshot | undefined;
  readonly dispatch: (command: Command) => void;
  readonly unlockVault: (passphrase: string) => void;
  readonly lockVault: () => void;
  readonly connectHost: (hostId: HostId) => void;
  readonly disconnectSession: (sessionId: SessionId) => void;
  readonly selectSession: (sessionId: SessionId) => void;
  readonly sendTerminalInput: (sessionId: SessionId, data: string) => void;
  readonly confirmHostKey: (hostId: HostId, accepted: boolean, remember: boolean) => void;
  readonly saveHost: (host: HostConfig) => void;
  readonly deleteHost: (hostId: HostId) => void;
}

export function useCoreState(): UseCoreStateReturn {
  const [state, setState] = useState<UiState>(() => coreWorkerBridge.getState());

  useEffect(() => {
    coreWorkerBridge.start();
    setState(coreWorkerBridge.getState());

    const unsubscribe = coreWorkerBridge.subscribe((event: Event) => {
      if (event.type === 'state_snapshot') {
        setState(event.state);
      } else if (event.type === 'vault_status_changed') {
        setState((prev) => ({
          ...prev,
          vault: event.status,
        }));
      } else if (event.type === 'host_key_verify_request') {
        setState((prev) => ({
          ...prev,
          pendingHostKeyVerification: event.verification,
        }));
      }
    });

    return () => {
      unsubscribe();
    };
  }, []);

  const dispatch = useCallback((command: Command) => {
    coreWorkerBridge.dispatch(command);
  }, []);

  const unlockVault = useCallback(
    (passphrase: string) => {
      dispatch({ type: 'unlock_vault', passphrase });
    },
    [dispatch]
  );

  const lockVault = useCallback(() => {
    dispatch({ type: 'lock_vault' });
  }, [dispatch]);

  const connectHost = useCallback(
    (hostId: HostId) => {
      dispatch({ type: 'connect_host', hostId });
    },
    [dispatch]
  );

  const disconnectSession = useCallback(
    (sessionId: SessionId) => {
      dispatch({ type: 'disconnect_session', sessionId });
    },
    [dispatch]
  );

  const selectSession = useCallback(
    (sessionId: SessionId) => {
      dispatch({ type: 'select_session', sessionId });
    },
    [dispatch]
  );

  const sendTerminalInput = useCallback(
    (sessionId: SessionId, data: string) => {
      dispatch({ type: 'terminal_input', sessionId, data });
    },
    [dispatch]
  );

  const confirmHostKey = useCallback(
    (hostId: HostId, accepted: boolean, remember: boolean) => {
      dispatch({ type: 'confirm_host_key', hostId, accepted, remember });
    },
    [dispatch]
  );

  const saveHost = useCallback(
    (host: HostConfig) => {
      dispatch({ type: 'save_host', host });
    },
    [dispatch]
  );

  const deleteHost = useCallback(
    (hostId: HostId) => {
      dispatch({ type: 'delete_host', hostId });
    },
    [dispatch]
  );

  const activeSession = useMemo(() => {
    if (!state.selectedSessionId) {
      return state.activeSessions[0];
    }
    return state.activeSessions.find((s) => s.sessionId === state.selectedSessionId);
  }, [state.activeSessions, state.selectedSessionId]);

  return {
    state,
    activeSession,
    dispatch,
    unlockVault,
    lockVault,
    connectHost,
    disconnectSession,
    selectSession,
    sendTerminalInput,
    confirmHostKey,
    saveHost,
    deleteHost,
  };
}
