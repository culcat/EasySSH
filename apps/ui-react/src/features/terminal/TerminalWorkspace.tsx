import React, { useEffect, useRef, useMemo } from 'react';
import clsx from 'clsx';
import type { SessionSnapshot, SessionId } from '../../types/proto';
import { useI18n } from '../../i18n';
import { coreWorkerBridge } from '../../services/coreWorkerBridge';
import { Badge } from '../../ui';
import styles from './TerminalWorkspace.module.css';

export interface TerminalWorkspaceProps {
  readonly sessions: readonly SessionSnapshot[];
  readonly selectedSessionId: SessionId | undefined;
  readonly onSelectSession: (sessionId: SessionId) => void;
  readonly onCloseSession: (sessionId: SessionId) => void;
  readonly onTerminalInput: (sessionId: SessionId, data: string) => void;
}

export const TerminalWorkspace: React.FC<TerminalWorkspaceProps> = ({
  sessions,
  selectedSessionId,
  onSelectSession,
  onCloseSession,
  onTerminalInput,
}) => {
  const { t } = useI18n();
  const terminalHostRef = useRef<HTMLDivElement>(null);

  const activeSession = useMemo(() => {
    return sessions.find((s) => s.sessionId === selectedSessionId) ?? sessions[0];
  }, [sessions, selectedSessionId]);

  // Dynamic import / initialization of xterm to remain resilient in Node/test environments
  useEffect(() => {
    if (!activeSession || !terminalHostRef.current) return;

    let isDisposed = false;
    let cleanupHandler: (() => void) | undefined;

    const setupTerminal = async () => {
      try {
        const { Terminal } = await import('@xterm/xterm');
        const { FitAddon } = await import('@xterm/addon-fit');

        if (isDisposed || !terminalHostRef.current) return;

        // Clear container
        terminalHostRef.current.innerHTML = '';

        const term = new Terminal({
          cursorBlink: true,
          fontFamily: 'Menlo, Monaco, "Courier New", monospace',
          fontSize: 14,
          theme: {
            background: '#030712',
            foreground: '#f8fafc',
            cursor: '#3b82f6',
            selectionBackground: '#1e3a8a',
          },
        });

        const fitAddon = new FitAddon();
        term.loadAddon(fitAddon);

        term.open(terminalHostRef.current);
        fitAddon.fit();

        // Attempt WebGL renderer addon with graceful fallback
        try {
          const { WebglAddon } = await import('@xterm/addon-webgl');
          const webglAddon = new WebglAddon();
          webglAddon.onContextLoss(() => {
            webglAddon.dispose();
          });
          term.loadAddon(webglAddon);
        } catch {
          // WebGL unavailable (e.g. headless or unsupported browser), falls back to DOM/Canvas
        }

        const inputDisposable = term.onData((data: string) => {
          onTerminalInput(activeSession.sessionId, data);
        });

        // Listen for output from the bridge
        const unsubscribe = coreWorkerBridge.subscribe((event) => {
          if (
            event.type === 'terminal_output' &&
            event.sessionId === activeSession.sessionId
          ) {
            term.write(event.data);
          }
        });

        const handleResize = () => {
          try {
            fitAddon.fit();
          } catch {
            // Container might be hidden
          }
        };

        window.addEventListener('resize', handleResize);

        cleanupHandler = () => {
          inputDisposable.dispose();
          unsubscribe();
          window.removeEventListener('resize', handleResize);
          term.dispose();
        };
      } catch (err) {
        console.warn('[TerminalWorkspace] Terminal rendering initialization deferred:', err);
      }
    };

    void setupTerminal();

    return () => {
      isDisposed = true;
      cleanupHandler?.();
    };
  }, [activeSession, onTerminalInput]);

  const getStatusBadge = (status: SessionSnapshot['status']) => {
    switch (status) {
      case 'connected':
        return <Badge variant="success" size="sm" withDot>{t('terminal.statusConnected')}</Badge>;
      case 'connecting':
        return <Badge variant="info" size="sm" withDot>{t('terminal.statusConnecting')}</Badge>;
      case 'authenticating':
        return <Badge variant="warning" size="sm" withDot>{t('terminal.statusAuthenticating')}</Badge>;
      case 'error':
        return <Badge variant="danger" size="sm" withDot>{t('terminal.statusError')}</Badge>;
      case 'disconnected':
      default:
        return <Badge variant="default" size="sm" withDot>{t('terminal.statusDisconnected')}</Badge>;
    }
  };

  const getLatencyClass = (latencyMs: number) => {
    if (latencyMs < 50) return styles.latencyLow;
    if (latencyMs < 150) return styles.latencyMedium;
    return styles.latencyHigh;
  };

  if (sessions.length === 0) {
    return (
      <main className={styles.workspace} aria-label={t('terminal.terminalStats')}>
        <div className={styles.emptyState}>
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <polyline points="4 17 10 11 4 5" />
            <line x1="12" y1="19" x2="20" y2="19" />
          </svg>
          <h2 className={styles.emptyTitle}>{t('terminal.noActiveSessions')}</h2>
          <p className={styles.emptyDesc}>{t('terminal.noActiveSessionsDesc')}</p>
        </div>
      </main>
    );
  }

  return (
    <main className={styles.workspace}>
      <div className={styles.tabBar} role="tablist">
        {sessions.map((session) => {
          const isActive = session.sessionId === activeSession?.sessionId;
          return (
            <button
              key={session.sessionId}
              role="tab"
              aria-selected={isActive}
              className={clsx(styles.tab, isActive && styles.tabActive)}
              onClick={() => onSelectSession(session.sessionId)}
            >
              <span>{session.title}</span>
              <span
                role="button"
                tabIndex={0}
                className={styles.tabCloseButton}
                onClick={(e) => {
                  e.stopPropagation();
                  onCloseSession(session.sessionId);
                }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.stopPropagation();
                    onCloseSession(session.sessionId);
                  }
                }}
                aria-label={t('terminal.closeTab')}
              >
                ×
              </span>
            </button>
          );
        })}
      </div>

      <div className={styles.terminalContainer}>
        <div ref={terminalHostRef} className={styles.xtermHost} />
      </div>

      {activeSession && (
        <footer className={styles.statsBar} aria-label={t('terminal.terminalStats')}>
          <div className={styles.statsLeft}>
            {getStatusBadge(activeSession.status)}
            <span className={styles.statItem}>
              {activeSession.sessionId}
            </span>
          </div>

          <div className={styles.statsRight}>
            <span className={styles.statItem}>
              {t('terminal.latency')}:{' '}
              <strong className={getLatencyClass(activeSession.latencyMs)}>
                {activeSession.latencyMs} ms
              </strong>
            </span>
            <span className={styles.statItem}>
              {t('terminal.fps')}:{' '}
              <strong className={styles.fpsStat}>{activeSession.fps}</strong>
            </span>
          </div>
        </footer>
      )}
    </main>
  );
};
