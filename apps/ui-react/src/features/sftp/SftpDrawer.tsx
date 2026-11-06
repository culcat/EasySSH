import React, { useState, useEffect } from 'react';
import type {
  SessionId,
  TransferId,
  SftpEntry,
  SftpTransferProgress,
} from '../../types/proto';
import { useI18n } from '../../i18n';
import { Button, Badge } from '../../ui';
import styles from './SftpDrawer.module.css';

export interface SftpDrawerProps {
  readonly isOpen: boolean;
  readonly onClose: () => void;
  readonly sessionId: SessionId | undefined;
  readonly sessionTitle?: string;
  readonly entries: readonly SftpEntry[];
  readonly transfers: readonly SftpTransferProgress[];
  readonly onListDir: (sessionId: SessionId, remotePath: string) => void;
  readonly onUpload: (sessionId: SessionId, localPath: string, remotePath: string, size?: number) => void;
  readonly onDownload: (sessionId: SessionId, remotePath: string, localPath: string, size?: number) => void;
  readonly onPauseResume: (transferId: TransferId) => void;
  readonly onCancel: (transferId: TransferId) => void;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i] ?? 'B'}`;
}

export const SftpDrawer: React.FC<SftpDrawerProps> = ({
  isOpen,
  onClose,
  sessionId,
  sessionTitle,
  entries,
  transfers,
  onListDir,
  onUpload,
  onDownload,
  onPauseResume,
  onCancel,
}) => {
  const { t } = useI18n();
  const [currentPath, setCurrentPath] = useState('/home/deploy');

  // Trigger listing on mount or session change
  useEffect(() => {
    if (isOpen && sessionId) {
      onListDir(sessionId, currentPath);
    }
  }, [isOpen, sessionId, currentPath, onListDir]);

  if (!isOpen || !sessionId) return null;

  const handleNavigate = () => {
    if (sessionId) {
      onListDir(sessionId, currentPath);
    }
  };

  const handleEntryClick = (entry: SftpEntry) => {
    if (entry.isDir) {
      setCurrentPath(entry.path);
      onListDir(sessionId, entry.path);
    }
  };

  const handleSimulatedUpload = () => {
    const fileName = `upload-${Date.now().toString().slice(-4)}.bin`;
    onUpload(sessionId, `/tmp/${fileName}`, `${currentPath}/${fileName}`, 1048576 * 2);
  };

  const getStatusBadge = (state: SftpTransferProgress['state']) => {
    switch (state) {
      case 'transferring':
        return <Badge variant="info" size="sm" withDot>{t('sftp.statusTransferring')}</Badge>;
      case 'paused':
        return <Badge variant="warning" size="sm" withDot>{t('sftp.statusPaused')}</Badge>;
      case 'completed':
        return <Badge variant="success" size="sm" withDot>{t('sftp.statusCompleted')}</Badge>;
      case 'cancelled':
        return <Badge variant="default" size="sm">{t('sftp.statusCancelled')}</Badge>;
      case 'failed':
        return <Badge variant="danger" size="sm">{t('sftp.statusFailed')}</Badge>;
      default:
        return <Badge variant="default" size="sm">{t('sftp.statusPending')}</Badge>;
    }
  };

  return (
    <aside className={styles.drawer} aria-label={t('sftp.drawerTitle')}>
      <div className={styles.header}>
        <div className={styles.titleArea}>
          <h2 className={styles.title}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
            </svg>
            {t('sftp.drawerTitle')}
          </h2>
          {sessionTitle && <span className={styles.sessionSub}>{sessionTitle}</span>}
        </div>
        <button
          type="button"
          className={styles.closeBtn}
          onClick={onClose}
          aria-label={t('common.close')}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <line x1="18" y1="6" x2="6" y2="18" />
            <line x1="6" y1="6" x2="18" y2="18" />
          </svg>
        </button>
      </div>

      <div className={styles.navBar}>
        <input
          type="text"
          className={styles.pathInput}
          value={currentPath}
          onChange={(e) => setCurrentPath(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleNavigate()}
          aria-label={t('sftp.remotePath')}
        />
        <Button size="sm" variant="secondary" onClick={handleNavigate}>
          {t('sftp.navigate')}
        </Button>
        <Button size="sm" variant="ghost" onClick={handleNavigate} aria-label={t('sftp.refresh')}>
          ↻
        </Button>
        <Button size="sm" variant="primary" onClick={handleSimulatedUpload}>
          + {t('sftp.upload')}
        </Button>
      </div>

      <div className={styles.contentArea}>
        <div className={styles.fileListArea}>
          {entries.length === 0 ? (
            <div className={styles.emptyNotice}>{t('sftp.emptyDirectory')}</div>
          ) : (
            <table className={styles.table}>
              <thead>
                <tr>
                  <th className={styles.th}>{t('sftp.name')}</th>
                  <th className={styles.th}>{t('sftp.size')}</th>
                  <th className={styles.th}>{t('common.status')}</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) => (
                  <tr key={entry.path} className={styles.tr}>
                    <td className={styles.td}>
                      <span
                        className={`${styles.nameCell} ${entry.isDir ? styles.nameDir : ''}`}
                        onClick={() => handleEntryClick(entry)}
                        role={entry.isDir ? 'button' : undefined}
                      >
                        {entry.isDir ? '📁 ' : '📄 '}
                        {entry.name}
                      </span>
                    </td>
                    <td className={`${styles.td} ${styles.sizeCell}`}>
                      {entry.isDir ? '-' : formatBytes(entry.size)}
                    </td>
                    <td className={styles.td}>
                      {!entry.isDir && (
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() =>
                            onDownload(sessionId, entry.path, `/downloads/${entry.name}`, entry.size)
                          }
                        >
                          ↓
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className={styles.transfersSection}>
          <div className={styles.transfersHeader}>
            <span>{t('sftp.transfersTitle')}</span>
            <Badge variant="default" size="sm">
              {transfers.length}
            </Badge>
          </div>

          <div className={styles.transfersList}>
            {transfers.length === 0 ? (
              <div className={styles.emptyNotice}>{t('sftp.noTransfers')}</div>
            ) : (
              transfers.map((xfer) => {
                const percent =
                  xfer.totalBytes > 0
                    ? Math.min(100, Math.round((xfer.bytesTransferred / xfer.totalBytes) * 100))
                    : 0;
                const isFinished =
                  xfer.state === 'completed' || xfer.state === 'failed' || xfer.state === 'cancelled';

                return (
                  <div key={xfer.transferId} className={styles.transferItem}>
                    <div className={styles.transferMetaRow}>
                      <span className={styles.transferFileName}>
                        {xfer.isUpload ? '↑' : '↓'} {xfer.localFileName}
                      </span>
                      <div className={styles.transferActions}>
                        {xfer.resumable && (
                          <Badge variant="warning" size="sm">
                            {t('sftp.resumable')}
                          </Badge>
                        )}
                        {getStatusBadge(xfer.state)}
                      </div>
                    </div>

                    <div className={styles.progressBarContainer}>
                      <div
                        ref={(node) => {
                          if (node) {
                            node.style.width = `${percent}%`;
                          }
                        }}
                        className={styles.progressBarFill}
                      />
                    </div>

                    <div className={styles.transferStatsRow}>
                      <span>
                        {formatBytes(xfer.bytesTransferred)} / {formatBytes(xfer.totalBytes)} ({percent}%)
                      </span>
                      <div className={styles.transferActions}>
                        {!isFinished && (
                          <>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => onPauseResume(xfer.transferId)}
                            >
                              {xfer.state === 'paused' ? t('sftp.resume') : t('sftp.pause')}
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => onCancel(xfer.transferId)}
                            >
                              ✕
                            </Button>
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </aside>
  );
};
