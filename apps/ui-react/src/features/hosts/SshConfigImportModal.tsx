import React, { useState, useMemo } from 'react';
import { useI18n } from '../../i18n';
import { Modal, Button, Badge } from '../../ui';
import styles from './SshConfigImportModal.module.css';

export interface SshConfigImportModalProps {
  readonly isOpen: boolean;
  readonly onClose: () => void;
  readonly onImport: (configText: string) => void;
}

interface PreviewHost {
  readonly alias: string;
  readonly hostName: string;
  readonly user: string;
  readonly port: number;
  readonly identityFile?: string;
  readonly proxyJump?: string;
}

export const SshConfigImportModal: React.FC<SshConfigImportModalProps> = ({
  isOpen,
  onClose,
  onImport,
}) => {
  const { t } = useI18n();
  const [configText, setConfigText] = useState('');

  // Live parsing for preview and security analysis
  const { parsedHosts, hasProxyCommand } = useMemo(() => {
    const lines = configText.split(/\r?\n/);
    const hosts: PreviewHost[] = [];
    let detectedProxyCommand = false;

    let currentHost: {
      alias: string;
      hostName?: string;
      user?: string;
      port?: number;
      identityFile?: string;
      proxyJump?: string;
    } | null = null;

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;

      const match = line.match(/^([A-Za-z0-9_]+)[=\s]+(.*)$/);
      if (!match) continue;

      const key = match[1]?.toLowerCase();
      const value = match[2]?.trim() ?? '';

      if (key === 'host') {
        const aliases = value.split(/\s+/).filter(Boolean);
        for (const alias of aliases) {
          if (alias === '*') continue;
          currentHost = { alias };
          hosts.push({
            alias: currentHost.alias,
            hostName: currentHost.alias,
            user: 'root',
            port: 22,
          });
        }
      } else if (currentHost && hosts.length > 0) {
        const target = hosts[hosts.length - 1];
        if (!target) continue;

        if (key === 'hostname') {
          hosts[hosts.length - 1] = { ...target, hostName: value };
        } else if (key === 'user') {
          hosts[hosts.length - 1] = { ...target, user: value };
        } else if (key === 'port') {
          const p = parseInt(value, 10);
          if (!isNaN(p) && p > 0) {
            hosts[hosts.length - 1] = { ...target, port: p };
          }
        } else if (key === 'identityfile') {
          hosts[hosts.length - 1] = { ...target, identityFile: value };
        } else if (key === 'proxyjump') {
          hosts[hosts.length - 1] = { ...target, proxyJump: value };
        } else if (key === 'proxycommand') {
          detectedProxyCommand = true;
        }
      } else if (key === 'proxycommand') {
        detectedProxyCommand = true;
      }
    }

    return {
      parsedHosts: hosts,
      hasProxyCommand: detectedProxyCommand,
    };
  }, [configText]);

  const handleImportSubmit = () => {
    if (parsedHosts.length === 0) return;
    onImport(configText);
    setConfigText('');
    onClose();
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={() => {
        setConfigText('');
        onClose();
      }}
      title={t('sshConfig.importTitle')}
      size="lg"
      footer={
        <>
          <Button
            variant="ghost"
            onClick={() => {
              setConfigText('');
              onClose();
            }}
          >
            {t('common.cancel')}
          </Button>
          <Button
            variant="primary"
            onClick={handleImportSubmit}
            disabled={parsedHosts.length === 0}
          >
            {t('sshConfig.importButton')}
          </Button>
        </>
      }
    >
      <div className={styles.container}>
        <p className={styles.description}>{t('sshConfig.importDescription')}</p>

        <textarea
          className={styles.textarea}
          placeholder={t('sshConfig.configPlaceholder')}
          value={configText}
          onChange={(e) => setConfigText(e.target.value)}
          spellCheck={false}
          aria-label={t('sshConfig.importTitle')}
        />

        {hasProxyCommand && (
          <div className={styles.securityAlert} role="alert">
            <svg
              className={styles.securityIcon}
              width="20"
              height="20"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
              <line x1="12" y1="9" x2="12" y2="13" />
              <line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
            <div>{t('sshConfig.securityWarningProxyCommand')}</div>
          </div>
        )}

        <div className={styles.previewSection}>
          <div className={styles.previewHeader}>
            <h3 className={styles.previewTitle}>{t('sshConfig.previewTitle')}</h3>
            {parsedHosts.length > 0 && (
              <Badge variant="info" size="sm">
                {t('sshConfig.importCountBadge', { count: parsedHosts.length })}
              </Badge>
            )}
          </div>

          {parsedHosts.length === 0 ? (
            <div className={styles.noPreview}>{t('sshConfig.noHostsParsed')}</div>
          ) : (
            <ul className={styles.previewList}>
              {parsedHosts.map((host, idx) => (
                <li key={`${host.alias}-${idx}`} className={styles.previewItem}>
                  <div className={styles.previewItemHeader}>
                    <span className={styles.previewAlias}>{host.alias}</span>
                    <Badge variant="default" size="sm">
                      {host.user}@{host.hostName}:{host.port}
                    </Badge>
                  </div>
                  <div className={styles.previewMeta}>
                    {host.identityFile && (
                      <Badge variant="warning" size="sm">
                        {t('sshConfig.identityFile')}: {host.identityFile}
                      </Badge>
                    )}
                    {host.proxyJump && (
                      <Badge variant="info" size="sm">
                        {t('sshConfig.proxyJump')}: {host.proxyJump}
                      </Badge>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </Modal>
  );
};
