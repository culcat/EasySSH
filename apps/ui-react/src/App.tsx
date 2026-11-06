import React, { useState } from 'react';
import clsx from 'clsx';
import { useCoreState } from './hooks/useCoreState';
import { useI18n, I18nProvider } from './i18n';
import { HostSidebar } from './features/hosts/HostSidebar';
import { TerminalWorkspace } from './features/terminal/TerminalWorkspace';
import { HostKeyDialog } from './features/security/HostKeyDialog';
import { VaultModal } from './features/vault/VaultModal';
import { SshConfigImportModal } from './features/hosts/SshConfigImportModal';
import { SftpDrawer } from './features/sftp/SftpDrawer';
import { Button, Badge } from './ui';
import styles from './App.module.css';

const AppContent: React.FC = () => {
  const { locale, setLocale, t } = useI18n();
  const {
    state,
    activeSession,
    activeSftpEntries,
    unlockVault,
    lockVault,
    connectHost,
    disconnectSession,
    selectSession,
    sendTerminalInput,
    confirmHostKey,
    importSshConfig,
    sftpListDir,
    sftpUpload,
    sftpDownload,
    sftpPauseResume,
    sftpCancel,
  } = useCoreState();

  const [isVaultModalOpen, setIsVaultModalOpen] = useState(false);
  const [isSshConfigModalOpen, setIsSshConfigModalOpen] = useState(false);
  const [isSftpDrawerOpen, setIsSftpDrawerOpen] = useState(false);

  return (
    <div className={styles.appLayout}>
      <header className={styles.topBar}>
        <div className={styles.brand}>
          <svg
            className={styles.brandIcon}
            width="22"
            height="22"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2.5"
          >
            <polyline points="4 17 10 11 4 5" />
            <line x1="12" y1="19" x2="20" y2="19" />
          </svg>
          <span>EasySSH</span>
        </div>

        <div className={styles.topActions}>
          <div className={styles.langToggle}>
            <button
              type="button"
              className={clsx(styles.langBtn, locale === 'en' && styles.langBtnActive)}
              onClick={() => setLocale('en')}
            >
              EN
            </button>
            <button
              type="button"
              className={clsx(styles.langBtn, locale === 'ru' && styles.langBtnActive)}
              onClick={() => setLocale('ru')}
            >
              RU
            </button>
          </div>

          <Button
            size="sm"
            variant="secondary"
            onClick={() => setIsSshConfigModalOpen(true)}
          >
            {t('hosts.importSshConfigBtn')}
          </Button>

          <Button
            size="sm"
            variant={isSftpDrawerOpen ? 'primary' : 'secondary'}
            onClick={() => setIsSftpDrawerOpen((prev) => !prev)}
            disabled={!activeSession}
          >
            📁 {t('terminal.openSftp')}
          </Button>

          <Badge
            variant={state.vault.isUnlocked ? 'success' : 'warning'}
            size="md"
            withDot
          >
            {state.vault.isUnlocked ? t('vault.statusUnlocked') : t('vault.statusLocked')}
          </Badge>

          {state.vault.isUnlocked ? (
            <Button size="sm" variant="secondary" onClick={lockVault}>
              {t('vault.lockButton')}
            </Button>
          ) : (
            <Button size="sm" variant="primary" onClick={() => setIsVaultModalOpen(true)}>
              {t('vault.unlockTitle')}
            </Button>
          )}
        </div>
      </header>

      <div className={styles.mainContent}>
        <HostSidebar
          hosts={state.hosts}
          onConnect={connectHost}
          onImportSshConfig={() => setIsSshConfigModalOpen(true)}
        />
        <TerminalWorkspace
          sessions={state.activeSessions}
          selectedSessionId={state.selectedSessionId}
          onSelectSession={selectSession}
          onCloseSession={disconnectSession}
          onTerminalInput={sendTerminalInput}
        />
      </div>

      <HostKeyDialog
        verification={state.pendingHostKeyVerification}
        onConfirm={(accepted, remember) => {
          if (state.pendingHostKeyVerification) {
            confirmHostKey(
              state.pendingHostKeyVerification.hostId,
              accepted,
              remember
            );
          }
        }}
      />

      <VaultModal
        isOpen={isVaultModalOpen}
        onClose={() => setIsVaultModalOpen(false)}
        onUnlock={unlockVault}
      />

      <SshConfigImportModal
        isOpen={isSshConfigModalOpen}
        onClose={() => setIsSshConfigModalOpen(false)}
        onImport={importSshConfig}
      />

      <SftpDrawer
        isOpen={isSftpDrawerOpen}
        onClose={() => setIsSftpDrawerOpen(false)}
        sessionId={activeSession?.sessionId}
        sessionTitle={activeSession?.title}
        entries={activeSftpEntries?.entries ?? []}
        transfers={state.sftpTransfers}
        onListDir={sftpListDir}
        onUpload={sftpUpload}
        onDownload={sftpDownload}
        onPauseResume={sftpPauseResume}
        onCancel={sftpCancel}
      />
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <I18nProvider defaultLocale="en">
      <AppContent />
    </I18nProvider>
  );
};

export default App;
