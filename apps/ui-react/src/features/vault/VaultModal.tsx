import React, { useState, useRef, useEffect } from 'react';
import { useI18n } from '../../i18n';
import { Modal, Input, Button } from '../../ui';
import styles from './VaultModal.module.css';

export interface VaultModalProps {
  readonly isOpen: boolean;
  readonly onClose: () => void;
  readonly onUnlock: (passphrase: string) => void;
}

export const VaultModal: React.FC<VaultModalProps> = ({
  isOpen,
  onClose,
  onUnlock,
}) => {
  const { t } = useI18n();
  const [passphrase, setPassphrase] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setPassphrase('');
      // Delay focus slightly to ensure modal is mounted
      setTimeout(() => inputRef.current?.focus(), 50);
    } else {
      // Zero out passphrase immediately upon modal closure
      setPassphrase('');
    }
  }, [isOpen]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const secretToDispatch = passphrase;

    // CRITICAL SECURITY ACTION:
    // Immediately clear React state before or synchronously with dispatch
    setPassphrase('');

    if (secretToDispatch.trim().length > 0) {
      onUnlock(secretToDispatch);
      onClose();
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={() => {
        setPassphrase('');
        onClose();
      }}
      title={t('vault.unlockTitle')}
      size="sm"
      footer={
        <>
          <Button
            variant="ghost"
            onClick={() => {
              setPassphrase('');
              onClose();
            }}
          >
            {t('common.cancel')}
          </Button>
          <Button
            variant="primary"
            onClick={handleSubmit}
            disabled={passphrase.trim().length === 0}
          >
            {t('vault.unlockButton')}
          </Button>
        </>
      }
    >
      <form onSubmit={handleSubmit} className={styles.content}>
        <p className={styles.notice}>{t('vault.unlockVaultToAccessKeys')}</p>

        <Input
          ref={inputRef}
          type="password"
          label={t('vault.passphrasePlaceholder')}
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          autoComplete="current-password"
        />

        <div className={styles.securityNote}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
          <span>{t('vault.passphraseZeroedNotice')}</span>
        </div>
      </form>
    </Modal>
  );
};
