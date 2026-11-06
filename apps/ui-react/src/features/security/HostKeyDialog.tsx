import React, { useState } from 'react';
import type { HostKeyVerification } from '../../types/proto';
import { useI18n } from '../../i18n';
import { Modal, Button } from '../../ui';
import styles from './HostKeyDialog.module.css';

export interface HostKeyDialogProps {
  readonly verification: HostKeyVerification | undefined;
  readonly onConfirm: (accepted: boolean, remember: boolean) => void;
}

export const HostKeyDialog: React.FC<HostKeyDialogProps> = ({
  verification,
  onConfirm,
}) => {
  const { t } = useI18n();
  const [remember, setRemember] = useState(true);

  if (!verification) return null;

  const isMismatch = verification.status === 'mismatch';

  const modalTitle = isMismatch
    ? t('security.hostKeyMismatchTitle')
    : t('security.hostKeyVerificationTitle');

  return (
    <Modal
      isOpen={Boolean(verification)}
      onClose={() => onConfirm(false, false)}
      title={modalTitle}
      size="md"
      closeOnBackdropClick={false}
      footer={
        <>
          <Button
            variant="danger"
            onClick={() => onConfirm(false, false)}
          >
            {t('security.rejectConnection')}
          </Button>
          <Button
            variant={isMismatch ? 'secondary' : 'primary'}
            onClick={() => onConfirm(true, remember)}
          >
            {t('security.acceptAndSave')}
          </Button>
        </>
      }
    >
      <div className={styles.dialogContent}>
        {isMismatch ? (
          <div className={styles.warningBanner} role="alert">
            <svg
              className={styles.warningIcon}
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
              <line x1="12" y1="9" x2="12" y2="13" />
              <line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
            <div>
              <strong>{t('security.dangerousMismatchAlert')}</strong>
            </div>
          </div>
        ) : (
          <p className={styles.tofuNotice}>{t('security.tofuNotice')}</p>
        )}

        <div className={styles.detailsCard}>
          <div className={styles.detailRow}>
            <span className={styles.detailLabel}>{t('hosts.hostname')}</span>
            <span>
              {verification.hostname}:{verification.port}
            </span>
          </div>

          <div className={styles.detailRow}>
            <span className={styles.detailLabel}>{t('security.keyType')}</span>
            <span>{verification.keyType}</span>
          </div>

          {isMismatch && verification.previousFingerprintSha256 && (
            <div className={styles.detailRow}>
              <span className={styles.detailLabel}>{t('security.previousFingerprint')}</span>
              <code className={styles.fingerprintCode}>
                {verification.previousFingerprintSha256}
              </code>
            </div>
          )}

          <div className={styles.detailRow}>
            <span className={styles.detailLabel}>
              {isMismatch ? t('security.newFingerprint') : t('security.fingerprintSha256')}
            </span>
            <code className={`${styles.fingerprintCode} ${isMismatch ? styles.mismatchCode : ''}`}>
              {verification.fingerprintSha256}
            </code>
          </div>
        </div>

        <label className={styles.checkboxContainer}>
          <input
            type="checkbox"
            className={styles.checkboxInput}
            checked={remember}
            onChange={(e) => setRemember(e.target.checked)}
          />
          <span>{t('security.rememberKeyNotice')}</span>
        </label>
      </div>
    </Modal>
  );
};
