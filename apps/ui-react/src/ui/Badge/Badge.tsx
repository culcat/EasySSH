import React from 'react';
import clsx from 'clsx';
import styles from './Badge.module.css';

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  readonly variant?: 'default' | 'success' | 'warning' | 'danger' | 'info';
  readonly size?: 'sm' | 'md';
  readonly withDot?: boolean;
}

export const Badge: React.FC<BadgeProps> = ({
  variant = 'default',
  size = 'sm',
  withDot = false,
  children,
  className,
  ...props
}) => {
  return (
    <span
      className={clsx(
        styles.badge,
        styles[`variant-${variant}`],
        styles[`size-${size}`],
        className
      )}
      {...props}
    >
      {withDot && <span className={styles.dot} aria-hidden="true" />}
      {children}
    </span>
  );
};
