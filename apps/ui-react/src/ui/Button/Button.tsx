import React from 'react';
import clsx from 'clsx';
import styles from './Button.module.css';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  readonly variant?: 'primary' | 'secondary' | 'danger' | 'ghost';
  readonly size?: 'sm' | 'md' | 'lg';
  readonly isLoading?: boolean;
  readonly icon?: React.ReactNode;
}

export const Button: React.FC<ButtonProps> = ({
  variant = 'secondary',
  size = 'md',
  isLoading = false,
  icon,
  children,
  className,
  disabled,
  ...props
}) => {
  return (
    <button
      className={clsx(
        styles.button,
        styles[`variant-${variant}`],
        styles[`size-${size}`],
        className
      )}
      disabled={disabled || isLoading}
      {...props}
    >
      {isLoading ? (
        <span className={styles.spinner} aria-hidden="true" />
      ) : (
        icon && <span aria-hidden="true">{icon}</span>
      )}
      {children}
    </button>
  );
};
