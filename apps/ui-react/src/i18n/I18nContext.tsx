import React, { createContext, useContext, useState, useCallback, useMemo } from 'react';
import { en } from './locales/en';
import { ru } from './locales/ru';
import type { Locale, TranslationKey, TranslationSchema } from './types';

interface I18nContextType {
  readonly locale: Locale;
  readonly setLocale: (locale: Locale) => void;
  readonly t: (key: TranslationKey, params?: Record<string, string | number>) => string;
}

const translations: Record<Locale, TranslationSchema> = {
  en,
  ru,
};

const I18nContext = createContext<I18nContextType | null>(null);

function resolveKey(obj: Record<string, unknown>, path: string): string | undefined {
  const parts = path.split('.');
  let current: unknown = obj;
  for (const part of parts) {
    if (current && typeof current === 'object' && part in current) {
      current = (current as Record<string, unknown>)[part];
    } else {
      return undefined;
    }
  }
  return typeof current === 'string' ? current : undefined;
}

export interface I18nProviderProps {
  readonly defaultLocale?: Locale;
  readonly children: React.ReactNode;
}

export const I18nProvider: React.FC<I18nProviderProps> = ({
  defaultLocale = 'en',
  children,
}) => {
  const [locale, setLocale] = useState<Locale>(defaultLocale);

  const t = useCallback(
    (key: TranslationKey, params?: Record<string, string | number>): string => {
      const activeDictionary = translations[locale] as unknown as Record<string, unknown>;
      const fallbackDictionary = translations.en as unknown as Record<string, unknown>;

      let text = resolveKey(activeDictionary, key) ?? resolveKey(fallbackDictionary, key) ?? key;

      if (params) {
        for (const [paramKey, paramValue] of Object.entries(params)) {
          text = text.replace(new RegExp(`\\{${paramKey}\\}`, 'g'), String(paramValue));
        }
      }

      return text;
    },
    [locale]
  );

  const value = useMemo(
    () => ({
      locale,
      setLocale,
      t,
    }),
    [locale, t]
  );

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
};

export const useI18n = (): I18nContextType => {
  const context = useContext(I18nContext);
  if (!context) {
    throw new Error('useI18n must be used within an I18nProvider');
  }
  return context;
};
