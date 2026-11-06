import type { en } from './locales/en';

type WidenStrings<T> = T extends string
  ? string
  : {
      readonly [K in keyof T]: WidenStrings<T[K]>;
    };

export type TranslationSchema = WidenStrings<typeof en>;
export type Locale = 'en' | 'ru';

export type NestedKeyOf<ObjectType extends object> = {
  [Key in keyof ObjectType & (string | number)]: ObjectType[Key] extends object
    ? `${Key}.${NestedKeyOf<ObjectType[Key]>}`
    : `${Key}`;
}[keyof ObjectType & (string | number)];

export type TranslationKey = NestedKeyOf<TranslationSchema>;
