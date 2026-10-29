import { useEffect, useMemo, useState } from 'react'

import { I18nContext, createTranslator, detectLang, storeLang } from './i18n.js'

// I18nProvider は表示言語と翻訳関数をアプリ全体に配ります。
// 言語の変更は localStorage に保存し、<html lang> にも反映します。
export function I18nProvider({ children }) {
  const [lang, setLang] = useState(detectLang)

  useEffect(() => {
    document.documentElement.lang = lang
  }, [lang])

  const value = useMemo(() => {
    const { t, tm, formatDate } = createTranslator(lang)
    return {
      lang,
      t,
      tm,
      formatDate,
      setLang: (next) => {
        storeLang(next)
        setLang(next)
      },
    }
  }, [lang])

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}
