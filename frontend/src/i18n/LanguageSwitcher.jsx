import { SUPPORTED_LANGS, useI18n } from './i18n.js'

// LanguageSwitcher は表示言語を切り替えるトグルです。
export function LanguageSwitcher() {
  const { lang, setLang, t } = useI18n()

  return (
    <div
      className="flex items-center gap-1 rounded-lg border p-0.5"
      style={{ borderColor: 'var(--border)' }}
      role="group"
      aria-label={t('ui.lang.aria')}
    >
      {SUPPORTED_LANGS.map(option => {
        const active = option.code === lang
        return (
          <button
            key={option.code}
            onClick={() => setLang(option.code)}
            aria-pressed={active}
            title={option.label}
            className="font-mono text-xs px-2 py-1 rounded-md transition-colors duration-150"
            style={{
              background: active ? 'var(--accent-dim)' : 'transparent',
              color: active ? 'var(--accent)' : 'var(--text-muted)',
            }}
          >
            {option.short}
          </button>
        )
      })}
    </div>
  )
}
