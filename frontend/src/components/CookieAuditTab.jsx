import { useState } from 'react'

import { useI18n } from '../i18n/i18n'
import { errorMessage, postJSON } from '../api'

const severityColor = { critical: 'var(--red)', high: 'var(--yellow)', warning: '#ff9944', info: 'var(--accent)' }

function FlagBadge({ ok, label }) {
  return (
    <span className="font-mono text-xs px-2 py-0.5 rounded-full"
      style={{ background: ok ? 'var(--green-dim)' : 'var(--red-dim)', color: ok ? 'var(--green)' : 'var(--red)' }}>
      {ok ? '✓' : '✗'} {label}
    </span>
  )
}

function CookieRow({ cookie, index }) {
  const { t, tm } = useI18n()
  const [open, setOpen] = useState(false)
  const hasIssues = cookie.issues.length > 0
  const borderColor = hasIssues ? (severityColor[cookie.severity] + '44') : 'var(--border)'
  // SameSite属性が付いていない場合、バックエンドは空文字列を返す。
  const sameSiteSafe = cookie.same_site === 'Strict' || cookie.same_site === 'Lax'
  const sameSiteLabel = cookie.same_site || t('ui.cookie.samesite_unset')

  return (
    <div className="rounded-lg border cursor-pointer transition-all duration-200 animate-slide-in"
      style={{ background: 'var(--bg-card)', borderColor, animationDelay: `${index * 50}ms`, opacity: 0, animationFillMode: 'forwards' }}
      onClick={() => setOpen(!open)}>
      <div className="flex items-center gap-3 p-4 flex-wrap">
        <div className="flex items-center gap-2">
          {cookie.sensitive && (
            <span className="font-mono text-xs px-2 py-0.5 rounded-full" style={{ background: 'var(--yellow-dim)', color: 'var(--yellow)' }}>
              🔑 {t('ui.cookie.sensitive')}
            </span>
          )}
          <span className="font-mono text-sm font-bold" style={{ color: 'var(--text)' }}>{cookie.name}</span>
        </div>
        <div className="flex gap-2 flex-wrap flex-1">
          <FlagBadge ok={cookie.secure} label="Secure" />
          <FlagBadge ok={cookie.http_only} label="HttpOnly" />
          <span className="font-mono text-xs px-2 py-0.5 rounded-full"
            style={{
              background: sameSiteSafe ? 'var(--green-dim)' : 'var(--red-dim)',
              color: sameSiteSafe ? 'var(--green)' : 'var(--red)',
            }}>
            SameSite={sameSiteLabel}
          </span>
        </div>
        {hasIssues && (
          <span className="font-mono text-xs font-bold" style={{ color: severityColor[cookie.severity] }}>
            {t('ui.cookie.issue_count', { count: cookie.issues.length })}
          </span>
        )}
        <span className="text-xs" style={{ color: 'var(--text-muted)', transform: open ? 'rotate(180deg)' : 'none', display: 'inline-block', transition: 'transform 0.2s' }}>▼</span>
      </div>
      {open && hasIssues && (
        <div className="px-4 pb-4 border-t flex flex-col gap-2" style={{ borderColor: 'var(--border)' }}>
          {cookie.issues.map((issue, i) => (
            <div key={i} className="mt-2 p-3 rounded-lg text-xs" style={{ background: 'var(--red-dim)', color: 'var(--red)', lineHeight: 1.6 }}>
              ⚠ {tm(issue)}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export function CookieAuditTab() {
  const { t, tm } = useI18n()
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  const audit = async () => {
    if (!url.trim()) return
    setLoading(true); setError(''); setResult(null)
    try {
      const data = await postJSON('/api/cookies', { url: url.trim() })
      setResult(data)
    } catch (e) { setError(errorMessage(e)) }
    finally { setLoading(false) }
  }

  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
        {t('ui.cookie.intro')}
      </p>

      <div className="flex gap-2">
        <input value={url} onChange={e => setUrl(e.target.value)} onKeyDown={e => e.key === 'Enter' && audit()}
          placeholder="https://example.com"
          className="flex-1 bg-transparent px-4 py-3 text-sm outline-none font-mono rounded-lg border"
          style={{ color: 'var(--text)', borderColor: 'var(--border)', background: 'var(--bg-card)' }} />
        <button onClick={audit} disabled={loading || !url.trim()}
          className="px-5 py-3 rounded-lg font-sans font-bold text-sm disabled:opacity-40"
          style={{ background: 'var(--accent)', color: '#000' }}>
          {loading ? t('ui.action.analyzing') : t('ui.action.analyze')}
        </button>
      </div>

      {error && <div className="p-3 rounded-lg font-mono text-sm" style={{ background: 'var(--red-dim)', color: 'var(--red)' }}>✗ {tm(error)}</div>}

      {result && (
        <div className="flex flex-col gap-3">
          <div className="flex gap-3 flex-wrap">
            <div className="p-3 rounded-lg border" style={{ background: 'var(--bg-card)', borderColor: 'var(--border)' }}>
              <span className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>{t('ui.cookie.total')} </span>
              <span className="font-mono font-bold" style={{ color: 'var(--accent)' }}>{result.total_cookies}</span>
            </div>
            <div className="p-3 rounded-lg border" style={{ background: 'var(--bg-card)', borderColor: result.issue_count > 0 ? 'var(--red)44' : 'var(--green)44' }}>
              <span className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>{t('ui.cookie.with_issues')} </span>
              <span className="font-mono font-bold" style={{ color: result.issue_count > 0 ? 'var(--red)' : 'var(--green)' }}>{result.issue_count}</span>
            </div>
            <div className="p-3 rounded-lg border" style={{ background: 'var(--bg-card)', borderColor: 'var(--border)' }}>
              <span className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>{t('ui.meta.response_time')} </span>
              <span className="font-mono font-bold" style={{ color: 'var(--accent)' }}>{result.response_time_ms}ms</span>
            </div>
          </div>

          {result.cookies.length === 0 ? (
            <div className="p-6 text-center rounded-xl border" style={{ borderColor: 'var(--border)', color: 'var(--text-muted)' }}>
              <div className="text-2xl mb-2">🍪</div>
              <p className="font-mono text-sm">{t('ui.cookie.empty')}</p>
            </div>
          ) : (
            result.cookies.map((c, i) => <CookieRow key={c.name} cookie={c} index={i} />)
          )}
        </div>
      )}
    </div>
  )
}
