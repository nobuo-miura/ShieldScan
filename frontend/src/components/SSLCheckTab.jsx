import { useState } from 'react'

import { useI18n } from '../i18n/i18n'
import { errorMessage, postJSON } from '../api'

const severityColor = { critical: 'var(--red)', high: 'var(--yellow)', warning: '#ff9944', info: 'var(--accent)' }
const severityBg = { critical: 'var(--red-dim)', high: 'var(--yellow-dim)', warning: 'rgba(255,153,68,0.1)', info: 'var(--accent-dim)' }

export function SSLCheckTab() {
  const { t, tm, formatDate } = useI18n()
  const [host, setHost] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  const check = async () => {
    if (!host.trim()) return
    setLoading(true); setError(''); setResult(null)
    try {
      const data = await postJSON('/api/ssl', { host: host.trim(), port: '443' })
      setResult(data)
    } catch (e) { setError(errorMessage(e)) }
    finally { setLoading(false) }
  }

  const cert = result?.cert
  const daysLeft = cert?.days_left ?? 0
  const daysColor = daysLeft < 14 ? 'var(--red)' : daysLeft < 30 ? 'var(--yellow)' : 'var(--green)'

  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
        {t('ui.ssl.intro')}
      </p>

      <div className="flex gap-2">
        <input value={host} onChange={e => setHost(e.target.value)} onKeyDown={e => e.key === 'Enter' && check()}
          placeholder="example.com"
          className="flex-1 bg-transparent px-4 py-3 text-sm outline-none font-mono rounded-lg border"
          style={{ color: 'var(--text)', borderColor: 'var(--border)', background: 'var(--bg-card)' }} />
        <button onClick={check} disabled={loading || !host.trim()}
          className="px-5 py-3 rounded-lg font-sans font-bold text-sm disabled:opacity-40"
          style={{ background: 'var(--accent)', color: '#000' }}>
          {loading ? t('ui.action.checking') : t('ui.action.check')}
        </button>
      </div>

      {error && <div className="p-3 rounded-lg font-mono text-sm" style={{ background: 'var(--red-dim)', color: 'var(--red)' }}>✗ {tm(error)}</div>}

      {result && (
        <div className="flex flex-col gap-4">
          {result.connect_error ? (
            <div className="p-4 rounded-xl border" style={{ background: 'var(--red-dim)', borderColor: 'var(--red)44', color: 'var(--red)' }}>
              {tm(result.connect_error)}
            </div>
          ) : (
            <>
              {/* Overview cards */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                <div className="p-3 rounded-lg border" style={{ background: 'var(--bg-card)', borderColor: 'var(--border)' }}>
                  <div className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>{t('ui.ssl.tls_version')}</div>
                  <div className="font-sans font-bold text-sm mt-1" style={{ color: result.tls_version?.includes('1.3') ? 'var(--green)' : 'var(--yellow)' }}>
                    {result.tls_version}
                  </div>
                </div>
                <div className="p-3 rounded-lg border col-span-2" style={{ background: 'var(--bg-card)', borderColor: 'var(--border)' }}>
                  <div className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>{t('ui.ssl.cipher_suite')}</div>
                  <div className="font-mono text-xs mt-1 break-all" style={{ color: 'var(--text)' }}>{result.cipher_suite}</div>
                </div>
                <div className="p-3 rounded-lg border" style={{ background: 'var(--bg-card)', borderColor: 'var(--border)' }}>
                  <div className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>{t('ui.meta.response_time')}</div>
                  <div className="font-sans font-bold text-sm mt-1" style={{ color: 'var(--accent)' }}>{result.response_time_ms}ms</div>
                </div>
              </div>

              {/* Cert info */}
              {cert && (
                <div className="p-4 rounded-xl border" style={{ background: 'var(--bg-card)', borderColor: 'var(--border)' }}>
                  <div className="font-mono text-xs mb-3" style={{ color: 'var(--text-muted)' }}>{t('ui.ssl.cert_heading')}</div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                    <div><span style={{ color: 'var(--text-muted)' }}>{t('ui.ssl.subject')}: </span><span className="font-mono" style={{ color: 'var(--text)' }}>{cert.subject}</span></div>
                    <div><span style={{ color: 'var(--text-muted)' }}>{t('ui.ssl.issuer')}: </span><span className="font-mono" style={{ color: 'var(--text)' }}>{cert.issuer}</span></div>
                    <div><span style={{ color: 'var(--text-muted)' }}>{t('ui.ssl.valid_until')}: </span><span className="font-mono" style={{ color: daysColor }}>{formatDate(cert.not_after)} {t('ui.ssl.days_left', { count: daysLeft })}</span></div>
                    <div><span style={{ color: 'var(--text-muted)' }}>{t('ui.ssl.self_signed')}: </span><span style={{ color: cert.self_signed ? 'var(--red)' : 'var(--green)' }}>{cert.self_signed ? `⚠ ${t('ui.value.yes')}` : `✓ ${t('ui.value.no')}`}</span></div>
                    {cert.sans?.length > 0 && (
                      <div className="col-span-2">
                        <span style={{ color: 'var(--text-muted)' }}>{t('ui.ssl.sans')}: </span>
                        <span className="font-mono text-xs" style={{ color: 'var(--text)' }}>{cert.sans.slice(0, 6).join(', ')}{cert.sans.length > 6 ? ` ... +${cert.sans.length - 6}` : ''}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Findings */}
              <div>
                <div className="font-mono text-xs mb-2" style={{ color: 'var(--text-muted)' }}>{t('ui.findings.heading')}</div>
                <div className="flex flex-col gap-2">
                  {result.findings.map((f, i) => (
                    <div key={i} className="p-3 rounded-lg border" style={{ background: severityBg[f.severity], borderColor: severityColor[f.severity] + '44' }}>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-mono text-xs font-bold px-2 py-0.5 rounded" style={{ background: severityColor[f.severity] + '22', color: severityColor[f.severity] }}>
                          {f.severity.toUpperCase()}
                        </span>
                        <span className="font-sans font-bold text-sm" style={{ color: 'var(--text)' }}>{tm(f.title)}</span>
                      </div>
                      <p className="text-xs" style={{ color: 'var(--text-muted)', lineHeight: 1.6 }}>{tm(f.description)}</p>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}
