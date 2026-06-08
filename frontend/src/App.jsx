import { useState, useCallback, useRef } from 'react'
import { RadarChart, Radar, PolarGrid, PolarAngleAxis, ResponsiveContainer, Tooltip } from 'recharts'
import { ScoreRing } from './components/ScoreRing'
import { HeaderCard } from './components/HeaderCard'
import { HistorySidebar } from './components/HistorySidebar'
import { CORSScanTab } from './components/CORSScanTab'
import { JWToolTab } from './components/JWToolTab'
import { SSLCheckTab } from './components/SSLCheckTab'
import { CookieAuditTab } from './components/CookieAuditTab'

const TABS = [
  { id: 'headers', label: '🛡 Headers',  desc: 'セキュリティヘッダー診断' },
  { id: 'cors',    label: '🌐 CORS',     desc: 'CORSミスコンフィグ検出' },
  { id: 'jwt',     label: '🔑 JWT',      desc: 'JWTトークン解析' },
  { id: 'ssl',     label: '🔒 SSL/TLS',  desc: 'TLS/SSL設定評価' },
  { id: 'cookie',  label: '🍪 Cookies',  desc: 'Cookieセキュリティ診断' },
]

const QUICK_TARGETS = ['https://example.com', 'https://github.com', 'https://google.com']

function ScanIcon({ spinning }) {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
      style={{ animation: spinning ? 'spin 1s linear infinite' : 'none' }}>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      <path d="M12 2a10 10 0 1 0 10 10" strokeLinecap="round" />
      <path d="M12 6v6l4 2" strokeLinecap="round" />
    </svg>
  )
}

function MetaBadge({ label, value, accent }) {
  return (
    <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border"
      style={{ background: 'var(--bg-card)', borderColor: 'var(--border)' }}>
      <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{label}</span>
      <span className="font-mono text-xs font-bold" style={{ color: accent ?? 'var(--accent)' }}>{value}</span>
    </div>
  )
}

function HeadersTab() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [refreshTrigger, setRefreshTrigger] = useState(0)

  const analyze = useCallback(async (targetUrl) => {
    const u = (targetUrl ?? url).trim()
    if (!u) return
    setLoading(true); setError(''); setResult(null)
    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: u }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error ?? 'Unknown error')
      setResult(data)
      setRefreshTrigger(n => n + 1)
    } catch (e) { setError(e.message) }
    finally { setLoading(false) }
  }, [url])

  const HEADER_SHORT = {
    'Strict-Transport-Security': 'HSTS',
    'Content-Security-Policy':   'CSP',
    'X-Frame-Options':           'X-Frame',
    'X-Content-Type-Options':    'X-CTO',
    'Referrer-Policy':           'Referrer',
    'Permissions-Policy':        'Permissions',
    'X-XSS-Protection':          'X-XSS',
    'Cache-Control':             'Cache',
  }

  const radarData = result?.headers?.map(h => ({
    subject: HEADER_SHORT[h.name] ?? h.name,
    score: h.max_score > 0 ? Math.round((h.score / h.max_score) * 100) : 0,
    fullMark: 100,
  })) ?? []

  const goodCount = result?.headers?.filter(h => h.status === 'good').length ?? 0
  const warnCount = result?.headers?.filter(h => h.status === 'warning').length ?? 0
  const missingCount = result?.headers?.filter(h => h.status === 'missing').length ?? 0

  return (
    <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
      <aside className="lg:col-span-1">
        <HistorySidebar onSelect={(u) => { setUrl(u); analyze(u) }} refreshTrigger={refreshTrigger} />
      </aside>
      <main className="lg:col-span-3 flex flex-col gap-6">
        {/* Search bar */}
        <div>
          <div className="rounded-xl border p-1 flex items-center gap-2 transition-all duration-300"
            style={{ borderColor: loading ? 'var(--accent)' : 'var(--border)', background: 'var(--bg-card)', boxShadow: loading ? '0 0 24px rgba(0,229,255,0.15)' : 'none' }}>
            <input value={url} onChange={e => setUrl(e.target.value)} onKeyDown={e => e.key === 'Enter' && analyze()}
              placeholder="https://example.com"
              className="flex-1 bg-transparent px-4 py-3 text-sm outline-none font-mono"
              style={{ color: 'var(--text)' }} />
            <button onClick={() => analyze()} disabled={loading || !url.trim()}
              className="flex items-center gap-2 px-5 py-3 rounded-lg font-sans font-bold text-sm transition-all duration-200 disabled:opacity-40"
              style={{ background: 'var(--accent)', color: '#000' }}>
              <ScanIcon spinning={loading} />
              {loading ? 'スキャン中...' : '診断'}
            </button>
          </div>
          <div className="flex flex-wrap gap-2 mt-3">
            {QUICK_TARGETS.map(t => (
              <button key={t} onClick={() => { setUrl(t); analyze(t) }}
                className="font-mono text-xs px-3 py-1 rounded-full border transition-all duration-150"
                style={{ borderColor: 'var(--border)', color: 'var(--text-muted)', background: 'transparent' }}
                onMouseEnter={e => { e.target.style.borderColor = 'var(--accent)'; e.target.style.color = 'var(--accent)' }}
                onMouseLeave={e => { e.target.style.borderColor = 'var(--border)'; e.target.style.color = 'var(--text-muted)' }}>
                {t.replace('https://', '')}
              </button>
            ))}
          </div>
        </div>

        {error && <div className="p-4 rounded-xl border font-mono text-sm" style={{ borderColor: 'var(--red)33', background: 'var(--red-dim)', color: 'var(--red)' }}>✗ {error}</div>}

        {result && (
          <div className="flex flex-col gap-6 animate-fade-up">
            <div className="rounded-xl border p-6" style={{ background: 'var(--bg-card)', borderColor: 'var(--border)' }}>
              <div className="flex flex-col md:flex-row items-center gap-6">
                <ScoreRing score={result.total_score} max={result.max_score} grade={result.grade} />
                <div className="flex-1 w-full">
                  <div className="font-mono text-xs mb-1" style={{ color: 'var(--text-muted)' }}>スキャン対象</div>
                  <div className="font-sans font-bold text-base mb-4 break-all leading-relaxed" style={{ color: 'var(--accent)' }}>{result.final_url}</div>
                  <div className="flex flex-wrap gap-2">
                    <MetaBadge label="✓ 良好" value={goodCount} accent="var(--green)" />
                    <MetaBadge label="⚠ 要改善" value={warnCount} accent="var(--yellow)" />
                    <MetaBadge label="✗ 未設定" value={missingCount} accent="var(--red)" />
                    <MetaBadge label="応答時間" value={`${result.response_time_ms}ms`} accent="var(--text-muted)" />
                    <MetaBadge label="TLS" value={result.tls_enabled ? '有効 🔒' : '無効'} accent={result.tls_enabled ? 'var(--green)' : 'var(--red)'} />
                  </div>
                </div>
                <div className="w-56 h-56 shrink-0">
                  <ResponsiveContainer width="100%" height="100%">
                    <RadarChart data={radarData} outerRadius="60%" margin={{ top: 16, right: 24, bottom: 16, left: 24 }}>
                      <PolarGrid stroke="var(--border)" />
                      <PolarAngleAxis dataKey="subject" tick={{ fontSize: 9, fill: 'var(--text-muted)', fontFamily: 'Space Mono' }} />
                      <Radar dataKey="score" stroke="var(--accent)" fill="var(--accent)" fillOpacity={0.15} strokeWidth={1.5} />
                      <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 11, fontFamily: 'Space Mono' }} labelStyle={{ color: 'var(--text)' }} itemStyle={{ color: 'var(--accent)' }} />
                    </RadarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
            <div>
              <h2 className="font-mono text-xs mb-3" style={{ color: 'var(--text-muted)' }}>── ヘッダー詳細（クリックで展開）</h2>
              <div className="flex flex-col gap-3">
                {result.headers.map((h, i) => <HeaderCard key={h.name} header={h} index={i} />)}
              </div>
            </div>
          </div>
        )}

        {!result && !loading && !error && (
          <div className="flex flex-col items-center justify-center py-24 gap-4" style={{ color: 'var(--text-muted)' }}>
            <div className="text-6xl opacity-20">🛡</div>
            <p className="font-mono text-sm">URLを入力してスキャンを開始</p>
          </div>
        )}
      </main>
    </div>
  )
}

export default function App() {
  const [activeTab, setActiveTab] = useState('headers')

  return (
    <div className="app-shell min-h-screen">
      {/* Header */}
      <header className="border-b px-6 py-4" style={{ borderColor: 'var(--border)', background: 'var(--bg-card)' }}>
        <div className="max-w-6xl mx-auto flex items-center gap-4">
          <div className="w-8 h-8 rounded-lg flex items-center justify-center"
            style={{ background: 'var(--accent-dim)', border: '1px solid var(--accent)33' }}>
            <span style={{ color: 'var(--accent)' }}>🛡</span>
          </div>
          <div>
            <h1 className="font-sans font-extrabold text-lg tracking-tight" style={{ color: 'var(--text)' }}>ShieldScan</h1>
            <p className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>Web Security Analyzer</p>
          </div>
        </div>
      </header>

      {/* Tab bar */}
      <div className="border-b sticky top-0 z-10" style={{ borderColor: 'var(--border)', background: 'var(--bg-card)88', backdropFilter: 'blur(12px)' }}>
        <div className="max-w-6xl mx-auto px-4">
          <div className="flex gap-1 overflow-x-auto">
            {TABS.map(tab => (
              <button key={tab.id} onClick={() => setActiveTab(tab.id)}
                className="flex items-center gap-2 px-4 py-3 font-sans text-sm font-bold whitespace-nowrap border-b-2 transition-all duration-200"
                style={{
                  borderColor: activeTab === tab.id ? 'var(--accent)' : 'transparent',
                  color: activeTab === tab.id ? 'var(--accent)' : 'var(--text-muted)',
                  background: 'transparent',
                }}>
                {tab.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-6xl mx-auto px-4 py-8">
        {activeTab === 'headers' && <HeadersTab />}
        {activeTab === 'cors' && (
          <div className="max-w-3xl">
            <div className="mb-4">
              <h2 className="font-sans font-bold text-lg" style={{ color: 'var(--text)' }}>CORScan</h2>
              <p className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>CORSミスコンフィグ検出</p>
            </div>
            <CORSScanTab />
          </div>
        )}
        {activeTab === 'jwt' && (
          <div className="max-w-3xl">
            <div className="mb-4">
              <h2 className="font-sans font-bold text-lg" style={{ color: 'var(--text)' }}>JWTool</h2>
              <p className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>JWT解析・脆弱性チェック</p>
            </div>
            <JWToolTab />
          </div>
        )}
        {activeTab === 'ssl' && (
          <div className="max-w-3xl">
            <div className="mb-4">
              <h2 className="font-sans font-bold text-lg" style={{ color: 'var(--text)' }}>SSLCheck</h2>
              <p className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>TLS/SSL設定評価</p>
            </div>
            <SSLCheckTab />
          </div>
        )}
        {activeTab === 'cookie' && (
          <div className="max-w-3xl">
            <div className="mb-4">
              <h2 className="font-sans font-bold text-lg" style={{ color: 'var(--text)' }}>CookieAudit</h2>
              <p className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>Cookieセキュリティ診断</p>
            </div>
            <CookieAuditTab />
          </div>
        )}
      </div>
    </div>
  )
}
