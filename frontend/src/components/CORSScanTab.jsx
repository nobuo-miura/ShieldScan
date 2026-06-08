import { useState } from 'react'

const severityConfig = {
  critical: { color: 'var(--red)',    bg: 'var(--red-dim)',    label: 'CRITICAL' },
  high:     { color: 'var(--yellow)', bg: 'var(--yellow-dim)', label: 'HIGH' },
  info:     { color: 'var(--accent)', bg: 'var(--accent-dim)', label: 'INFO' },
}

function TestRow({ test }) {
  const [open, setOpen] = useState(false)

  const statusColor = test.reflected
    ? (test.acac_present ? 'var(--red)' : 'var(--yellow)')
    : 'var(--green)'
  const statusLabel = test.reflected
    ? (test.acac_present ? '🔴 脆弱' : '⚠️ 反射あり')
    : '✅ 安全'

  return (
    <div
      className="rounded-lg border cursor-pointer transition-all duration-200"
      style={{ background: 'var(--bg-card)', borderColor: open ? statusColor + '66' : 'var(--border)' }}
      onClick={() => setOpen(!open)}
    >
      <div className="flex items-center gap-3 p-4">
        <span className="font-mono text-xs font-bold shrink-0" style={{ color: statusColor }}>{statusLabel}</span>
        <span className="font-sans text-sm font-bold flex-1" style={{ color: 'var(--text)' }}>{test.test_name}</span>
        <code className="font-mono text-xs hidden md:block" style={{ color: 'var(--text-muted)' }}>
          {test.origin.replace('https://', '')}
        </code>
        <span className="text-xs" style={{ color: 'var(--text-muted)', transform: open ? 'rotate(180deg)' : 'none', display: 'inline-block', transition: 'transform 0.2s' }}>▼</span>
      </div>
      {open && (
        <div className="px-4 pb-4 border-t" style={{ borderColor: 'var(--border)' }}>
          <code className="block text-xs p-2 rounded mt-3 mb-2 break-all" style={{ background: 'var(--bg)', color: 'var(--accent)', fontFamily: '"Space Mono", monospace' }}>
            Origin: {test.origin}
          </code>
          {test.detail && (
            <code className="block text-xs p-2 rounded mb-3 break-all" style={{ background: 'var(--bg)', color: 'var(--text-muted)', fontFamily: '"Space Mono", monospace' }}>
              {test.detail}
            </code>
          )}
          <p className="text-sm" style={{ color: 'var(--text-muted)', lineHeight: 1.6 }}>{test.description}</p>
        </div>
      )}
    </div>
  )
}

export function CORSScanTab() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  const scan = async () => {
    if (!url.trim()) return
    setLoading(true); setError(''); setResult(null)
    try {
      const res = await fetch('/api/cors', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.trim() }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error ?? 'Unknown error')
      setResult(data)
    } catch (e) { setError(e.message) }
    finally { setLoading(false) }
  }

  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
        4種類のオリジンパターンでCORSポリシーをテストします。
      </p>

      <div className="flex gap-2">
        <input value={url} onChange={e => setUrl(e.target.value)} onKeyDown={e => e.key === 'Enter' && scan()}
          placeholder="https://example.com"
          className="flex-1 bg-transparent px-4 py-3 text-sm outline-none font-mono rounded-lg border"
          style={{ color: 'var(--text)', borderColor: 'var(--border)', background: 'var(--bg-card)' }} />
        <button onClick={scan} disabled={loading || !url.trim()}
          className="px-5 py-3 rounded-lg font-sans font-bold text-sm disabled:opacity-40"
          style={{ background: 'var(--accent)', color: '#000' }}>
          {loading ? 'スキャン中...' : 'スキャン'}
        </button>
      </div>

      {error && <div className="p-3 rounded-lg font-mono text-sm" style={{ background: 'var(--red-dim)', color: 'var(--red)' }}>✗ {error}</div>}

      {result && (
        <div className="flex flex-col gap-3">
          <div className="flex items-center gap-3 p-4 rounded-xl border" style={{ background: 'var(--bg-card)', borderColor: result.vulnerable ? 'var(--red)44' : 'var(--green)44' }}>
            <span className="text-2xl">{result.vulnerable ? '🔴' : '✅'}</span>
            <div>
              <div className="font-sans font-bold" style={{ color: result.vulnerable ? 'var(--red)' : 'var(--green)' }}>
                {result.vulnerable ? 'CORS脆弱性が検出されました' : 'CORSの設定は安全です'}
              </div>
              <div className="font-mono text-xs mt-1" style={{ color: 'var(--text-muted)' }}>{result.response_time_ms}ms</div>
            </div>
          </div>
          {result.tests.map((t, i) => <TestRow key={i} test={t} />)}
        </div>
      )}
    </div>
  )
}
