import { useState } from 'react'

const severityColor = {
  critical: 'var(--red)',
  high:     'var(--yellow)',
  warning:  '#ff9944',
  info:     'var(--accent)',
}
const severityBg = {
  critical: 'var(--red-dim)',
  high:     'var(--yellow-dim)',
  warning:  'rgba(255,153,68,0.1)',
  info:     'var(--accent-dim)',
}

const SAMPLE_JWT = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlNoaWVsZFNjYW4iLCJpYXQiOjE1MTYyMzkwMjJ9.'

function JsonTree({ data }) {
  return (
    <div className="rounded-lg p-3 font-mono text-xs overflow-x-auto" style={{ background: 'var(--bg)', color: 'var(--text)' }}>
      {Object.entries(data).map(([k, v]) => (
        <div key={k} className="flex gap-2">
          <span style={{ color: 'var(--accent)' }}>{k}:</span>
          <span style={{ color: typeof v === 'number' ? 'var(--green)' : typeof v === 'boolean' ? 'var(--yellow)' : 'var(--text)' }}>
            {JSON.stringify(v)}
          </span>
        </div>
      ))}
    </div>
  )
}

export function JWToolTab() {
  const [token, setToken] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  const analyze = async (t) => {
    const tk = (t ?? token).trim()
    if (!tk) return
    setLoading(true); setError(''); setResult(null)
    try {
      const res = await fetch('/api/jwt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: tk }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error ?? 'Unknown error')
      setResult(data)
    } catch (e) { setError(e.message) }
    finally { setLoading(false) }
  }

  const worstSeverity = result?.findings?.reduce((w, f) => {
    const order = { info: 0, warning: 1, high: 2, critical: 3 }
    return order[f.severity] > order[w] ? f.severity : w
  }, 'info')

  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
        JWTトークンを解析し、alg:none・kid injection・exp未設定などの脆弱性を検出します。
      </p>

      <div className="flex flex-col gap-2">
        <textarea value={token} onChange={e => setToken(e.target.value)}
          placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...."
          rows={3}
          className="w-full bg-transparent px-4 py-3 text-xs outline-none font-mono rounded-lg border resize-none"
          style={{ color: 'var(--accent)', borderColor: 'var(--border)', background: 'var(--bg-card)' }} />
        <div className="flex gap-2">
          <button onClick={() => { setToken(SAMPLE_JWT); analyze(SAMPLE_JWT) }}
            className="px-4 py-2 rounded-lg text-xs font-mono border transition-all"
            style={{ borderColor: 'var(--border)', color: 'var(--text-muted)', background: 'transparent' }}>
            サンプル (alg:none)
          </button>
          <button onClick={() => analyze()} disabled={loading || !token.trim()}
            className="flex-1 py-2 rounded-lg font-sans font-bold text-sm disabled:opacity-40"
            style={{ background: 'var(--accent)', color: '#000' }}>
            {loading ? '解析中...' : '解析'}
          </button>
        </div>
      </div>

      {error && <div className="p-3 rounded-lg font-mono text-sm" style={{ background: 'var(--red-dim)', color: 'var(--red)' }}>✗ {error}</div>}

      {result && (
        <div className="flex flex-col gap-4">
          {result.parse_error ? (
            <div className="p-4 rounded-xl border" style={{ background: 'var(--red-dim)', borderColor: 'var(--red)44', color: 'var(--red)' }}>
              パースエラー: {result.parse_error}
            </div>
          ) : (
            <>
              {/* Meta */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                {result.issued_at && (
                  <div className="p-3 rounded-lg border" style={{ background: 'var(--bg-card)', borderColor: 'var(--border)' }}>
                    <div className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>発行日時</div>
                    <div className="font-mono text-xs mt-1 break-all" style={{ color: 'var(--text)' }}>{result.issued_at}</div>
                  </div>
                )}
                {result.expires_at && (
                  <div className="p-3 rounded-lg border" style={{ background: 'var(--bg-card)', borderColor: result.expired ? 'var(--red)44' : 'var(--border)' }}>
                    <div className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>有効期限</div>
                    <div className="font-mono text-xs mt-1 break-all" style={{ color: result.expired ? 'var(--red)' : 'var(--green)' }}>
                      {result.expires_at} {result.expired ? '⚠ 期限切れ' : ''}
                    </div>
                  </div>
                )}
              </div>

              {/* Header / Payload */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                  <div className="font-mono text-xs mb-2" style={{ color: 'var(--text-muted)' }}>── ヘッダー</div>
                  <JsonTree data={result.header} />
                </div>
                <div>
                  <div className="font-mono text-xs mb-2" style={{ color: 'var(--text-muted)' }}>── ペイロード</div>
                  <JsonTree data={result.payload} />
                </div>
              </div>

              {/* Findings */}
              <div>
                <div className="font-mono text-xs mb-2" style={{ color: 'var(--text-muted)' }}>── 検出結果</div>
                <div className="flex flex-col gap-2">
                  {result.findings.map((f, i) => (
                    <div key={i} className="p-3 rounded-lg border" style={{ background: severityBg[f.severity], borderColor: severityColor[f.severity] + '44' }}>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-mono text-xs font-bold px-2 py-0.5 rounded" style={{ background: severityColor[f.severity] + '22', color: severityColor[f.severity] }}>
                          {f.severity.toUpperCase()}
                        </span>
                        <span className="font-sans font-bold text-sm" style={{ color: 'var(--text)' }}>{f.title}</span>
                      </div>
                      <p className="text-xs" style={{ color: 'var(--text-muted)', lineHeight: 1.6 }}>{f.description}</p>
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
