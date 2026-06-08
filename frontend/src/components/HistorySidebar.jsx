import { useEffect, useState } from 'react'

const gradeColor = {
  'A+': '#00ff87', A: '#00ff87', B: '#00e5ff', C: '#ffcc00', D: '#ff9944', F: '#ff4466'
}

export function HistorySidebar({ onSelect, refreshTrigger }) {
  const [history, setHistory] = useState([])

  useEffect(() => {
    fetch('/api/history')
      .then(r => r.json())
      .then(data => setHistory(Array.isArray(data) ? data : []))
      .catch(() => {})
  }, [refreshTrigger])

  if (history.length === 0) return null

  return (
    <div
      className="rounded-xl border p-4"
      style={{ background: 'var(--bg-card)', borderColor: 'var(--border)' }}
    >
      <h3 className="font-mono text-xs mb-3" style={{ color: 'var(--text-muted)' }}>
        ── 過去のスキャン ──
      </h3>
      <div className="flex flex-col gap-2">
        {history.map(entry => (
          <button
            key={entry.id}
            onClick={() => onSelect(entry.url)}
            className="flex items-center gap-3 p-2 rounded-lg text-left w-full transition-all duration-150"
            style={{ background: 'transparent' }}
            onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-hover)'}
            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
          >
            <span
              className="w-8 h-8 rounded flex items-center justify-center text-xs font-bold shrink-0 font-sans"
              style={{
                background: (gradeColor[entry.grade] ?? '#6b6b8a') + '22',
                color: gradeColor[entry.grade] ?? '#6b6b8a'
              }}
            >
              {entry.grade}
            </span>
            <div className="flex-1 min-w-0">
              <div className="text-xs truncate font-mono" style={{ color: 'var(--text)' }}>
                {entry.url.replace(/^https?:\/\//, '')}
              </div>
              <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
                {entry.total_score}/{entry.max_score}pt
              </div>
            </div>
          </button>
        ))}
      </div>
    </div>
  )
}
