import { useState } from 'react'

const statusConfig = {
  good:    { color: 'var(--green)',  bg: 'var(--green-dim)',  icon: '✓', label: '良好' },
  warning: { color: 'var(--yellow)', bg: 'var(--yellow-dim)', icon: '⚠', label: '要改善' },
  missing: { color: 'var(--red)',    bg: 'var(--red-dim)',    icon: '✗', label: '未設定' },
}

export function HeaderCard({ header, index }) {
  const [open, setOpen] = useState(false)
  const cfg = statusConfig[header.status] ?? statusConfig.missing
  const pct = header.max_score > 0 ? (header.score / header.max_score) * 100 : 0

  return (
    <div
      className="rounded-lg border cursor-pointer transition-all duration-200 animate-slide-in"
      style={{
        background: 'var(--bg-card)',
        borderColor: open ? cfg.color + '44' : 'var(--border)',
        animationDelay: `${index * 60}ms`,
        opacity: 0,
        animationFillMode: 'forwards',
      }}
      onClick={() => setOpen(!open)}
    >
      {/* Header row */}
      <div className="flex items-center gap-3 p-4">
        <span
          className="w-7 h-7 rounded flex items-center justify-center text-sm font-bold shrink-0"
          style={{ background: cfg.bg, color: cfg.color }}
        >
          {cfg.icon}
        </span>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-sm font-bold" style={{ color: 'var(--text)' }}>
              {header.name}
            </span>
            <span
              className="text-xs px-2 py-0.5 rounded-full font-mono"
              style={{ background: cfg.bg, color: cfg.color }}
            >
              {cfg.label}
            </span>
          </div>
          {/* Score bar */}
          <div className="mt-2 h-1 rounded-full overflow-hidden" style={{ background: 'var(--border)' }}>
            <div
              className="h-full rounded-full transition-all duration-1000"
              style={{ width: `${pct}%`, background: cfg.color, transitionDelay: `${index * 60 + 200}ms` }}
            />
          </div>
        </div>

        <div className="text-right shrink-0">
          <span className="font-mono text-sm font-bold" style={{ color: cfg.color }}>
            {header.score}
          </span>
          <span className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>
            /{header.max_score}
          </span>
        </div>

        <span
          className="text-xs transition-transform duration-200 shrink-0"
          style={{ color: 'var(--text-muted)', transform: open ? 'rotate(180deg)' : 'rotate(0)' }}
        >
          ▼
        </span>
      </div>

      {/* Expanded detail */}
      {open && (
        <div
          className="px-4 pb-4 border-t"
          style={{ borderColor: 'var(--border)' }}
        >
          {header.value && (
            <div className="mt-3 mb-3">
              <div className="text-xs mb-1" style={{ color: 'var(--text-muted)' }}>現在の値</div>
              <code
                className="block text-xs p-2 rounded break-all"
                style={{ background: 'var(--bg)', color: 'var(--accent)', fontFamily: '"Space Mono", monospace' }}
              >
                {header.value}
              </code>
            </div>
          )}
          <p className="text-sm mb-2" style={{ color: 'var(--text-muted)', lineHeight: 1.6 }}>
            {header.description}
          </p>
          {header.advice && (
            <div
              className="mt-2 p-3 rounded-lg text-sm"
              style={{ background: cfg.bg, color: cfg.color, lineHeight: 1.6 }}
            >
              💡 {header.advice}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
