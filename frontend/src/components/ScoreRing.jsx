export function ScoreRing({ score, max, grade }) {
  const pct = max > 0 ? score / max : 0
  const radius = 48
  const circ = 2 * Math.PI * radius
  const offset = circ * (1 - pct)

  const gradeColor = {
    'A+': '#00ff87', A: '#00ff87', B: '#00e5ff', C: '#ffcc00', D: '#ff9944', F: '#ff4466'
  }[grade] ?? '#6b6b8a'

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative w-32 h-32">
        <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
          <circle cx="60" cy="60" r={radius} fill="none" stroke="var(--border)" strokeWidth="8" />
          <circle
            cx="60" cy="60" r={radius}
            fill="none"
            stroke={gradeColor}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circ}
            strokeDashoffset={offset}
            style={{
              transition: 'stroke-dashoffset 1s cubic-bezier(0.4,0,0.2,1)',
              filter: `drop-shadow(0 0 8px ${gradeColor}88)`
            }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-sans text-3xl font-bold" style={{ color: gradeColor }}>{grade}</span>
          <span className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>{score}/{max}</span>
        </div>
      </div>
      <span className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>セキュリティスコア</span>
    </div>
  )
}
