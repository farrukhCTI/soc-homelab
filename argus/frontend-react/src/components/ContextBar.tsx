import { ReactNode } from 'react'

interface Stat {
  label: ReactNode
  value?: ReactNode
  danger?: boolean
}

interface Props {
  title: string
  stats?: Stat[]
  right?: ReactNode
}

export default function ContextBar({ title, stats = [], right }: Props) {
  return (
    <div
      style={{
        background: 'var(--surface2)',
        borderBottom: '1px solid var(--border)',
        padding: '0 24px',
        height: 32,
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        fontSize: 11,
        flexShrink: 0,
      }}
    >
      <span style={{ fontWeight: 600, color: 'var(--text)', fontSize: 12 }}>{title}</span>

      {stats.map((stat, i) => (
        <span key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ color: 'var(--dim)' }}>|</span>
          <span style={{ color: stat.danger ? 'var(--red)' : 'var(--muted)' }}>
            {stat.value !== undefined ? (
              <>
                <strong style={{ color: stat.danger ? 'var(--red)' : 'var(--text)', fontWeight: 600 }}>
                  {stat.value}
                </strong>
                {' '}{stat.label}
              </>
            ) : stat.label}
          </span>
        </span>
      ))}

      {right && (
        <span style={{ marginLeft: 'auto' }}>{right}</span>
      )}
    </div>
  )
}
