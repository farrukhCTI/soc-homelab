import { Tag } from 'antd'
import type { Severity } from '../types'

interface Props {
  severity: string
  size?: 'sm' | 'md'
}

export default function SeverityBadge({ severity, size = 'md' }: Props) {
  const s = (severity || '').toUpperCase() as Severity
  const cls = s.toLowerCase()
  return (
    <Tag
      className={`sev-${cls}`}
      style={{
        fontSize: size === 'sm' ? 9 : 10,
        fontWeight: 700,
        letterSpacing: '0.5px',
        textTransform: 'uppercase',
        borderRadius: 3,
        padding: size === 'sm' ? '0 5px' : '1px 8px',
        lineHeight: size === 'sm' ? '16px' : '18px',
        margin: 0,
      }}
    >
      {s}
    </Tag>
  )
}
