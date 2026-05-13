import { useLocation, useNavigate } from 'react-router-dom'
import { Layout, Menu } from 'antd'

const NAV_ITEMS = [
  { key: '/',             label: 'Case Queue' },
  { key: '/investigation',label: 'Investigation' },
  { key: '/actions',      label: 'Actions Log' },
  { key: '/hunt',         label: 'Hunt Workbench' },
]

export default function AppNav() {
  const location = useLocation()
  const navigate = useNavigate()

  const selectedKey = NAV_ITEMS.find(item =>
    item.key === '/'
      ? location.pathname === '/'
      : location.pathname.startsWith(item.key)
  )?.key ?? '/'

  return (
    <Layout.Header
      style={{
        position: 'sticky',
        top: 0,
        zIndex: 100,
        height: 48,
        padding: '0 24px',
        background: 'var(--surface)',
        borderBottom: '1px solid var(--border)',
        display: 'flex',
        alignItems: 'center',
        gap: 0,
      }}
    >
      <span
        style={{
          fontSize: 15,
          fontWeight: 700,
          color: 'var(--accent)',
          letterSpacing: '-0.3px',
          marginRight: 24,
          cursor: 'pointer',
          flexShrink: 0,
        }}
        onClick={() => navigate('/')}
      >
        ARGUS
      </span>

      <Menu
        mode="horizontal"
        theme="dark"
        selectedKeys={[selectedKey]}
        onClick={({ key }) => navigate(key)}
        items={NAV_ITEMS}
        style={{
          background: 'transparent',
          borderBottom: 'none',
          flex: 1,
          lineHeight: '46px',
          fontSize: 13,
        }}
      />
    </Layout.Header>
  )
}
