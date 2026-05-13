import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Table, Tag, Button, Typography, Space, Spin, Alert, Tooltip } from 'antd'
import { ReloadOutlined, RightOutlined } from '@ant-design/icons'
import type { ColumnsType, ExpandableConfig } from 'antd/es/table'
import { fetchCases, fetchCaseBehaviors } from '../api'
import type { Case, Behavior } from '../types'
import SeverityBadge from '../components/SeverityBadge'
import ContextBar from '../components/ContextBar'

const { Text } = Typography

function fmtTime(ts: string) {
  return new Date(ts).toISOString().replace('T', ' ').slice(0, 19) + ' UTC'
}

// Behavior sub-table rendered when a case row expands
function BehaviorSubTable({ caseId }: { caseId: string }) {
  const navigate = useNavigate()
  const { data, isLoading, error } = useQuery({
    queryKey: ['case-behaviors', caseId],
    queryFn: () => fetchCaseBehaviors(caseId),
  })

  if (isLoading) return <Spin size="small" style={{ padding: 16 }} />
  if (error) return <Alert type="error" message="Failed to load behaviors" showIcon style={{ margin: 8 }} />

  const cols: ColumnsType<Behavior> = [
    {
      key: 'sev',
      width: 84,
      render: (_, r) => <SeverityBadge severity={r.severity} size="sm" />,
    },
    {
      title: 'Behavior',
      dataIndex: 'description',
      ellipsis: true,
      render: (v: string) => <Text style={{ color: 'var(--text)', fontSize: 13 }}>{v}</Text>,
    },
    {
      title: 'Tactic',
      dataIndex: 'tactic',
      width: 160,
      render: (v: string) => (
        <Tag style={{ background: 'rgba(42,49,66,0.8)', color: 'var(--muted)', borderColor: 'rgba(58,70,90,0.8)', fontSize: 10 }}>
          {v}
        </Tag>
      ),
    },
    {
      title: 'Host',
      dataIndex: 'host',
      width: 140,
      render: (v: string) => <Text className="mono" style={{ fontSize: 11, color: 'var(--muted)' }}>{v}</Text>,
    },
    {
      title: 'Time (UTC)',
      dataIndex: 'timestamp',
      width: 160,
      render: (v: string) => <Text className="mono" style={{ fontSize: 11, color: 'var(--dim)' }}>{fmtTime(v)}</Text>,
    },
    {
      title: 'Status',
      dataIndex: 'status',
      width: 90,
      render: (v: string) => <Text style={{ fontSize: 11, color: 'var(--dim)' }}>{v}</Text>,
    },
    {
      key: 'arrow',
      width: 32,
      render: (_, r) => (
        <RightOutlined style={{ color: 'var(--accent)', fontSize: 11 }} />
      ),
    },
  ]

  return (
    <Table
      dataSource={data}
      columns={cols}
      rowKey="behavior_id"
      size="small"
      pagination={false}
      showHeader={false}
      style={{ background: 'var(--bg)' }}
      onRow={(r) => ({
        style: { cursor: 'pointer' },
        onClick: () => navigate(`/investigation?behavior_id=${r.behavior_id}`),
      })}
    />
  )
}

// Left accent color by severity
function severityBorderColor(sev: string) {
  switch ((sev || '').toUpperCase()) {
    case 'CRITICAL': return 'var(--red)'
    case 'HIGH':     return 'rgba(248,81,73,0.5)'
    case 'MEDIUM':   return 'rgba(210,153,34,0.45)'
    default:         return 'rgba(88,166,255,0.25)'
  }
}

export default function CaseQueue() {
  const navigate = useNavigate()
  const [expandedRows, setExpandedRows] = useState<string[]>([])

  const { data: cases, isLoading, error, refetch, dataUpdatedAt } = useQuery({
    queryKey: ['cases'],
    queryFn: fetchCases,
    refetchInterval: 60_000,
  })

  const total    = cases?.length ?? 0
  const open     = cases?.filter(c => c.status?.toLowerCase() === 'open').length ?? 0
  const critical = cases?.filter(c => c.highest_severity?.toUpperCase() === 'CRITICAL').length ?? 0
  const lastUpdated = dataUpdatedAt
    ? new Date(dataUpdatedAt).toISOString().replace('T', ' ').slice(0, 19) + ' UTC'
    : ''

  const columns: ColumnsType<Case> = [
    // Severity + status stacked
    {
      key: 'sev',
      width: 100,
      render: (_, r) => (
        <Space direction="vertical" size={4}>
          <SeverityBadge severity={r.highest_severity} />
          <Tag
            style={{
              fontSize: 9,
              fontWeight: 600,
              textTransform: 'uppercase',
              letterSpacing: '0.3px',
              background: 'rgba(63,185,80,0.10)',
              color: 'var(--green)',
              borderColor: 'rgba(63,185,80,0.22)',
              margin: 0,
            }}
          >
            {r.status}
          </Tag>
        </Space>
      ),
    },
    // Main narrative column
    {
      key: 'narrative',
      render: (_, r) => {
        const br = r.blast_radius ?? {}
        const scopeParts = [
          br.hosts_affected != null    ? `${br.hosts_affected}h`    : '',
          br.ips_contacted != null && br.ips_contacted > 0
                                       ? `${br.ips_contacted}ip`   : '',
          br.processes_spawned != null ? `${br.processes_spawned}p` : '',
        ].filter(Boolean).join(' ')

        const tactics = r.tactics_seen ?? []
        const vis     = tactics.slice(0, 3)
        const overflow = tactics.length - vis.length

        return (
          <div>
            {/* Line 1: reason */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
              <Text strong style={{ color: 'var(--text)', fontSize: 13 }}>
                {r.grouped_by?.reason || 'No grouping reason'}
              </Text>
            </div>
            {/* Line 2: metadata */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 0, flexWrap: 'nowrap', overflow: 'hidden' }}>
              <Text className="mono" style={{ fontSize: 10, color: 'var(--dim)', marginRight: 8, flexShrink: 0 }}>
                {r.case_id}
              </Text>
              {r.grouped_by?.time_window && (
                <Text className="mono" style={{ fontSize: 10, color: 'var(--muted)', marginRight: 8, flexShrink: 0 }}>
                  {r.grouped_by.time_window}
                </Text>
              )}
              {r.grouped_by?.shared_host && (
                <Text style={{ fontSize: 11, color: 'var(--muted)', marginRight: 8, flexShrink: 0 }}>
                  {r.grouped_by.shared_host}
                </Text>
              )}
              {scopeParts && (
                <>
                  <Text style={{ color: 'var(--dim)', marginRight: 8 }}>&middot;</Text>
                  <Text style={{ fontSize: 11, color: 'var(--dim)', marginRight: 8, flexShrink: 0 }}>
                    {scopeParts}
                  </Text>
                </>
              )}
              {vis.length > 0 && (
                <>
                  <Text style={{ color: 'var(--dim)', marginRight: 8 }}>&middot;</Text>
                  <Space size={4} wrap={false} style={{ flexShrink: 0 }}>
                    {vis.map(t => (
                      <Tag
                        key={t}
                        style={{
                          background: 'rgba(42,49,66,0.8)',
                          color: 'var(--dim)',
                          borderColor: 'rgba(58,70,90,0.8)',
                          fontSize: 9,
                          margin: 0,
                        }}
                      >
                        {t}
                      </Tag>
                    ))}
                    {overflow > 0 && (
                      <Text style={{ fontSize: 10, color: 'var(--dim)' }}>+{overflow}</Text>
                    )}
                  </Space>
                </>
              )}
            </div>
          </div>
        )
      },
    },
    // Risk score
    {
      key: 'risk',
      width: 90,
      align: 'right' as const,
      render: (_, r) => (
        <div style={{ textAlign: 'right' }}>
          <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.8px', color: 'var(--dim)', marginBottom: 2 }}>
            Risk
          </div>
          <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--muted)', fontFamily: 'Consolas, monospace', lineHeight: 1 }}>
            {Math.round(r.risk_score)}
          </div>
          <div style={{ fontSize: 10, color: 'var(--dim)', marginTop: 2 }}>
            {r.behavior_count} behaviors
          </div>
        </div>
      ),
    },
  ]

  const expandable: ExpandableConfig<Case> = {
    expandedRowKeys: expandedRows,
    onExpand: (expanded, record) => {
      setExpandedRows(expanded
        ? [...expandedRows, record.case_id]
        : expandedRows.filter(k => k !== record.case_id)
      )
    },
    expandedRowRender: (record) => <BehaviorSubTable caseId={record.case_id} />,
    expandRowByClick: true,
    expandIcon: ({ expanded, onExpand, record }) => (
      <RightOutlined
        style={{
          color: 'var(--dim)',
          fontSize: 10,
          transform: expanded ? 'rotate(90deg)' : 'none',
          transition: 'transform 0.2s',
        }}
        onClick={e => onExpand(record, e)}
      />
    ),
  }

  if (isLoading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh' }}>
        <Spin size="large" />
      </div>
    )
  }

  if (error) {
    return (
      <div style={{ padding: 24 }}>
        <Alert
          type="error"
          message="Failed to load cases"
          description={(error as Error).message}
          showIcon
          action={<Button size="small" onClick={() => refetch()}>Retry</Button>}
        />
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 48px)' }}>
      <ContextBar
        title="Case Queue"
        stats={[
          { value: total, label: 'cases' },
          { value: open, label: 'open' },
          ...(critical > 0 ? [{ value: critical, label: 'critical', danger: true }] : []),
          { label: `sorted by risk desc` },
          ...(lastUpdated ? [{ label: `updated ${lastUpdated}` }] : []),
        ]}
        right={
          <Button
            size="small"
            icon={<ReloadOutlined />}
            onClick={() => refetch()}
            style={{ fontSize: 11 }}
          >
            Refresh
          </Button>
        }
      />

      <div style={{ flex: 1, overflow: 'auto', padding: '16px 24px' }}>
        <Table
          dataSource={cases}
          columns={columns}
          rowKey="case_id"
          size="small"
          pagination={false}
          expandable={expandable}
          showHeader={false}
          style={{ background: 'transparent' }}
          rowClassName={(r) => `case-row-${r.highest_severity?.toLowerCase()}`}
          onRow={(r) => ({
            style: {
              borderLeft: `3px solid ${severityBorderColor(r.highest_severity)}`,
              cursor: 'pointer',
            },
          })}
        />
      </div>
    </div>
  )
}
