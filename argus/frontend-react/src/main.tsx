import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ConfigProvider, theme } from 'antd'
import App from './App'
import './index.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 30_000,
    },
  },
})

const argusTheme = {
  algorithm: theme.darkAlgorithm,
  token: {
    colorBgBase: '#0d1117',
    colorBgContainer: '#161b22',
    colorBgElevated: '#1c2230',
    colorBorder: '#2a3142',
    colorBorderSecondary: '#2a3142',
    colorText: '#e6edf3',
    colorTextSecondary: '#7d8590',
    colorTextTertiary: '#4a5568',
    colorPrimary: '#58a6ff',
    colorError: '#f85149',
    colorWarning: '#d29922',
    colorSuccess: '#3fb950',
    colorLink: '#58a6ff',
    fontFamily: "'Segoe UI', system-ui, sans-serif",
    fontSize: 13,
    borderRadius: 6,
    borderRadiusSM: 4,
    lineHeight: 1.5,
    controlHeight: 32,
    controlHeightSM: 24,
  },
  components: {
    Table: {
      headerBg: '#161b22',
      headerColor: '#7d8590',
      rowHoverBg: '#1c2230',
      borderColor: '#2a3142',
      cellPaddingBlock: 8,
      cellPaddingInline: 14,
      headerBorderRadius: 0,
    },
    Badge: {
      colorBorderBg: 'transparent',
    },
    Tag: {
      defaultBg: 'rgba(42,49,66,0.8)',
      defaultColor: '#7d8590',
    },
    Button: {
      defaultBg: 'transparent',
      defaultBorderColor: '#2a3142',
      defaultColor: '#7d8590',
    },
    Card: {
      colorBgContainer: '#161b22',
      colorBorderSecondary: '#2a3142',
    },
    Layout: {
      headerBg: '#161b22',
      siderBg: '#161b22',
      bodyBg: '#0d1117',
      triggerBg: '#1c2230',
    },
    Menu: {
      darkItemBg: '#161b22',
      darkItemColor: '#7d8590',
      darkItemHoverColor: '#e6edf3',
      darkItemSelectedColor: '#e6edf3',
      darkItemSelectedBg: 'rgba(88,166,255,0.08)',
      itemHeight: 48,
    },
    Select: {
      colorBgContainer: '#1c2230',
      colorBorder: '#2a3142',
    },
    Input: {
      colorBgContainer: '#1c2230',
      colorBorder: '#2a3142',
      activeBorderColor: '#58a6ff',
    },
  },
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <ConfigProvider theme={argusTheme}>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </ConfigProvider>
    </QueryClientProvider>
  </StrictMode>
)
