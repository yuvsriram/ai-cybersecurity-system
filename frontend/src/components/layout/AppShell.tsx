import {
  Activity,
  Bell,
  Bot,
  BriefcaseBusiness,
  Database,
  FileClock,
  LayoutDashboard,
  LogOut,
  Radar,
  ScanSearch,
} from 'lucide-react'
import {
  NavLink,
  Outlet,
} from 'react-router-dom'

import {
  useApiKey,
} from '../../auth/ApiKeyContext'

const navigation = [
  {
    to: '/',
    label: 'Overview',
    icon: LayoutDashboard,
    end: true,
  },
  {
    to: '/analyze',
    label: 'Analyze Logs',
    icon: ScanSearch,
  },
  {
    to: '/events',
    label: 'Events',
    icon: Database,
  },
  {
    to: '/alerts',
    label: 'Alerts',
    icon: Bell,
  },
  {
    to: '/investigations',
    label: 'AI Investigations',
    icon: Bot,
  },
  {
    to: '/cases',
    label: 'Cases',
    icon: BriefcaseBusiness,
  },
  {
    to: '/audit',
    label: 'Audit Log',
    icon: FileClock,
  },
  {
    to: '/system',
    label: 'System',
    icon: Activity,
  },
]

export function AppShell() {
  const {
    authMode,
    disconnect,
  } = useApiKey()

  const demoMode =
    authMode === 'demo'

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <Radar
              size={22}
            />
          </div>

          <div>
            <div className="brand-name">
              Sentinel AI
            </div>

            <div className="brand-subtitle">
              Security Operations
            </div>
          </div>
        </div>

        <nav className="navigation">
          <div className="navigation-label">
            Workspace
          </div>

          {navigation.map(
            ({
              to,
              label,
              icon: Icon,
              end,
            }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                className={({
                  isActive,
                }) =>
                  [
                    'nav-item',
                    isActive
                      ? 'nav-item-active'
                      : '',
                  ]
                    .filter(Boolean)
                    .join(' ')
                }
              >
                <Icon
                  size={18}
                />

                <span>
                  {label}
                </span>
              </NavLink>
            ),
          )}
        </nav>

        <div className="sidebar-footer">
          <div className="environment-card">
            <div className="environment-row">
              <span className="status-dot" />

              <span>
                {demoMode
                  ? 'Public demo'
                  : 'Local environment'}
              </span>
            </div>

            <span className="environment-detail">
              {demoMode
                ? (
                    'Protected server-side '
                    + 'demo access'
                  )
                : (
                    'Production-like stack'
                  )}
            </span>
          </div>

          {!demoMode && (
            <button
              className="disconnect-button"
              type="button"
              onClick={disconnect}
            >
              <LogOut
                size={16}
              />

              Disconnect
            </button>
          )}
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div>
            <div className="topbar-eyebrow">
              AI POWERED CYBERSECURITY SYSTEM
            </div>

            <div className="topbar-title">
              Analyst Console
            </div>
          </div>

          <div className="topbar-status">
            <span className="status-dot" />

            {demoMode
              ? 'Live demo'
              : 'API connected'}
          </div>
        </header>

        <div className="page-container">
          <Outlet />
        </div>
      </main>
    </div>
  )
}