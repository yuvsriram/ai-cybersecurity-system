import {
  Navigate,
  Route,
  Routes,
} from 'react-router-dom'

import {
  useApiKey,
} from './auth/ApiKeyContext'

import {
  AppShell,
} from './components/layout/AppShell'

import {
  AlertsPage,
} from './pages/AlertsPage'

import {
  AnalyzeLogsPage,
} from './pages/AnalyzeLogsPage'

import {
  AuditLogPage,
} from './pages/AuditLogPage'

import {
  CasesPage,
} from './pages/CasesPage'

import {
  ConnectPage,
} from './pages/ConnectPage'

import {
  DashboardPage,
} from './pages/DashboardPage'

import {
  EventsPage,
} from './pages/EventsPage'

import {
  InvestigationsPage,
} from './pages/InvestigationsPage'

import {
  SystemPage,
} from './pages/SystemPage'


function App() {
  const {
    connected,
    authMode,
  } = useApiKey()

  return (
    <Routes>
      <Route
        path="/connect"
        element={
          authMode === 'demo'
            ? (
                <Navigate
                  to="/"
                  replace
                />
              )
            : connected
              ? (
                  <Navigate
                    to="/"
                    replace
                  />
                )
              : (
                  <ConnectPage />
                )
        }
      />

      <Route
        element={
          connected
            ? (
                <AppShell />
              )
            : (
                <Navigate
                  to="/connect"
                  replace
                />
              )
        }
      >
        <Route
          index
          element={
            <DashboardPage />
          }
        />

        <Route
          path="analyze"
          element={
            <AnalyzeLogsPage />
          }
        />

        <Route
          path="events"
          element={
            <EventsPage />
          }
        />

        <Route
          path="alerts"
          element={
            <AlertsPage />
          }
        />

        <Route
          path="investigations"
          element={
            <InvestigationsPage />
          }
        />

        <Route
          path="cases"
          element={
            <CasesPage />
          }
        />

        <Route
          path="audit"
          element={
            <AuditLogPage />
          }
        />

        <Route
          path="system"
          element={
            <SystemPage />
          }
        />

        <Route
          path="*"
          element={
            <Navigate
              to="/"
              replace
            />
          }
        />
      </Route>
    </Routes>
  )
}

export default App