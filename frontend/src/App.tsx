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
  PlaceholderPage,
} from './pages/PlaceholderPage'


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
            <PlaceholderPage
              title="Cases"
              description="Track analyst cases and correlated alerts through investigation."
            />
          }
        />

        <Route
          path="audit"
          element={
            <PlaceholderPage
              title="Audit Log"
              description="Review security-sensitive activity and administrative actions."
            />
          }
        />

        <Route
          path="system"
          element={
            <PlaceholderPage
              title="System"
              description="Inspect application health, workers, observability, and platform status."
            />
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