import {
  StrictMode,
} from 'react'

import {
  createRoot,
} from 'react-dom/client'

import {
  BrowserRouter,
} from 'react-router-dom'

import App from './App'

import {
  ApiKeyProvider,
} from './auth/ApiKeyContext'

import './index.css'
import './styles/data.css'
import './styles/analysis.css'
import './styles/investigations.css'
import './styles/cases.css'
import './styles/audit.css'
import './styles/system.css'

createRoot(
  document.getElementById(
    'root',
  )!,
).render(
  <StrictMode>
    <BrowserRouter>
      <ApiKeyProvider>
        <App />
      </ApiKeyProvider>
    </BrowserRouter>
  </StrictMode>,
)