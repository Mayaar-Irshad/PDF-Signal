// Global styles first, so component styles (imported by App) can override them.
import './styles/tokens.css';
import './styles/global.css';
import './styles/accessibility.css';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './app/App';
import { installTrustedTypesPolicy } from './security/trustedTypes';

// Must run before anything reaches a Trusted Types sink (the scan worker is the only one).
installTrustedTypesPolicy();

const container = document.getElementById('root');
if (container === null) {
  throw new Error('PDF Signal could not find its root element.');
}

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
