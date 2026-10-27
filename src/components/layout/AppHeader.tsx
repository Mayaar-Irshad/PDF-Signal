import { APP_CONFIG } from '../../config/appConfig';

/** Brand mark: a signal trace inside a document outline. Decorative. */
function SignalMark() {
  return (
    <svg className="brand__mark" viewBox="0 0 40 40" aria-hidden="true" focusable="false">
      <path
        d="M9 4.5h15.5L32 12v23.5H9z"
        fill="none"
        stroke="currentColor"
        strokeWidth="2.4"
        strokeLinejoin="round"
      />
      <path
        d="M24 4.5V12h8"
        fill="none"
        stroke="currentColor"
        strokeWidth="2.4"
        strokeLinejoin="round"
      />
      <path
        d="M12 25h4l2.5-7 3.5 12 3-8h3"
        fill="none"
        stroke="currentColor"
        strokeWidth="2.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function AppHeader() {
  return (
    <header className="app-header">
      <div className="app-header__inner">
        <div className="brand">
          <SignalMark />
          <div>
            <h1 className="brand__name">{APP_CONFIG.name}</h1>
            <p className="brand__description">Browser-only PDF security triage</p>
          </div>
        </div>
        <p className="privacy-indicator">
          <svg
            viewBox="0 0 16 16"
            aria-hidden="true"
            focusable="false"
            className="privacy-indicator__icon"
          >
            <path
              d="M4.5 7V5a3.5 3.5 0 0 1 7 0v2M3.5 7h9v7h-9z"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinejoin="round"
            />
          </svg>
          Processed locally · no uploads
        </p>
      </div>
    </header>
  );
}
