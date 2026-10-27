interface WarningIconProps {
  readonly className?: string;
}

/** Decorative warning triangle; pair it with visible text that carries the meaning. */
export function WarningIcon({ className = 'warning-icon' }: WarningIconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path
        d="M12 3.2 1.9 20.5h20.2z"
        fill="currentColor"
        fillOpacity="0.16"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <path d="M12 9.5v5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      <circle cx="12" cy="17.4" r="1.15" fill="currentColor" />
    </svg>
  );
}
