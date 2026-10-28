import { APP_CONFIG } from '../../config/appConfig';

export function AppFooter() {
  return (
    <footer className="app-footer">
      <div className="app-footer__inner">
        <p>
          {APP_CONFIG.name} {APP_CONFIG.version}. An independent TypeScript implementation of the
          core keyword scan of{' '}
          <a href={APP_CONFIG.pdfidSourceUrl} target="_blank" rel="noopener noreferrer">
            PDFiD
          </a>{' '}
          by Didier Stevens, whose source code is in the public domain. Not affiliated with or
          endorsed by the PDFiD author.
        </p>
        <p>
          Static triage only: PDF Signal is not an antivirus product and cannot prove that a file is
          safe or malicious.
        </p>
        <p className="app-footer__copyright">© 2026 Irshad. Released under the MIT licence.</p>
      </div>
    </footer>
  );
}
