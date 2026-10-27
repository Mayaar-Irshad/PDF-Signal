export function PrivacyNotice() {
  return (
    <aside className="card privacy-notice" aria-labelledby="privacy-heading">
      <h2 id="privacy-heading" className="section-heading">
        Your file stays on this device
      </h2>
      <ul className="check-list">
        <li>The PDF is read and scanned inside your browser, in a background worker.</li>
        <li>It is never uploaded. PDF Signal has no server, scanning service or external API.</li>
        <li>
          The file is not stored: nothing is written to browser storage, and it is released after
          the scan.
        </li>
        <li>Reports are generated locally and only saved when you choose to download one.</li>
        <li>No analytics, tracking or third-party scripts are included.</li>
      </ul>
      <p className="privacy-notice__note">
        PDFs can contain highly sensitive information. PDF Signal never displays the document itself
        or its text; it reports keyword counts, file structure, action types and script pattern
        names only.
      </p>
    </aside>
  );
}
