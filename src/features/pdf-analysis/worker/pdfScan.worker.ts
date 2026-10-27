/**
 * Dedicated Web Worker entry point. Scanning runs here, off the interface thread. Each scan
 * gets a fresh worker that the client terminates afterwards, so no file data outlives a scan.
 *
 * A worker separates execution from the page; it is not an operating-system sandbox. The PDF
 * is only ever read as bytes and is never rendered, parsed for execution or evaluated.
 */
import { handleScanRequest } from './scanWorkerHandler';

self.addEventListener('message', (event: MessageEvent<unknown>) => {
  void handleScanRequest(event.data, (message) => {
    self.postMessage(message);
  });
});
