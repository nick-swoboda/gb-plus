"use strict";

export function createDiagnostics({ invoke, elements, onBusy, onError, onNotice }) {
  async function exportArchive() {
    if (!invoke) {
      onError("Diagnostic export is available only inside the Tauri app.");
      return;
    }
    onBusy(true);
    elements.diagnosticStatus.dataset.kind = "working";
    elements.diagnosticStatus.textContent = "Preparing a default-safe archive…";
    try {
      const result = await invoke("export_diagnostics", {});
      if (!result) {
        elements.diagnosticStatus.dataset.kind = "idle";
        elements.diagnosticStatus.textContent = "Export cancelled. No archive was written.";
        return;
      }
      elements.diagnosticStatus.dataset.kind = "success";
      elements.diagnosticStatus.textContent = `${result.status}: ${result.path}`;
      elements.diagnosticPath.textContent = result.path;
      elements.diagnosticPath.title = result.path;
      elements.diagnosticHash.textContent = result.archiveSha256;
      elements.diagnosticManifestHash.textContent = result.manifestSha256;
      elements.diagnosticSize.textContent = `${result.byteCount.toLocaleString()} bytes · ${result.entryCount} entries`;
      elements.diagnosticResult.hidden = false;
      onNotice("Diagnostic archive exported");
    } catch (error) {
      elements.diagnosticStatus.dataset.kind = "error";
      const message = error instanceof Error ? error.message : String(error);
      elements.diagnosticStatus.textContent = message;
      onError(message);
    } finally {
      onBusy(false);
    }
  }

  elements.exportDiagnostics.addEventListener("click", () => {
    void exportArchive();
  });

  return { exportArchive };
}
