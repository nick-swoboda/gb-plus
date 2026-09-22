"use strict";

const LIVE_REFRESH_DELAY_MS = 220;

function displayName(path) {
  if (!path) return "No active project";
  const parts = path.split("/").filter(Boolean);
  return parts.at(-1) || path;
}

function formatBytes(value) {
  if (!Number.isFinite(value)) return "Size unknown";
  if (value < 1024) return `${value.toLocaleString()} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}

function statusLabel(status) {
  switch (status) {
    case "text":
      return "Read-only text";
    case "binary":
      return "Binary · not rendered";
    case "oversized":
      return "Oversized · not rendered";
    case "symlink":
      return "Symlink · not followed";
    case "missing":
      return "Missing";
    case "changed":
      return "Changed during read";
    case "notFile":
      return "Not a regular file";
    default:
      return "Unreadable";
  }
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

export function createWorkspaceBrowser({ invoke, elements, onError }) {
  let root = null;
  let generation = 0;
  let pending = 0;
  let hostBusy = false;
  let selectedPath = null;
  let refreshTimer = null;
  const directories = new Map();
  const expanded = new Set(["."]);

  function setStatus(message, kind = "idle") {
    elements.workspaceStatus.textContent = message;
    elements.workspaceStatus.dataset.kind = kind;
  }

  function updateAvailability() {
    const blocked = hostBusy || pending > 0;
    elements.workspaceRefresh.disabled = blocked || !root;
    elements.workspaceTree.querySelectorAll("button[data-workspace-action]").forEach((button) => {
      button.disabled = blocked || button.dataset.workspaceAction === "none";
    });
  }

  function renderViewerEmpty() {
    elements.workspaceViewer.hidden = true;
    elements.workspaceViewerEmpty.hidden = false;
    elements.workspaceViewer.dataset.status = "idle";
    elements.workspaceFilePath.textContent = "No file selected";
    elements.workspaceFileMeta.textContent = "Read only";
    elements.workspaceFileDetail.textContent = "";
    elements.workspaceFileContent.textContent = "";
    elements.workspaceFileContent.hidden = false;
  }

  function renderFile(file) {
    elements.workspaceViewerEmpty.hidden = true;
    elements.workspaceViewer.hidden = false;
    elements.workspaceViewer.dataset.status = file.status;
    elements.workspaceFilePath.textContent = file.path;
    elements.workspaceFilePath.title = file.path;
    const size = Number.isFinite(file.byteCount) ? ` · ${formatBytes(file.byteCount)}` : "";
    elements.workspaceFileMeta.textContent = `${statusLabel(file.status)}${size}`;
    elements.workspaceFileDetail.textContent = file.detail;
    const isText = file.status === "text" && typeof file.content === "string";
    elements.workspaceFileContent.hidden = !isText;
    elements.workspaceFileContent.textContent = isText ? file.content : "";
  }

  function renderViewerError(path, message) {
    renderFile({
      path,
      status: "unreadable",
      content: null,
      byteCount: null,
      detail: message,
    });
  }

  function makeTreeRow(entry, depth) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "workspace-tree-row";
    row.dataset.kind = entry.kind;
    row.dataset.workspaceAction = entry.kind === "directory" || entry.kind === "file"
      ? entry.kind
      : "none";
    row.setAttribute("role", "treeitem");
    row.setAttribute("aria-level", String(depth));
    row.style.setProperty("--workspace-indent", `${(depth - 1) * 13}px`);
    if (entry.path === selectedPath) row.classList.add("is-selected");

    const disclosure = document.createElement("span");
    disclosure.className = "workspace-tree-disclosure";
    disclosure.setAttribute("aria-hidden", "true");
    if (entry.kind === "directory") {
      const open = expanded.has(entry.path);
      disclosure.textContent = open ? "⌄" : "›";
      row.setAttribute("aria-expanded", String(open));
    } else if (entry.kind === "symlink") {
      disclosure.textContent = "↗";
    } else if (entry.kind === "file") {
      disclosure.textContent = "·";
    } else {
      disclosure.textContent = "!";
      row.setAttribute("aria-disabled", "true");
    }

    const name = document.createElement("span");
    name.className = "workspace-tree-name";
    if (entry.kind === "file" && /\.[A-Za-z0-9][A-Za-z0-9._-]*$/.test(entry.name)) {
      name.classList.add("has-extension");
    }
    name.textContent = entry.name;

    const meta = document.createElement("span");
    meta.className = "workspace-tree-meta";
    if (entry.kind === "file" && Number.isFinite(entry.size)) {
      meta.textContent = formatBytes(entry.size);
    } else if (entry.detail) {
      meta.textContent = entry.detail;
    } else {
      meta.textContent = entry.kind;
    }
    row.title = entry.detail || entry.path || entry.name;
    row.append(disclosure, name, meta);

    if (entry.kind === "directory" && entry.path) {
      row.addEventListener("click", () => {
        void toggleDirectory(entry.path);
      });
    } else if (entry.kind === "file" && entry.path) {
      row.addEventListener("click", () => {
        void openFile(entry.path);
      });
    }
    return row;
  }

  function appendDirectory(path, depth, fragment) {
    const directory = directories.get(path);
    if (!directory) return;
    directory.entries.forEach((entry) => {
      fragment.append(makeTreeRow(entry, depth));
      if (entry.kind === "directory" && entry.path && expanded.has(entry.path)) {
        appendDirectory(entry.path, depth + 1, fragment);
      }
    });
    if (directory.truncated) {
      const note = document.createElement("div");
      note.className = "workspace-tree-limit";
      note.style.setProperty("--workspace-indent", `${depth * 13}px`);
      note.textContent = `First ${directory.limit.toLocaleString()} entries shown · directory truncated`;
      fragment.append(note);
    }
  }

  function renderTree() {
    elements.workspaceTree.replaceChildren();
    if (!root) {
      elements.workspaceTree.hidden = true;
      elements.workspaceEmpty.hidden = false;
      elements.workspaceEmpty.textContent = "No active workspace. Bind or select a project first.";
      updateAvailability();
      return;
    }
    const rootDirectory = directories.get(".");
    if (!rootDirectory) {
      elements.workspaceTree.hidden = true;
      elements.workspaceEmpty.hidden = false;
      elements.workspaceEmpty.textContent = pending > 0
        ? "Loading the active workspace…"
        : "Open Workspace or choose Refresh to load the file tree.";
      updateAvailability();
      return;
    }
    const fragment = document.createDocumentFragment();
    appendDirectory(".", 1, fragment);
    elements.workspaceTree.append(fragment);
    elements.workspaceTree.hidden = false;
    elements.workspaceEmpty.hidden = true;
    updateAvailability();
  }

  async function requestDirectory(path, token, reportFailure = true) {
    pending += 1;
    updateAvailability();
    try {
      const directory = await invoke("list_workspace_directory", { path });
      if (token !== generation || !root) return false;
      directories.set(path, directory);
      renderTree();
      return true;
    } catch (error) {
      if (token !== generation) return false;
      const message = errorMessage(error);
      setStatus(message, "error");
      if (reportFailure) onError(message);
      return false;
    } finally {
      pending = Math.max(0, pending - 1);
      renderTree();
    }
  }

  async function ensureRoot() {
    if (!root || directories.has(".")) return;
    if (!invoke) {
      const message = "Workspace IPC is unavailable in this window.";
      setStatus(message, "error");
      onError(message);
      return;
    }
    const token = generation;
    setStatus("Loading active workspace…", "loading");
    const loaded = await requestDirectory(".", token);
    if (loaded && token === generation) {
      const directory = directories.get(".");
      setStatus(
        directory?.truncated
          ? `Loaded ${directory.limit.toLocaleString()} entries · truncated at the safety limit.`
          : "Live refresh active · read-only browser.",
        directory?.truncated ? "attention" : "live",
      );
    }
  }

  async function toggleDirectory(path) {
    if (hostBusy || !root) return;
    if (expanded.has(path)) {
      expanded.delete(path);
      renderTree();
      return;
    }
    expanded.add(path);
    renderTree();
    if (directories.has(path)) return;
    setStatus(`Opening ${path}…`, "loading");
    const token = generation;
    const loaded = await requestDirectory(path, token);
    if (loaded && token === generation) setStatus("Live refresh active · read-only browser.", "live");
  }

  async function openFile(path, token = generation, reportFailure = true) {
    if (!root) return false;
    selectedPath = path;
    renderTree();
    elements.workspaceViewerEmpty.hidden = true;
    elements.workspaceViewer.hidden = false;
    elements.workspaceViewer.dataset.status = "loading";
    elements.workspaceFilePath.textContent = path;
    elements.workspaceFileMeta.textContent = "Opening read-only…";
    elements.workspaceFileDetail.textContent = "The host is validating workspace authority and file identity.";
    elements.workspaceFileContent.textContent = "";
    elements.workspaceFileContent.hidden = true;
    pending += 1;
    updateAvailability();
    try {
      const file = await invoke("open_workspace_file", { path });
      if (token !== generation || !root) return false;
      renderFile(file);
      return true;
    } catch (error) {
      if (token !== generation) return false;
      const message = errorMessage(error);
      renderViewerError(path, message);
      setStatus(message, "error");
      if (reportFailure) onError(message);
      return false;
    } finally {
      pending = Math.max(0, pending - 1);
      updateAvailability();
    }
  }

  function parentPath(path) {
    const separator = path.lastIndexOf("/");
    return separator === -1 ? "." : path.slice(0, separator);
  }

  function directoryStillPresent(path) {
    if (path === ".") return true;
    return directories.get(parentPath(path))?.entries.some(
      (entry) => entry.kind === "directory" && entry.path === path,
    ) === true;
  }

  async function refresh(announced = false) {
    if (!root || !invoke) return;
    const token = generation + 1;
    generation = token;
    const paths = [...expanded].sort((left, right) => {
      const depth = (value) => value === "." ? 0 : value.split("/").length;
      return depth(left) - depth(right) || left.localeCompare(right);
    });
    directories.clear();
    setStatus(announced ? "Refreshing workspace…" : "Workspace changed · refreshing…", "loading");
    renderTree();
    let ok = await requestDirectory(".", token, announced);
    for (const path of paths) {
      if (path === "." || token !== generation || !directoryStillPresent(path)) continue;
      ok = await requestDirectory(path, token, announced) && ok;
    }
    if (selectedPath && token === generation) {
      ok = await openFile(selectedPath, token, announced) && ok;
    }
    if (ok && token === generation) {
      setStatus(announced ? "Workspace refreshed." : "Live refresh active · read-only browser.", "live");
    }
  }

  function reset(nextRoot) {
    window.clearTimeout(refreshTimer);
    refreshTimer = null;
    generation += 1;
    root = nextRoot || null;
    selectedPath = null;
    directories.clear();
    expanded.clear();
    expanded.add(".");
    elements.workspaceRoot.textContent = displayName(root);
    elements.workspaceRoot.title = root || "No active project";
    renderViewerEmpty();
    if (root) {
      setStatus("Open Workspace to load the read-only tree.", "idle");
    } else {
      setStatus("Bind a project to browse files.", "idle");
    }
    renderTree();
  }

  function handleEvent(event) {
    if (!event || typeof event !== "object") return;
    if (event.kind === "error") {
      const detail = typeof event.detail === "string" ? event.detail : "Unknown watcher failure.";
      setStatus(`Live refresh unavailable: ${detail} Manual refresh remains available.`, "error");
      return;
    }
    if (event.kind !== "changed" || !root) return;
    window.clearTimeout(refreshTimer);
    setStatus("Workspace changed · refresh pending…", "loading");
    refreshTimer = window.setTimeout(() => {
      refreshTimer = null;
      void refresh(false);
    }, LIVE_REFRESH_DELAY_MS);
  }

  function setHostBusy(busy) {
    hostBusy = busy;
    updateAvailability();
  }

  elements.workspaceRefresh.addEventListener("click", () => {
    void refresh(true);
  });
  reset(null);

  return { ensureRoot, handleEvent, refresh, reset, setHostBusy };
}
