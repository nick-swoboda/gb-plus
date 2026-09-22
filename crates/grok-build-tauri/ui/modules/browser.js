"use strict";

const ACTIVE_RUNTIME_PHASES = new Set(["downloading", "extracting", "verifying"]);

export function createBrowserControl({ invoke, elements, getActiveProjectId, onError, onNotice, onCapabilityState }) {
  let view = null;
  let localBusy = false;
  let stopBusy = false;
  let hostBusy = true;
  let lastProjectId = null;
  let interactionQueue = Promise.resolve();
  let agentRefreshTimer = null;

  elements.browserInstall.addEventListener("click", () => void installRuntime());
  elements.browserArmInApp.addEventListener("click", () => void arm("in_app"));
  elements.browserOpenHeaded.addEventListener("click", () => void arm("headed"));
  elements.browserStop.addEventListener("click", () => void stop());
  elements.browserUrlForm.addEventListener("submit", (event) => {
    event.preventDefault();
    void action("browser_navigate", { url: elements.browserUrl.value }, "Navigation completed");
  });
  elements.browserRefresh.addEventListener("click", () => {
    void action("browser_inspect", {}, "Preview refreshed");
  });
  elements.browserViewport.addEventListener("pointerdown", (event) => {
    if (event.button !== 0 || view?.mode !== "in_app") return;
    const point = viewportPoint(event);
    if (!point) return;
    event.preventDefault();
    elements.browserViewport.focus({ preventScroll: true });
    queueInteraction("browser_pointer", {
      x: point.x,
      y: point.y,
    });
  });
  elements.browserViewport.addEventListener("wheel", (event) => {
    if (!view?.userControlActive || view?.mode !== "in_app") return;
    const point = viewportPoint(event);
    if (!point) return;
    event.preventDefault();
    queueInteraction("browser_focused_scroll", {
      x: point.x,
      y: point.y,
      deltaY: Math.round(Math.max(-2000, Math.min(2000, event.deltaY))),
    });
  }, { passive: false });
  elements.browserViewport.addEventListener("keydown", (event) => {
    if (!view?.userControlActive || event.metaKey || event.ctrlKey || event.altKey) return;
    if (event.key === "Escape") {
      event.preventDefault();
      void releaseUserControl();
      elements.browserViewport.blur();
      return;
    }
    if (event.key.length === 1) {
      event.preventDefault();
      queueInteraction("browser_insert_text", {
        text: event.key,
      });
      return;
    }
    const allowed = new Set(["Enter", "Tab", "Backspace", "Delete", "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "PageUp", "PageDown", "Home", "End"]);
    if (allowed.has(event.key)) {
      event.preventDefault();
      queueInteraction("browser_focused_key", {
        key: event.key,
      });
    }
  });
  document.addEventListener("pointerdown", (event) => {
    if (!view?.userControlActive || elements.browserViewport.contains(event.target)) return;
    void releaseUserControl();
  });

  async function refresh(silent = true) {
    if (!invoke) return;
    try {
      view = await invoke("browser_status", {});
      render();
    } catch (error) {
      if (!silent) onError(message(error));
    }
  }

  async function installRuntime() {
    if (!invoke || localBusy || view?.stopVisible || ACTIVE_RUNTIME_PHASES.has(view?.runtime?.phase)) return;
    localBusy = true;
    view = {
      ...(view || {}),
      runtime: {
        ...(view?.runtime || {}),
        phase: "downloading",
        downloadedBytes: 0,
        totalBytes: view?.runtime?.downloadBytes || 187918859,
        detail: "Downloading…",
      },
    };
    render();
    try {
      view = await invoke("browser_install_runtime", {});
      onNotice("Chrome for Testing installed and fully verified");
    } catch (error) {
      onError(message(error));
      await refresh();
    } finally {
      localBusy = false;
      render();
    }
  }

  async function arm(mode) {
    if (!invoke || localBusy || hostBusy || !getActiveProjectId()) return;
    if (!view?.runtime?.installed) {
      onError("Download Chrome before starting Browser.");
      return;
    }
    localBusy = true;
    view = {
      ...(view || {}),
      phase: "starting",
      detail: "Starting…",
      lastRefusal: null,
    };
    render();
    try {
      view = await invoke("browser_arm", { mode });
      onNotice(mode === "headed" ? "Browser armed in headed mode" : "Browser armed in the in-app viewport");
    } catch (error) {
      onError(message(error));
      await refresh();
    } finally {
      localBusy = false;
      render();
    }
  }

  async function stop() {
    if (!invoke || stopBusy) return;
    stopBusy = true;
    render();
    try {
      view = await invoke("browser_stop", {});
      onNotice("Browser stopped · grant Off");
    } catch (error) {
      onError(message(error));
      await refresh();
    } finally {
      stopBusy = false;
      render();
    }
  }

  async function action(command, payload, notice) {
    if (!invoke || localBusy || view?.phase !== "armed") {
      onError("Arm Browser before using its controlled actions.");
      return;
    }
    localBusy = true;
    render();
    try {
      const response = await invoke(command, payload);
      view = response.browser;
      onNotice(notice);
    } catch (error) {
      onError(message(error));
      await refresh();
    } finally {
      localBusy = false;
      render();
    }
  }

  function queueInteraction(command, payload) {
    if (!invoke || view?.phase !== "armed" || !view?.interactionToken) return;
    interactionQueue = interactionQueue.then(async () => {
      try {
        const currentToken = view?.interactionToken;
        if (!currentToken || view?.phase !== "armed") return;
        const response = await invoke(command, {
          ...payload,
          interactionToken: currentToken,
        });
        view = response.browser;
        render();
      } catch (error) {
        onError(message(error));
        await refresh();
      }
    });
  }

  async function releaseUserControl() {
    if (!invoke || !view?.userControlActive) return;
    try {
      view = await invoke("browser_release_user_control", {});
      render();
    } catch (error) {
      onError(message(error));
      await refresh();
    }
  }

  function viewportPoint(event) {
    const rect = elements.browserScreenshot.getBoundingClientRect();
    if (elements.browserScreenshot.hidden || rect.width <= 0 || rect.height <= 0) return null;
    const relativeX = event.clientX - rect.left;
    const relativeY = event.clientY - rect.top;
    if (relativeX < 0 || relativeY < 0 || relativeX >= rect.width || relativeY >= rect.height) {
      onError("Click inside the current page image.");
      return null;
    }
    return {
      x: relativeX * Number(view?.viewportWidth || 1280) / rect.width,
      y: relativeY * Number(view?.viewportHeight || 800) / rect.height,
    };
  }

  function handleProgress(progress) {
    if (!progress) return;
    view = {
      ...(view || {}),
      runtime: {
        ...(view?.runtime || {}),
        phase: "downloading",
        downloadedBytes: progress.downloadedBytes,
        totalBytes: progress.totalBytes,
        detail: `Downloading ${formatBytes(progress.downloadedBytes)} of ${formatBytes(progress.totalBytes)}…`,
      },
    };
    render();
  }

  function reset(snapshot) {
    hostBusy = !snapshot?.activeProjectId;
    const projectId = snapshot?.activeProjectId || null;
    if (projectId !== lastProjectId) {
      lastProjectId = projectId;
      void refresh();
    } else if (!view) {
      void refresh();
    }
    render();
  }

  function setHostBusy(busy) {
    hostBusy = Boolean(busy);
    render();
  }

  function onViewShown() {
    void refresh(false);
  }

  function render() {
    const runtime = view?.runtime || {};
    const phase = view?.phase || "off";
    const armed = phase === "armed";
    const stopping = phase === "stopping";
    const runtimeActive = ACTIVE_RUNTIME_PHASES.has(runtime.phase);
    const runtimeReady = Boolean(runtime.installed);
    const error = phase === "failed" || runtime.phase === "failed";
    const chipKind = armed ? "on" : (error ? "error" : "off");
    const chipText = armed
      ? `Browser On · ${view.mode === "headed" ? "Headed" : "In-app"}`
      : (phase === "failed" ? "Browser error" : "Browser Off");

    elements.browserChip.dataset.kind = chipKind;
    elements.browserChip.textContent = chipText;
    elements.browserToolbarChip.dataset.kind = chipKind;
    elements.browserToolbarChip.textContent = armed ? "Browser On" : (error ? "Browser error" : "Browser Off");
    elements.browserToolbarChip.setAttribute("aria-label", `Show Browser: ${chipText}`);
    elements.browserRuntimeDetail.textContent = runtimeDisplayDetail(runtime);
    elements.browserTerms.href = runtime.termsUrl || "https://policies.google.com/terms";
    elements.browserInstall.disabled = localBusy || runtimeActive || armed || stopping;
    elements.browserInstall.hidden = runtimeReady || runtimeActive;
    elements.browserInstall.textContent = "Download";
    const total = Number(runtime.totalBytes || 0);
    const current = Number(runtime.downloadedBytes || 0);
    elements.browserProgress.hidden = runtime.phase !== "downloading" || total <= 0;
    elements.browserProgress.max = total || 1;
    elements.browserProgress.value = Math.min(total, Math.max(0, current));

    const canArm = phase === "off" || phase === "failed";
    elements.browserArmInApp.disabled = localBusy || hostBusy || !runtimeReady || !canArm;
    elements.browserOpenHeaded.disabled = localBusy || hostBusy || !runtimeReady || !canArm;
    elements.browserStop.hidden = !view?.stopVisible && phase !== "failed";
    elements.browserStop.textContent = view?.stopVisible ? "Stop" : "Reset";
    elements.browserStop.disabled = stopBusy;
    onCapabilityState("browser", Boolean(view?.stopVisible), stopBusy);

    const actionDisabled = localBusy || !armed;
    for (const control of [
      elements.browserUrl,
      elements.browserNavigate,
      elements.browserRefresh,
    ]) control.disabled = actionDisabled;
    elements.browserRefresh.hidden = !armed;

    const screenshot = typeof view?.screenshotDataUrl === "string"
      && view.screenshotDataUrl.startsWith("data:image/png;base64,")
      ? view.screenshotDataUrl
      : null;
    elements.browserScreenshot.hidden = !screenshot;
    if (screenshot) elements.browserScreenshot.src = screenshot;
    else elements.browserScreenshot.removeAttribute("src");
    elements.browserEmpty.hidden = Boolean(screenshot);
    elements.browserViewport.classList.toggle("is-user-controlled", Boolean(view?.userControlActive));
    elements.browserViewport.setAttribute("aria-pressed", String(Boolean(view?.userControlActive)));
    const status = browserDisplayStatus(view, runtime, error);
    elements.browserStatus.textContent = status;
    elements.browserStatus.hidden = !status;
    elements.browserStatus.dataset.kind = view?.lastRefusal ? "error" : (armed ? "on" : (error ? "error" : "off"));
  }

  function handleAgentEvent(event) {
    if (!event || !["tool_completed", "tool_refused"].includes(event.kind)) return;
    const name = event.payload?.name;
    if (typeof name !== "string" || !name.startsWith("browser_")) return;
    window.clearTimeout(agentRefreshTimer);
    agentRefreshTimer = window.setTimeout(() => void refresh(), 120);
  }

  return { refresh, handleProgress, handleAgentEvent, reset, setHostBusy, onViewShown, stop, releaseUserControl };
}

function runtimeDisplayDetail(runtime) {
  if (runtime?.phase === "failed") return runtime.detail || "Download failed";
  if (runtime?.phase === "downloading") {
    const total = Number(runtime.totalBytes || 0);
    const current = Number(runtime.downloadedBytes || 0);
    return total > 0 ? `Downloading ${formatBytes(current)} of ${formatBytes(total)}…` : "Downloading…";
  }
  if (runtime?.phase === "extracting") return "Installing…";
  if (runtime?.phase === "verifying") return "Verifying…";
  if (runtime?.installed) return "Installed";
  if (!runtime || runtime.phase == null || runtime.phase === "checking") return "Checking…";
  return "Not installed";
}

function browserDisplayStatus(view, runtime, error) {
  if (view?.lastRefusal) return view.lastRefusal;
  if (error) return view?.detail || runtime?.detail || "Browser unavailable";
  if (view?.phase === "starting") return "Starting…";
  return "";
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  return `${(bytes / (1024 ** index)).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function message(error) {
  return error instanceof Error ? error.message : String(error);
}
