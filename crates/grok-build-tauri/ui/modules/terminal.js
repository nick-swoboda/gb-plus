"use strict";

import { Terminal } from "../vendor/xterm/xterm.mjs";
import { FitAddon } from "../vendor/xterm/addon-fit.mjs";

const INERT_LINK_HANDLER = Object.freeze({
  allowNonHttpProtocols: false,
  activate(event) {
    event.preventDefault();
  },
});

const ACTIVE_STATES = new Set(["starting", "live", "stopping"]);
const encoder = new TextEncoder();

export function createInteractiveTerminal({ invoke, elements, onError, onNotice }) {
  const terminal = new Terminal({
    allowProposedApi: false,
    convertEol: false,
    cursorBlink: true,
    cursorStyle: "block",
    disableStdin: true,
    fontFamily: 'ui-monospace, "SFMono-Regular", Menlo, monospace',
    fontSize: 11,
    letterSpacing: 0,
    lineHeight: 1.2,
    linkHandler: INERT_LINK_HANDLER,
    logLevel: "off",
    macOptionIsMeta: true,
    minimumContrastRatio: 4.5,
    screenReaderMode: true,
    scrollback: 10_000,
    theme: {
      background: "#F9D993",
      foreground: "#121312",
      cursor: "#121312",
      cursorAccent: "#FFFFFF",
      selectionBackground: "#121312",
      selectionForeground: "#FFFFFF",
      black: "#121312",
      red: "#560C07",
      green: "#275E17",
      yellow: "#121312",
      blue: "#6786AB",
      magenta: "#560C07",
      cyan: "#121312",
      white: "#121312",
      brightBlack: "#121312",
      brightRed: "#560C07",
      brightGreen: "#275E17",
      brightYellow: "#121312",
      brightBlue: "#6786AB",
      brightMagenta: "#560C07",
      brightCyan: "#121312",
      brightWhite: "#121312",
    },
  });
  const fitAddon = new FitAddon();
  terminal.loadAddon(fitAddon);
  terminal.open(elements.ptySurface);

  let target = null;
  let view = null;
  let generation = 0;
  let lastSequence = 0;
  let pendingEvents = [];
  let attaching = false;
  let localBusy = false;
  let hostBusy = false;
  let writeChain = Promise.resolve();
  let resizeTimer = null;
  let lastResize = "";

  terminal.onData((data) => {
    if (view?.state !== "live" || !invoke) return;
    const bytes = Array.from(encoder.encode(data));
    writeChain = writeChain
      .then(() => invoke("pty_write", { data: bytes }))
      .catch((error) => {
        onError(error instanceof Error ? error.message : String(error));
      });
  });

  terminal.attachCustomKeyEventHandler((event) => {
    if (
      event.type === "keydown"
      && event.metaKey
      && !event.altKey
      && !event.ctrlKey
      && event.key.toLowerCase() === "c"
      && terminal.hasSelection()
    ) {
      event.preventDefault();
      if (!navigator.clipboard?.writeText) {
        onError("Clipboard access is unavailable for terminal copy.");
        return false;
      }
      void navigator.clipboard.writeText(terminal.getSelection()).catch(() => {
        onError("The selected terminal text could not be copied.");
      });
      return false;
    }
    return true;
  });

  const resizeObserver = new ResizeObserver(() => scheduleFit());
  resizeObserver.observe(elements.ptySurface);

  elements.ptyStart.addEventListener("click", () => {
    void start();
  });
  elements.ptyStop.addEventListener("click", () => {
    void stop();
  });
  elements.ptyInterrupt.addEventListener("click", () => {
    void interrupt();
  });

  function reset(snapshot) {
    const next = snapshot?.activeProjectId && snapshot?.workspaceRef?.workspaceId
      ? {
          projectId: snapshot.activeProjectId,
          workspaceId: snapshot.workspaceRef.workspaceId,
          cwd: snapshot.folderPath,
        }
      : null;
    const changed = target?.projectId !== next?.projectId
      || target?.workspaceId !== next?.workspaceId;
    target = next;
    elements.terminalCwd.textContent = next?.cwd || "No active project";
    elements.terminalCwd.title = next?.cwd || "";
    if (!changed) return;

    generation += 1;
    view = null;
    lastSequence = 0;
    pendingEvents = [];
    attaching = false;
    lastResize = "";
    terminal.reset();
    terminal.options.disableStdin = true;
    renderUnavailable(next ? "Reading shell state…" : "Bind a project to start a shell.");
    if (next) void attach(generation);
  }

  async function attach(expectedGeneration) {
    if (!invoke || !target) return;
    attaching = true;
    try {
      const current = await invoke("pty_status", {});
      if (expectedGeneration !== generation || !matchesTarget(current)) return;
      applyView(current, true);
    } catch (error) {
      if (expectedGeneration === generation) {
        renderUnavailable("Shell state unavailable");
        onError(error instanceof Error ? error.message : String(error));
      }
    } finally {
      if (expectedGeneration === generation) {
        attaching = false;
        flushPending();
      }
    }
  }

  async function start() {
    if (!invoke || !target || localBusy || ACTIVE_STATES.has(view?.state)) return;
    localBusy = true;
    renderControls();
    const expectedGeneration = generation;
    const dimensions = fitAddon.proposeDimensions() || { rows: 24, cols: 80 };
    attaching = true;
    try {
      const started = await invoke("pty_start", {
        rows: clamp(dimensions.rows, 1, 500),
        cols: clamp(dimensions.cols, 2, 500),
      });
      if (expectedGeneration !== generation || !matchesTarget(started)) return;
      applyView(started, true);
      terminal.focus();
      onNotice("Interactive user shell is live · not contained");
    } catch (error) {
      if (expectedGeneration === generation) {
        await refreshAfterFailure();
        onError(error instanceof Error ? error.message : String(error));
      }
    } finally {
      if (expectedGeneration === generation) {
        attaching = false;
        localBusy = false;
        flushPending();
        renderControls();
      }
    }
  }

  async function stop() {
    if (!invoke || !target || localBusy || !ACTIVE_STATES.has(view?.state)) return;
    localBusy = true;
    renderControls();
    try {
      const stopped = await invoke("pty_stop", {});
      if (matchesTarget(stopped)) applyView(stopped, false);
    } catch (error) {
      onError(error instanceof Error ? error.message : String(error));
    } finally {
      localBusy = false;
      renderControls();
    }
  }

  async function interrupt() {
    if (!invoke || view?.state !== "live") return;
    try {
      await invoke("pty_interrupt", {});
      terminal.focus();
    } catch (error) {
      onError(error instanceof Error ? error.message : String(error));
    }
  }

  async function refreshAfterFailure() {
    try {
      const current = await invoke("pty_status", {});
      if (matchesTarget(current)) applyView(current, true);
    } catch {
      renderUnavailable("Shell failed to start");
    }
  }

  function handleEvent(event) {
    if (!event || !target) return;
    if (
      event.projectId !== target.projectId
      || event.workspaceId !== target.workspaceId
    ) return;
    if (attaching || !view) {
      pendingEvents.push(event);
      if (pendingEvents.length > 256) pendingEvents.shift();
      return;
    }
    applyEvent(event);
  }

  function applyEvent(event) {
    if (event.kind === "output") {
      if (!Number.isSafeInteger(event.sequence) || event.sequence <= lastSequence) return;
      if (Array.isArray(event.data)) terminal.write(new Uint8Array(event.data));
      lastSequence = event.sequence;
      elements.ptyPlaceholder.hidden = true;
      return;
    }
    if (event.kind === "state" && typeof event.state === "string") {
      view = {
        ...(view || {}),
        state: event.state,
        status: event.status || stateLabel(event.state),
      };
      renderView();
    }
  }

  function applyView(nextView, resetOutput) {
    view = nextView;
    if (resetOutput) {
      terminal.reset();
      const scrollback = Array.isArray(nextView.scrollback)
        ? new Uint8Array(nextView.scrollback)
        : new Uint8Array();
      if (scrollback.length) terminal.write(scrollback);
      lastSequence = Number.isSafeInteger(nextView.outputSequence)
        ? nextView.outputSequence
        : 0;
    }
    renderView();
  }

  function renderView() {
    const state = view?.state || "not_started";
    const conciseStatus = stateLabel(state);
    elements.ptyStatus.dataset.state = state;
    elements.ptyStatus.textContent = conciseStatus;
    elements.ptyStatus.title = view?.status || conciseStatus;
    elements.ptyShell.textContent = view?.shell || "Selected when started";
    elements.ptyShell.title = view?.shell || "";
    terminal.options.disableStdin = state !== "live";
    const hasOutput = Number(view?.scrollback?.length || 0) > 0 || lastSequence > 0;
    elements.ptyPlaceholder.hidden = ACTIVE_STATES.has(state) || hasOutput || state === "exited";
    if (!elements.ptyPlaceholder.hidden) {
      const title = elements.ptyPlaceholder.querySelector("strong");
      const detail = elements.ptyPlaceholder.querySelector("span");
      if (title) title.textContent = state === "failed" ? "Shell unavailable" : "Shell not started";
      if (detail) detail.textContent = view?.status || "Start a direct interactive shell in the active project or worktree.";
    }
    renderControls();
    scheduleFit();
  }

  function renderUnavailable(message) {
    elements.ptyStatus.dataset.state = "not_started";
    elements.ptyStatus.textContent = "Not started";
    elements.ptyStatus.title = message;
    elements.ptyShell.textContent = "Selected when started";
    elements.ptyPlaceholder.hidden = false;
    const detail = elements.ptyPlaceholder.querySelector("span");
    if (detail) detail.textContent = message;
    renderControls();
  }

  function renderControls() {
    const bound = Boolean(target);
    const state = view?.state || "not_started";
    elements.ptyStart.disabled = !bound || hostBusy || localBusy || ACTIVE_STATES.has(state);
    elements.ptyStart.textContent = ["exited", "failed"].includes(state)
      ? "Restart shell"
      : "Start shell";
    elements.ptyStop.disabled = hostBusy || localBusy || !ACTIVE_STATES.has(state);
    elements.ptyInterrupt.disabled = hostBusy || localBusy || state !== "live";
  }

  function flushPending() {
    const pending = pendingEvents;
    pendingEvents = [];
    pending
      .sort((left, right) => (left.sequence || 0) - (right.sequence || 0))
      .forEach(applyEvent);
  }

  function matchesTarget(candidate) {
    return Boolean(
      target
      && candidate?.projectId === target.projectId
      && candidate?.workspaceId === target.workspaceId,
    );
  }

  function scheduleFit() {
    window.clearTimeout(resizeTimer);
    resizeTimer = window.setTimeout(() => {
      if (!elements.ptySurface.offsetParent) return;
      try {
        fitAddon.fit();
      } catch {
        return;
      }
      if (view?.state !== "live" || !invoke) return;
      const sizeKey = `${terminal.rows}x${terminal.cols}`;
      if (sizeKey === lastResize) return;
      lastResize = sizeKey;
      void invoke("pty_resize", { rows: terminal.rows, cols: terminal.cols }).catch((error) => {
        onError(error instanceof Error ? error.message : String(error));
      });
    }, 80);
  }

  function onViewShown() {
    scheduleFit();
    if (view?.state === "live") terminal.focus();
  }

  function setHostBusy(busy) {
    hostBusy = Boolean(busy);
    renderControls();
  }

  return { reset, handleEvent, onViewShown, setHostBusy };
}

function stateLabel(state) {
  switch (state) {
    case "starting": return "Starting…";
    case "live": return "Live";
    case "stopping": return "Stopping…";
    case "exited": return "Stopped";
    case "failed": return "Unavailable";
    default: return "Not started";
  }
}

function clamp(value, minimum, maximum) {
  const number = Number.isFinite(value) ? Math.trunc(value) : minimum;
  return Math.min(maximum, Math.max(minimum, number));
}
